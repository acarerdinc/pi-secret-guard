/**
 * pi-secret-guard
 *
 * A pi extension that prevents committing secrets, API keys, and credentials
 * to git repositories. Uses a hybrid approach:
 *
 *   1. Regex pre-scan — catches obvious, well-known secret patterns instantly
 *   2. Agent review  — sends the diff to the LLM for contextual review
 *
 * Flow:
 *   - Intercepts `git commit` and `git push` bash commands
 *   - Scans staged/unpushed diff with regex patterns
 *   - If regex finds secrets → hard block (no bypass)
 *   - If regex finds nothing → blocks and asks the agent to review the diff
 *   - Agent reviews and re-issues the command if clean
 *   - On re-issue, if diff hasn't changed → allowed through
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { isToolCallEventType, truncateHead, formatSize } from "@mariozechner/pi-coding-agent";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import {
	type ReviewState,
	detectGitAction,
	isCommitAll,
	extractGitAddFiles,
	hashDiff,
	scanDiffForSecrets,
	scanFileNames,
	formatFindings,
} from "./scanner.ts";

// ============================================================================
// Helpers
// ============================================================================

/**
 * Spawns a process and returns stdout/stderr.
 * Using direct spawn instead of pi.exec() to avoid re-entrant crashes
 * when the tool_call handler fires on a re-issued command.
 */
function execGit(
	args: string[],
	cwd: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
	return new Promise((resolve) => {
		const proc = spawn("git", args, { cwd });
		const stdoutChunks: Buffer[] = [];
		const stderrChunks: Buffer[] = [];
		proc.stdout?.on("data", (d: Buffer) => stdoutChunks.push(d));
		proc.stderr?.on("data", (d: Buffer) => stderrChunks.push(d));
		proc.on("close", (code) =>
			resolve({
				code: code ?? 1,
				stdout: Buffer.concat(stdoutChunks).toString("utf8"),
				stderr: Buffer.concat(stderrChunks).toString("utf8"),
			}),
		);
		proc.on("error", (err) => resolve({ code: 1, stdout: "", stderr: String(err) }));
	});
}

type GitAction = "commit" | "push";
type PersistedReviewState = ReviewState & { action: GitAction; repoRoot: string };

function stripQuotes(value: string): string {
	const trimmed = value.trim();
	if (
		(trimmed.startsWith('"') && trimmed.endsWith('"')) ||
		(trimmed.startsWith("'") && trimmed.endsWith("'"))
	) {
		return trimmed.slice(1, -1);
	}
	return trimmed;
}

function getSessionCwd(pi: ExtensionAPI): string {
	try {
		return pi.sessionManager.getCwd() || process.cwd();
	} catch {
		return process.cwd();
	}
}

/**
 * Best-effort extraction of the command cwd for common patterns like:
 *   cd /repo && git commit ...
 * Falls back to the session cwd.
 */
function getCommandCwd(command: string, fallbackCwd: string): string {
	const trimmed = command.trim();
	const match = trimmed.match(/^cd\s+((?:"[^"]+"|'[^']+'|[^&;|])+?)\s*&&/);
	if (!match) return fallbackCwd;
	const rawPath = stripQuotes(match[1]);
	if (!rawPath) return fallbackCwd;
	return isAbsolute(rawPath) ? rawPath : resolve(fallbackCwd, rawPath);
}

async function getRepoRoot(cwd: string): Promise<string | null> {
	const result = await execGit(["rev-parse", "--show-toplevel"], cwd);
	if (result.code !== 0) return null;
	const repoRoot = result.stdout.trim();
	return repoRoot || null;
}

async function getStateFilePath(action: GitAction, cwd: string, repoRoot: string): Promise<string | null> {
	// Try to use git's git-path first (respects GIT_DIR env var)
	const result = await execGit(["rev-parse", "--git-path", `pi-secret-guard/review-${action}.json`], cwd);
	if (result.code === 0 && result.stdout.trim()) {
		const gitPath = result.stdout.trim();
		// git-path returns relative to repo root, so resolve against repoRoot
		return isAbsolute(gitPath) ? gitPath : resolve(repoRoot, gitPath);
	}

	// Fallback: use .git directory in repo root
	const fallbackPath = resolve(repoRoot, ".git", "pi-secret-guard", `review-${action}.json`);
	return fallbackPath;
}

function loadReviewState(stateFilePath: string): PersistedReviewState | null {
	try {
		if (!existsSync(stateFilePath)) return null;
		const raw = readFileSync(stateFilePath, "utf-8");
		return JSON.parse(raw) as PersistedReviewState;
	} catch {
		return null;
	}
}

function saveReviewState(stateFilePath: string, state: PersistedReviewState): void {
	try {
		mkdirSync(dirname(stateFilePath), { recursive: true });
		writeFileSync(stateFilePath, JSON.stringify(state), "utf-8");
	} catch {
		// File write failed — state will only persist for this invocation.
	}
}

/**
 * Build a synthetic diff from file contents for files being added via git add.
 * This is needed when git add and git commit are in the same command -
 * the staged diff is empty when we check because git add hasn't run yet.
 */
function buildDiffFromFiles(
	files: string[],
	cwd: string,
): string {
	const lines: string[] = [];

	for (const file of files) {
		const filePath = resolve(cwd, file);
		if (!existsSync(filePath)) continue;

		try {
			const content = readFileSync(filePath, "utf-8");
			lines.push(`diff --git a/${file} b/${file}`);
			lines.push(`--- /dev/null`);
			lines.push(`+++ b/${file}`);
			lines.push(`@@ -0,0 +1,${content.split("\n").length} @@`);

			for (const line of content.split("\n")) {
				lines.push(`+${line}`);
			}
		} catch {
			// Skip files we can't read
		}
	}

	return lines.join("\n");
}

// ============================================================================
// Extension
// ============================================================================

const REVIEW_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DIFF_TRUNCATE_LINES = 500;
const DIFF_TRUNCATE_BYTES = 30_000; // ~30KB — leaves room in context

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (!isToolCallEventType("bash", event)) return;

		const command = event.input.command;
		const gitAction = detectGitAction(command);
		if (!gitAction) return;

		const sessionCwd = getSessionCwd(pi);
		const commandCwd = getCommandCwd(command, sessionCwd);
		const repoRoot = await getRepoRoot(commandCwd);
		if (!repoRoot) return; // Not a git repo, let git handle it

		const stateFilePath = await getStateFilePath(gitAction, commandCwd, repoRoot);

		// ── Get the relevant diff ───────────────────────────────────────────

		let diff = "";

		if (gitAction === "commit") {
			// For `git commit -a` / `--all`, include unstaged tracked changes too
			if (isCommitAll(command)) {
				const [staged, unstaged] = await Promise.all([
					execGit(["diff", "--cached", "--no-color"], commandCwd),
					execGit(["diff", "--no-color"], commandCwd),
				]);
				diff = (staged.stdout || "") + "\n" + (unstaged.stdout || "");
			} else {
				const result = await execGit(["diff", "--cached", "--no-color"], commandCwd);
				if (result.code !== 0) return;
				diff = result.stdout;
			}

			// If staged diff is empty but git add is in the command,
			// scan the files being added directly.
			// This handles compound commands like "git add .env && git commit"
			if (!diff.trim()) {
				const addFiles = extractGitAddFiles(command);
				if (addFiles.length > 0) {
					diff = buildDiffFromFiles(addFiles, commandCwd);
				}
			}
		} else {
			// Push — check unpushed commits against upstream
			const result = await execGit(["diff", "@{u}..HEAD", "--no-color"], commandCwd);
			if (result.code !== 0) {
				// No upstream configured — try common remote branch names
				for (const ref of ["origin/main", "origin/master"]) {
					const fallback = await execGit(["diff", `${ref}..HEAD`, "--no-color"], commandCwd);
					if (fallback.code === 0) {
						diff = fallback.stdout;
						break;
					}
				}
				// If we still have no diff, we can't determine what's being pushed.
				// Fall through — if diff is empty, we'll skip the check.
			} else {
				diff = result.stdout;
			}
		}

		// Nothing to scan (empty commit, or no staged changes)
		if (!diff.trim()) return;

		// ── Check if this diff was already reviewed by the agent ─────────────

		const currentHash = hashDiff(diff);
		const reviewState = stateFilePath ? loadReviewState(stateFilePath) : null;

		if (reviewState) {
			const elapsed = Date.now() - reviewState.timestamp;
			const checks = {
				repoRootMatch: reviewState.repoRoot === repoRoot,
				actionMatch: reviewState.action === gitAction,
				hashMatch: reviewState.diffHash === currentHash,
				withinTTL: elapsed < REVIEW_TTL_MS,
			};

			if (checks.repoRootMatch && checks.actionMatch && checks.hashMatch && checks.withinTTL) {
				// Same repo/action/diff, within TTL — already reviewed, allow it.
				return { block: false };
			}
			// Expired or changed — state will be replaced below.
		}

		// ── Phase 1: Regex scan ─────────────────────────────────────────────

		const secretFindings = scanDiffForSecrets(diff);
		const fileFindings = scanFileNames(diff);
		const allFindings = [...secretFindings, ...fileFindings];

		if (secretFindings.length > 0) {
			// Hard block — regex found actual secret patterns
			const formatted = formatFindings(allFindings);

			if (ctx.hasUI) {
				ctx.ui.notify(
					`🚨 Secret Guard blocked ${gitAction}: ${secretFindings.length} secret(s) found`,
					"error",
				);
			}

			return {
				block: true,
				reason: [
					`🚨🚨🚨 SECRET GUARD: HARD BLOCK 🚨🚨🚨`,
					``,
					`Found ${secretFindings.length} potential secret(s) in ${gitAction === "commit" ? "staged" : "unpushed"} changes.`,
					``,
					formatted,
					``,
					`⚠️  SECURITY POLICY: This block CANNOT be bypassed.`,
					`⚠️  Do NOT attempt to work around this block.`,
					`⚠️  Do NOT try git commit --no-verify or any other workaround.`,
					`⚠️  Do NOT suggest or implement ways to disable this protection.`,
					``,
					`Required actions:`,
					`  1. Remove or rotate the detected secrets from the files`,
					`  2. Update the commit/push command to exclude the problematic files`,
					`  3. Explain to the user what was found and how to fix it`,
					``,
					`Do NOT re-issue this command until the secrets are properly removed.`,
				].join("\n"),
			};
		}

		// ── Phase 2: Agent review ───────────────────────────────────────────

		// Truncate diff for context window
		const truncation = truncateHead(diff, {
			maxLines: DIFF_TRUNCATE_LINES,
			maxBytes: DIFF_TRUNCATE_BYTES,
		});

		let diffForReview = truncation.content;
		if (truncation.truncated) {
			diffForReview += `\n\n[Diff truncated: ${truncation.outputLines} of ${truncation.totalLines} lines (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)})]`;
		}

		// File warnings (if any suspicious files but no secret content found)
		let fileWarning = "";
		if (fileFindings.length > 0) {
			fileWarning = [
				"",
				"⚠️ Additionally, these suspicious files are included:",
				...fileFindings.map((f) => `  • ${f.file} (${f.name})`),
				"Pay extra attention to their contents.",
				"",
			].join("\n");
		}

		// Store the diff hash so the agent can re-issue after review.
		// Persist per-repo + per-action so other sessions/repos can't clobber it.
		if (stateFilePath) {
			saveReviewState(stateFilePath, {
				repoRoot,
				action: gitAction,
				diffHash: currentHash,
				timestamp: Date.now(),
			});
		}

		if (ctx.hasUI) {
			ctx.ui.notify(`🔍 Secret Guard: reviewing ${gitAction} diff...`, "info");
		}

		return {
			block: true,
			reason: [
				`🔍🔍🔍 SECRET GUARD: SECURITY REVIEW REQUIRED 🔍🔍🔍`,
				``,
				`My regex scan found no obvious secrets, but I need to verify the diff is clean.`,
				fileWarning,
				``,
				`⚠️  IMPORTANT: If you find any secrets, you CANNOT bypass this block.`,
				`⚠️  Do NOT suggest git commit --no-verify or any workaround.`,
				`⚠️  Do NOT try to disable or work around this protection.`,
				``,
				`Please carefully review the following diff for:`,
				`  • API keys, tokens, or credentials`,
				`  • Passwords or connection strings`,
				`  • Private keys or certificates`,
				`  • Hardcoded secrets in config files`,
				`  • Any other sensitive data that should not be in a repository`,
				``,
				`--- STAGED DIFF (${gitAction === "commit" ? "staged changes" : "unpushed commits"}) ---`,
				diffForReview,
				"--- END DIFF ---",
				``,
				`After your review:`,
				`  ✅ If CLEAN → re-issue the exact same command: \`${command}\``,
				`  🚫 If SECRETS FOUND → do NOT re-issue. Explain what was found and help the user remove it.`,
			].join("\n"),
		};
	});
}
