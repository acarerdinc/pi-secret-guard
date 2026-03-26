/**
 * pi-secret-guard
 *
 * Hybrid git secret guard for pi:
 *   1. Regex pre-scan for known secret formats
 *   2. LLM review for subtle secrets
 *   3. Exact re-issue allowed only after the review block is present in session history
 *
 * Important safety behavior:
 *   - Regex hits are hard-blocked.
 *   - Clean diffs are soft-blocked for review.
 *   - Re-issue is only allowed for the exact same repo/action/diff within TTL,
 *     and only when the previous guard review block is visible in session history.
 *   - Compound commands that mix `git commit` and `git push` are blocked and must
 *     be split, because the commit changes the push diff and cannot be safely
 *     re-issued as one exact command.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { isToolCallEventType, truncateHead, formatSize } from "@mariozechner/pi-coding-agent";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import {
	type ReviewState,
	detectGitAction,
	detectGitActions,
	isCommitAll,
	hashDiff,
	scanDiffForSecrets,
	scanFileNames,
	formatFindings,
} from "./scanner.ts";

function execGit(
	args: string[],
	cwd: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
	return new Promise((resolve) => {
		const proc = spawn("git", args, { cwd });
		let stdout = "";
		let stderr = "";
		proc.stdout?.on("data", (d) => (stdout += d));
		proc.stderr?.on("data", (d) => (stderr += d));
		proc.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
		proc.on("error", (err) => resolve({ code: 1, stdout: "", stderr: String(err) }));
	});
}

type GitAction = "commit" | "push";
type ReviewStatus = "pending";
type PersistedReviewState = ReviewState & {
	action: GitAction;
	repoRoot: string;
	status: ReviewStatus;
	command: string;
};

const REVIEW_TTL_MS = 5 * 60 * 1000;
const DIFF_TRUNCATE_LINES = 500;
const DIFF_TRUNCATE_BYTES = 30_000;
const REVIEW_TAG = "SECRET_GUARD_REVIEW";

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

async function getStateFilePath(action: GitAction, cwd: string): Promise<string | null> {
	const result = await execGit(["rev-parse", "--git-path", `pi-secret-guard/review-${action}.json`], cwd);
	if (result.code !== 0) return null;
	const gitPath = result.stdout.trim();
	if (!gitPath) return null;
	return isAbsolute(gitPath) ? gitPath : resolve(cwd, gitPath);
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
		// best effort
	}
}

function clearReviewState(stateFilePath: string | null): void {
	if (!stateFilePath) return;
	try {
		if (existsSync(stateFilePath)) unlinkSync(stateFilePath);
	} catch {
		// best effort
	}
}

function normalizeCommand(command: string): string {
	return command.trim().replace(/\s+/g, " ");
}

function makeReviewMarker(action: GitAction, diffHash: string, command: string): string {
	return `${REVIEW_TAG}:${action}:${diffHash}:${normalizeCommand(command)}`;
}

function extractTextContent(content: unknown): string {
	if (!Array.isArray(content)) return "";
	return content
		.map((part) => {
			if (!part || typeof part !== "object") return "";
			const maybeText = (part as { text?: unknown }).text;
			return typeof maybeText === "string" ? maybeText : "";
		})
		.join("\n");
}

function hasRecentMatchingReviewBlock(
	pi: ExtensionAPI,
	action: GitAction,
	diffHash: string,
	command: string,
): boolean {
	const marker = makeReviewMarker(action, diffHash, command);
	try {
		const branch = pi.sessionManager.getBranch();
		for (let i = branch.length - 1; i >= 0; i--) {
			const entry = branch[i] as any;
			if (entry?.type !== "message") continue;
			const msg = entry.message;
			if (msg?.role === "user") return false;
			if (msg?.role !== "toolResult") continue;
			if (!msg.isError) continue;
			const text = extractTextContent(msg.content);
			if (text.includes(marker)) return true;
		}
	} catch {
		return false;
	}
	return false;
}

async function getDiffForAction(action: GitAction, commandCwd: string, command: string): Promise<string> {
	if (action === "commit") {
		if (isCommitAll(command)) {
			const [staged, unstaged] = await Promise.all([
				execGit(["diff", "--cached", "--no-color"], commandCwd),
				execGit(["diff", "--no-color"], commandCwd),
			]);
			return (staged.stdout || "") + "\n" + (unstaged.stdout || "");
		}
		const result = await execGit(["diff", "--cached", "--no-color"], commandCwd);
		return result.code === 0 ? result.stdout : "";
	}

	const upstream = await execGit(["diff", "@{u}..HEAD", "--no-color"], commandCwd);
	if (upstream.code === 0) return upstream.stdout;

	for (const ref of ["origin/main", "origin/master"]) {
		const fallback = await execGit(["diff", `${ref}..HEAD`, "--no-color"], commandCwd);
		if (fallback.code === 0) return fallback.stdout;
	}

	return "";
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (!isToolCallEventType("bash", event)) return;

		const command = event.input.command;
		const gitActions = detectGitActions(command);
		const gitAction = detectGitAction(command);
		if (!gitAction) return;

		if (gitActions.length > 1) {
			return {
				block: true,
				reason: [
					"🚫 SECRET GUARD: Split git commit and git push into separate commands.",
					"",
					"This command mixes multiple git actions in one shell invocation.",
					"Secret Guard cannot safely review-and-reissue `git commit && git push` as one exact command,",
					"because the commit changes the push diff.",
					"",
					"Run them separately:",
					"  1. git commit ...",
					"  2. git push ...",
				].join("\n"),
			};
		}

		const sessionCwd = getSessionCwd(pi);
		const commandCwd = getCommandCwd(command, sessionCwd);
		const repoRoot = await getRepoRoot(commandCwd);
		if (!repoRoot) return;

		const stateFilePath = await getStateFilePath(gitAction, commandCwd);
		const diff = await getDiffForAction(gitAction, commandCwd, command);
		if (!diff.trim()) {
			clearReviewState(stateFilePath);
			return;
		}

		const currentHash = hashDiff(diff);
		const reviewState = stateFilePath ? loadReviewState(stateFilePath) : null;

		if (reviewState) {
			const elapsed = Date.now() - reviewState.timestamp;
			const sameReview =
				reviewState.repoRoot === repoRoot &&
				reviewState.action === gitAction &&
				reviewState.diffHash === currentHash &&
				reviewState.command === normalizeCommand(command) &&
				reviewState.status === "pending" &&
				elapsed < REVIEW_TTL_MS;

			if (sameReview && hasRecentMatchingReviewBlock(pi, gitAction, currentHash, command)) {
				clearReviewState(stateFilePath);
				if (ctx.hasUI) {
					ctx.ui.notify(`✅ Secret Guard: allowing reviewed ${gitAction}`, "success");
				}
				return;
			}

			if (!sameReview || elapsed >= REVIEW_TTL_MS) {
				clearReviewState(stateFilePath);
			}
		}

		const secretFindings = scanDiffForSecrets(diff);
		const fileFindings = scanFileNames(diff);
		const allFindings = [...secretFindings, ...fileFindings];

		if (secretFindings.length > 0) {
			clearReviewState(stateFilePath);
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
					`🚨 SECRET GUARD: BLOCKED — Found ${secretFindings.length} potential secret(s) in ${gitAction === "commit" ? "staged" : "unpushed"} changes.`,
					"",
					formatted,
					"",
					"Action required:",
					"  1. Remove or rotate the detected secrets",
					"  2. Add sensitive files to .gitignore",
					"  3. If these are FALSE POSITIVES, explain why to the user and let them decide",
					"",
					"Do NOT re-issue the commit/push command until the secrets are removed.",
				].join("\n"),
			};
		}

		const truncation = truncateHead(diff, {
			maxLines: DIFF_TRUNCATE_LINES,
			maxBytes: DIFF_TRUNCATE_BYTES,
		});

		let diffForReview = truncation.content;
		if (truncation.truncated) {
			diffForReview += `\n\n[Diff truncated: ${truncation.outputLines} of ${truncation.totalLines} lines (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)})]`;
		}

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

		if (stateFilePath) {
			saveReviewState(stateFilePath, {
				repoRoot,
				action: gitAction,
				status: "pending",
				command: normalizeCommand(command),
				diffHash: currentHash,
				timestamp: Date.now(),
			});
		}

		if (ctx.hasUI) {
			ctx.ui.notify(`🔍 Secret Guard: reviewing ${gitAction} diff...`, "info");
		}

		const reviewMarker = makeReviewMarker(gitAction, currentHash, command);
		return {
			block: true,
			reason: [
				`🔍 SECRET GUARD: Review required before ${gitAction}.`,
				"",
				"My regex scan found no obvious secrets, but a human-level review is needed.",
				fileWarning,
				"Please carefully review the following diff for:",
				"  • API keys, tokens, or credentials",
				"  • Passwords or connection strings",
				"  • Private keys or certificates",
				"  • Hardcoded secrets in config files",
				"  • Any other sensitive data that should not be in a repository",
				"",
				`--- ${gitAction === "commit" ? "STAGED" : "UNPUSHED"} DIFF ---`,
				diffForReview,
				"--- END DIFF ---",
				"",
				`Review marker: ${reviewMarker}`,
				"",
				"After your review:",
				`  ✅ If CLEAN → re-issue the exact same command: \`${command}\``,
				"  🚫 If SECRETS FOUND → do NOT re-issue. Explain what you found and help fix it.",
			].join("\n"),
		};
	});
}
