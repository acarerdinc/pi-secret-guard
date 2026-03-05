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
import {
	type ReviewState,
	detectGitAction,
	isCommitAll,
	hashDiff,
	scanDiffForSecrets,
	scanFileNames,
	formatFindings,
} from "./scanner.ts";

// ============================================================================
// Extension
// ============================================================================

const REVIEW_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DIFF_TRUNCATE_LINES = 500;
const DIFF_TRUNCATE_BYTES = 30_000; // ~30KB — leaves room in context

export default function (pi: ExtensionAPI) {
	// State: tracks the diff hash of the last agent-reviewed diff
	let reviewState: ReviewState | null = null;

	pi.on("tool_call", async (event, ctx) => {
		if (!isToolCallEventType("bash", event)) return;

		const command = event.input.command;
		const gitAction = detectGitAction(command);
		if (!gitAction) return;

		// ── Get the relevant diff ───────────────────────────────────────────

		let diff = "";

		if (gitAction === "commit") {
			// For `git commit -a` / `--all`, include unstaged tracked changes too
			if (isCommitAll(command)) {
				const [staged, unstaged] = await Promise.all([
					pi.exec("git", ["diff", "--cached", "--no-color"]),
					pi.exec("git", ["diff", "--no-color"]),
				]);
				diff = (staged.stdout || "") + "\n" + (unstaged.stdout || "");
			} else {
				const result = await pi.exec("git", ["diff", "--cached", "--no-color"]);
				if (result.code !== 0) return; // Not a git repo, let git handle it
				diff = result.stdout;
			}
		} else {
			// Push — check unpushed commits against upstream
			const result = await pi.exec("git", ["diff", "@{u}..HEAD", "--no-color"]);
			if (result.code !== 0) {
				// No upstream configured — try common remote branch names
				for (const ref of ["origin/main", "origin/master"]) {
					const fallback = await pi.exec("git", ["diff", `${ref}..HEAD`, "--no-color"]);
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

		if (reviewState) {
			const elapsed = Date.now() - reviewState.timestamp;
			if (reviewState.diffHash === currentHash && elapsed < REVIEW_TTL_MS) {
				// Same diff, within TTL — agent already reviewed this, allow it
				reviewState = null;
				return;
			}
			// Expired or diff changed — clear stale state
			reviewState = null;
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

		// Store the diff hash so the agent can re-issue after review
		reviewState = { diffHash: currentHash, timestamp: Date.now() };

		if (ctx.hasUI) {
			ctx.ui.notify(`🔍 Secret Guard: reviewing ${gitAction} diff...`, "info");
		}

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
				`--- STAGED DIFF (${gitAction === "commit" ? "staged changes" : "unpushed commits"}) ---`,
				diffForReview,
				"--- END DIFF ---",
				"",
				"After your review:",
				`  ✅ If CLEAN → re-issue the exact same command: \`${command}\``,
				"  🚫 If SECRETS FOUND → do NOT re-issue. Explain what you found and help fix it.",
			].join("\n"),
		};
	});
}
