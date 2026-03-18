/**
 * pi-secret-guard
 *
 * A pi extension that prevents committing secrets, API keys, and credentials
 * to git repositories.
 *
 * Flow:
 *   - Intercepts `git commit` and `git push` bash commands
 *   - Scans staged/unpushed diff with regex patterns
 *   - If regex finds secrets → hard block (no bypass)
 *   - If regex finds nothing:
 *     - Interactive mode → asks user to confirm via dialog
 *     - Non-interactive mode → auto-approves (trusts regex scan)
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { isToolCallEventType, truncateHead, formatSize } from "@mariozechner/pi-coding-agent";
import {
	detectGitAction,
	isCommitAll,
	scanDiffForSecrets,
	scanFileNames,
	formatFindings,
} from "./scanner.ts";

// ============================================================================
// Extension
// ============================================================================

const DIFF_TRUNCATE_LINES = 500;
const DIFF_TRUNCATE_BYTES = 30_000; // ~30KB — leaves room in context

export default function (pi: ExtensionAPI) {
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

		// ── Phase 2: Confirmation ───────────────────────────────────────────
		//
		// Regex found no secrets. In interactive mode, ask the user to confirm.
		// In non-interactive mode (Waffle, print, etc.), auto-approve — the
		// user explicitly asked for the commit and the regex scan is the
		// primary defense layer.
		//
		// We intentionally do NOT use a block-and-re-issue pattern here
		// because re-issued commands can be blocked by other extensions
		// (e.g., git-guard) or refused by the agent due to system prompt
		// constraints, creating an unresolvable deadlock.

		// File warnings (if any suspicious files but no secret content found)
		let fileWarning = "";
		if (fileFindings.length > 0) {
			fileWarning = [
				"\n⚠️ Suspicious files included:",
				...fileFindings.map((f) => `  • ${f.file} (${f.name})`),
			].join("\n");
		}

		if (ctx.hasUI) {
			// Truncate diff for the confirm dialog context
			const truncation = truncateHead(diff, {
				maxLines: DIFF_TRUNCATE_LINES,
				maxBytes: DIFF_TRUNCATE_BYTES,
			});

			let diffSummary = truncation.content;
			if (truncation.truncated) {
				diffSummary += `\n\n[Diff truncated: ${truncation.outputLines} of ${truncation.totalLines} lines (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)})]`;
			}

			const ok = await ctx.ui.confirm(
				"🔍 Secret Guard",
				[
					`No secrets found by regex scan. Allow ${gitAction}?`,
					fileWarning,
					"",
					"--- Changed files ---",
					// Extract file list from diff for a concise summary
					...diff.split("\n")
						.filter((l) => l.startsWith("+++ b/"))
						.map((l) => `  ${l.slice(6)}`),
					"---",
				].join("\n"),
			);

			if (!ok) {
				return {
					block: true,
					reason: `🔍 SECRET GUARD: User denied ${gitAction} after review. Do NOT retry without explicit user request.`,
				};
			}

			// User approved — allow through
			return;
		}

		// Non-interactive mode: auto-approve after regex scan passes.
		// The user explicitly asked for the commit and regex found nothing.
		if (fileFindings.length > 0) {
			// Log suspicious file warnings so the agent sees them
			ctx.ui.notify(
				`🔍 Secret Guard: allowing ${gitAction} (regex clean).${fileWarning}`,
				"warn",
			);
		}
		// Allow the commit through
		return;
	});
}
