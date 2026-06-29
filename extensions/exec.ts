/**
 * Process execution helper for pi-secret-guard.
 *
 * Spawns child processes (typically `git`) and returns stdout/stderr as
 * decoded UTF-8 strings, with a hard byte cap to prevent
 * `ERR_STRING_TOO_LONG` crashes on very large diffs.
 *
 * Background:
 *   - Node's V8 has a `kStringMaxLength` of `0x1fffffe8` (≈ 537 MB on x64).
 *   - `Buffer.concat(chunks).toString("utf8")` throws an uncaught exception
 *     when the total exceeds that limit, killing the host pi process.
 *   - Real-world repro: `git push` of a many-commit fork branch in a large
 *     monorepo can produce a diff > 512 MB.
 *
 * Strategy: cap each stream at `MAX_BUFFER_BYTES` (256 MB by default — well
 * below the string limit, leaves headroom for `Buffer.concat` overhead).
 * On overflow, kill the child and return `{ code: 1, overflow: true }` with a
 * descriptive stderr message. Callers MUST check `.overflow` (or non-zero exit)
 * and block the git op — an unscanned diff must never be allowed through.
 * `index.ts` routes overflow to `overflowBlock()` to enforce this fail-closed
 * security default.
 *
 * The cap can be overridden via the `PI_SECRET_GUARD_MAX_BUFFER_BYTES`
 * environment variable (advanced — most users won't need this).
 */

import { spawn } from "node:child_process";

/**
 * Default cap for stdout/stderr buffers, in bytes (256 MB).
 *
 * Chosen to leave 2× headroom below Node's `kStringMaxLength` (~537 MB) for
 * transient allocations during `Buffer.concat` + UTF-8 decoding.
 */
export const DEFAULT_MAX_BUFFER_BYTES = 256 * 1024 * 1024;

/**
 * Resolve the effective buffer cap, honoring the env override.
 *
 * Invalid values (non-numeric, ≤ 0) fall back to the default.
 */
export function resolveMaxBufferBytes(
	envValue: string | undefined = process.env.PI_SECRET_GUARD_MAX_BUFFER_BYTES,
): number {
	if (!envValue) return DEFAULT_MAX_BUFFER_BYTES;
	const n = Number(envValue);
	if (!Number.isFinite(n) || n <= 0) return DEFAULT_MAX_BUFFER_BYTES;
	return Math.floor(n);
}

export interface ExecResult {
	code: number;
	stdout: string;
	stderr: string;
	/** True when the child was killed because output exceeded the buffer cap. */
	overflow?: boolean;
}

export interface ExecOptions {
	/** Override the stdout/stderr byte cap (defaults to {@link resolveMaxBufferBytes}). */
	maxBufferBytes?: number;
	/**
	 * Spawn factory — overridable for tests. Defaults to `node:child_process`'s
	 * {@link spawn}. The signature is the subset of `spawn` we use.
	 */
	spawnFn?: typeof spawn;
}

/**
 * Spawn a process and collect stdout/stderr with a byte cap.
 *
 * Using direct spawn instead of `pi.exec()` to avoid re-entrant crashes when
 * the `tool_call` handler fires on a re-issued command (see HANDOVER.md).
 *
 * @param command  Executable name (e.g. `"git"`).
 * @param args     Argument list.
 * @param cwd      Working directory.
 * @param options  Optional cap + spawn factory overrides.
 * @returns Resolves with `{ code, stdout, stderr, overflow? }`. Never rejects.
 */
export function execProc(
	command: string,
	args: string[],
	cwd: string,
	options: ExecOptions = {},
): Promise<ExecResult> {
	const cap = options.maxBufferBytes ?? resolveMaxBufferBytes();
	const spawnImpl = options.spawnFn ?? spawn;

	return new Promise((resolve) => {
		const proc = spawnImpl(command, args, { cwd });

		const stdoutChunks: Buffer[] = [];
		const stderrChunks: Buffer[] = [];
		let stdoutBytes = 0;
		let stderrBytes = 0;
		let overflow = false;
		let overflowStream: "stdout" | "stderr" | null = null;
		let settled = false;

		const kill = (which: "stdout" | "stderr") => {
			if (overflow) return;
			overflow = true;
			overflowStream = which;
			try {
				proc.kill();
			} catch {
				/* ignore — process may already be exiting */
			}
		};

		proc.stdout?.on("data", (d: Buffer) => {
			if (overflow) return;
			stdoutBytes += d.length;
			if (stdoutBytes > cap) {
				kill("stdout");
				return;
			}
			stdoutChunks.push(d);
		});

		proc.stderr?.on("data", (d: Buffer) => {
			if (overflow) return;
			stderrBytes += d.length;
			if (stderrBytes > cap) {
				kill("stderr");
				return;
			}
			stderrChunks.push(d);
		});

		const settle = (result: ExecResult) => {
			if (settled) return;
			settled = true;
			resolve(result);
		};

		proc.on("close", (code) => {
			if (overflow) {
				const which = overflowStream ?? "output";
				const mb = Math.round(cap / (1024 * 1024));
				settle({
					code: 1,
					stdout: "",
					stderr:
						`pi-secret-guard: ${which} exceeded ${mb} MB cap during scan; ` +
						"refusing to load full diff into memory.\n" +
						"Either split this commit/push into smaller pieces, or bypass with " +
						"`git push --no-verify` (after manually verifying no secrets).",
					overflow: true,
				});
				return;
			}

			// Best-effort decode; guard against the kStringMaxLength path even if
			// the cap was set higher than safe. On decode failure we still fail-closed.
			try {
				settle({
					code: code ?? 1,
					stdout: Buffer.concat(stdoutChunks).toString("utf8"),
					stderr: Buffer.concat(stderrChunks).toString("utf8"),
				});
			} catch (err) {
				const msg = err instanceof Error ? err.message : String(err);
				settle({
					code: 1,
					stdout: "",
					stderr:
						`pi-secret-guard: failed to decode child output: ${msg}\n` +
						"This usually means the diff exceeded Node's string length limit.\n" +
						"Bypass with `git push --no-verify` after manual review.",
					overflow: true,
				});
			}
		});

		proc.on("error", (err) => {
			const msg = err instanceof Error ? err.message : String(err);
			settle({ code: 1, stdout: "", stderr: msg });
		});
	});
}

/**
 * Convenience wrapper for the common `git` invocations used by
 * pi-secret-guard. Equivalent to `execProc("git", args, cwd)`.
 */
export function execGit(
	args: string[],
	cwd: string,
	options: ExecOptions = {},
): Promise<ExecResult> {
	return execProc("git", args, cwd, options);
}
