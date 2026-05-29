/**
 * Unit tests for execProc / execGit (./extensions/exec.ts).
 *
 * Run with: npx tsx test/test-exec.ts
 *
 * These tests cover the byte-cap behavior that fixes the
 * `ERR_STRING_TOO_LONG` crash on very large diffs. We mock `spawn` to emit
 * controlled chunk streams so we can deterministically test overflow without
 * actually generating gigabytes of git data.
 */

import { EventEmitter } from "node:events";
import {
	DEFAULT_MAX_BUFFER_BYTES,
	resolveMaxBufferBytes,
	execProc,
	execGit,
} from "../extensions/exec.ts";

// ============================================================================
// Test harness — mirrors the style in test-scanner.ts
// ============================================================================

let passed = 0;
let failed = 0;

function group(name: string) {
	console.log(`\n${"═".repeat(60)}`);
	console.log(`  ${name}`);
	console.log(`${"═".repeat(60)}`);
}

function assert(description: string, condition: boolean) {
	if (condition) {
		passed++;
		console.log(`  ✅ ${description}`);
	} else {
		failed++;
		console.log(`  ❌ ${description}`);
	}
}

// ============================================================================
// Mock spawn — emits the scripted chunks then closes
// ============================================================================

interface ScriptStep {
	stream: "stdout" | "stderr";
	chunk: Buffer;
}

interface MockSpawnConfig {
	script: ScriptStep[];
	exitCode?: number;
	emitError?: Error;
	/** Delay between chunks in ms (0 = synchronous, default 0). */
	delayMs?: number;
}

function makeMockSpawn(config: MockSpawnConfig) {
	let killed = false;
	const procEvents = new EventEmitter() as EventEmitter & {
		stdout: EventEmitter;
		stderr: EventEmitter;
		kill: () => void;
	};
	procEvents.stdout = new EventEmitter();
	procEvents.stderr = new EventEmitter();
	procEvents.kill = () => {
		killed = true;
	};

	// Schedule script playback on next tick so listeners attach first.
	queueMicrotask(async () => {
		if (config.emitError) {
			procEvents.emit("error", config.emitError);
			return;
		}
		for (const step of config.script) {
			if (killed) break;
			if (config.delayMs && config.delayMs > 0) {
				await new Promise((r) => setTimeout(r, config.delayMs));
			}
			procEvents[step.stream].emit("data", step.chunk);
		}
		procEvents.emit("close", config.exitCode ?? 0);
	});

	// The real spawn returns ChildProcess; we return an object structurally
	// compatible with the slice that execProc uses. Cast through unknown to
	// satisfy the declared spawn return type without pulling all of its
	// internal fields into the mock.
	return procEvents as unknown as ReturnType<typeof import("node:child_process").spawn>;
}

function mockSpawnFactory(
	config: MockSpawnConfig,
): typeof import("node:child_process").spawn {
	return ((_command: string, _args: readonly string[], _opts: unknown) =>
		makeMockSpawn(config)) as typeof import("node:child_process").spawn;
}

// ============================================================================
// Tests
// ============================================================================

async function run() {
	// --------------------------------------------------------------------
	group("resolveMaxBufferBytes");

	assert(
		"defaults to DEFAULT_MAX_BUFFER_BYTES (256 MB) when env unset",
		resolveMaxBufferBytes(undefined) === DEFAULT_MAX_BUFFER_BYTES,
	);
	assert(
		"defaults to DEFAULT_MAX_BUFFER_BYTES on empty string",
		resolveMaxBufferBytes("") === DEFAULT_MAX_BUFFER_BYTES,
	);
	assert(
		"falls back to default on non-numeric value",
		resolveMaxBufferBytes("not-a-number") === DEFAULT_MAX_BUFFER_BYTES,
	);
	assert(
		"falls back to default on zero",
		resolveMaxBufferBytes("0") === DEFAULT_MAX_BUFFER_BYTES,
	);
	assert(
		"falls back to default on negative",
		resolveMaxBufferBytes("-1024") === DEFAULT_MAX_BUFFER_BYTES,
	);
	assert(
		"honors custom positive integer",
		resolveMaxBufferBytes("1048576") === 1024 * 1024,
	);
	assert(
		"floors fractional values",
		resolveMaxBufferBytes("100.7") === 100,
	);
	assert(
		"DEFAULT_MAX_BUFFER_BYTES leaves headroom below kStringMaxLength",
		// kStringMaxLength on x64 is 0x1fffffe8 ≈ 537 MB. We want the default
		// well below it so Buffer.concat + UTF-8 decode never trips the limit.
		// 256 MB ≈ 50% of the limit — comfortable single-buffer headroom.
		DEFAULT_MAX_BUFFER_BYTES < 0x1fffffe8 &&
			DEFAULT_MAX_BUFFER_BYTES <= Math.floor(0x1fffffe8 * 0.55),
	);

	// --------------------------------------------------------------------
	group("execProc — small output happy path");

	{
		const result = await execProc("git", ["dummy"], "/tmp", {
			spawnFn: mockSpawnFactory({
				script: [
					{ stream: "stdout", chunk: Buffer.from("hello world", "utf8") },
				],
				exitCode: 0,
			}),
		});
		assert("returns code 0", result.code === 0);
		assert("returns full stdout", result.stdout === "hello world");
		assert("returns empty stderr", result.stderr === "");
		assert("does NOT flag overflow", !result.overflow);
	}

	// --------------------------------------------------------------------
	group("execProc — stdout exactly at cap succeeds");

	{
		const cap = 1024;
		const exact = Buffer.alloc(cap, 0x61); // 1024 'a' bytes
		const result = await execProc("git", ["dummy"], "/tmp", {
			maxBufferBytes: cap,
			spawnFn: mockSpawnFactory({
				script: [{ stream: "stdout", chunk: exact }],
				exitCode: 0,
			}),
		});
		assert("returns code 0", result.code === 0);
		assert("returns full stdout (length matches cap)", result.stdout.length === cap);
		assert("does NOT flag overflow at exact boundary", !result.overflow);
	}

	// --------------------------------------------------------------------
	group("execProc — stdout over cap returns overflow error");

	{
		const cap = 1024;
		const big = Buffer.alloc(cap + 1, 0x62); // one byte over
		const result = await execProc("git", ["dummy"], "/tmp", {
			maxBufferBytes: cap,
			spawnFn: mockSpawnFactory({
				script: [{ stream: "stdout", chunk: big }],
				exitCode: 0,
			}),
		});
		assert("returns code 1", result.code === 1);
		assert("stdout is empty", result.stdout === "");
		assert("stderr describes overflow", /exceeded.*MB cap/.test(result.stderr));
		assert("stderr names stdout as the overflowing stream", /stdout/.test(result.stderr));
		assert("flags overflow", result.overflow === true);
		assert(
			"stderr suggests git push --no-verify bypass",
			result.stderr.includes("--no-verify"),
		);
	}

	// --------------------------------------------------------------------
	group("execProc — stderr over cap returns overflow error");

	{
		const cap = 512;
		const result = await execProc("git", ["dummy"], "/tmp", {
			maxBufferBytes: cap,
			spawnFn: mockSpawnFactory({
				script: [{ stream: "stderr", chunk: Buffer.alloc(cap + 1, 0x63) }],
				exitCode: 1,
			}),
		});
		assert("returns code 1", result.code === 1);
		assert("stderr describes overflow", /exceeded.*MB cap/.test(result.stderr));
		assert("stderr names stderr as the overflowing stream", /stderr/.test(result.stderr));
		assert("flags overflow", result.overflow === true);
	}

	// --------------------------------------------------------------------
	group("execProc — many small chunks summing over cap");

	{
		const cap = 4096;
		// 100 chunks × 100 bytes = 10000 bytes (~2.4× cap)
		const chunks: ScriptStep[] = Array.from({ length: 100 }, () => ({
			stream: "stdout" as const,
			chunk: Buffer.alloc(100, 0x64),
		}));
		const result = await execProc("git", ["dummy"], "/tmp", {
			maxBufferBytes: cap,
			spawnFn: mockSpawnFactory({ script: chunks, exitCode: 0, delayMs: 0 }),
		});
		assert("overflow detected across many chunks", result.overflow === true);
		assert("returns code 1", result.code === 1);
		assert("does not return partial stdout", result.stdout === "");
	}

	// --------------------------------------------------------------------
	group("execProc — child error path");

	{
		const result = await execProc("git", ["dummy"], "/tmp", {
			spawnFn: mockSpawnFactory({
				script: [],
				emitError: new Error("ENOENT: git not found"),
			}),
		});
		assert("returns code 1 on spawn error", result.code === 1);
		assert("propagates error message (not raw error toString)", /ENOENT/.test(result.stderr));
		assert("does not include 'Error:' prefix", !result.stderr.startsWith("Error:"));
		assert("does not crash", true);
	}

	// --------------------------------------------------------------------
	group("execProc — non-zero exit, output under cap is preserved");

	{
		const result = await execProc("git", ["dummy"], "/tmp", {
			spawnFn: mockSpawnFactory({
				script: [
					{ stream: "stdout", chunk: Buffer.from("ok", "utf8") },
					{ stream: "stderr", chunk: Buffer.from("warning: foo\n", "utf8") },
				],
				exitCode: 128,
			}),
		});
		assert("propagates exit code", result.code === 128);
		assert("preserves stdout", result.stdout === "ok");
		assert("preserves stderr", result.stderr === "warning: foo\n");
		assert("does NOT flag overflow", !result.overflow);
	}

	// --------------------------------------------------------------------
	group("execGit — convenience wrapper");

	{
		const result = await execGit(["dummy"], "/tmp", {
			spawnFn: mockSpawnFactory({
				script: [{ stream: "stdout", chunk: Buffer.from("git output", "utf8") }],
				exitCode: 0,
			}),
		});
		assert("execGit returns same shape as execProc", result.stdout === "git output");
		assert("execGit returns code 0", result.code === 0);
	}

	// --------------------------------------------------------------------
	group("execProc — async chunk stream with delay");

	{
		const cap = 100;
		// 5 chunks of 30 bytes each = 150 bytes total (over 100 cap)
		const chunks: ScriptStep[] = Array.from({ length: 5 }, () => ({
			stream: "stdout" as const,
			chunk: Buffer.alloc(30, 0x65),
		}));
		const result = await execProc("git", ["dummy"], "/tmp", {
			maxBufferBytes: cap,
			spawnFn: mockSpawnFactory({ script: chunks, exitCode: 0, delayMs: 1 }),
		});
		assert("overflow detected with async chunks", result.overflow === true);
		assert("returns code 1", result.code === 1);
	}

	// --------------------------------------------------------------------
	console.log(`\n${"═".repeat(60)}`);
	if (failed === 0) {
		console.log(`  ✅  ${passed} tests passed`);
	} else {
		console.log(`  ❌  ${failed} failed, ${passed} passed`);
	}
	console.log(`${"═".repeat(60)}\n`);

	process.exit(failed === 0 ? 0 : 1);
}

run().catch((err) => {
	console.error("Test runner crashed:", err);
	process.exit(2);
});
