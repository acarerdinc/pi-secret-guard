# pi-secret-guard Bug: `getEntries` Crash on Git Commands

## Priority: HIGH — Extension blocks all git commit/push operations

---

## What Goes Wrong

Any bash command matching a git commit or push pattern (e.g. `git commit -m "..."`, `git push origin main`) triggers a crash with:

```
Cannot read properties of undefined (reading 'getEntries')
```

**Effect:** The extension intercepts the command, shows the diff review UI, the user approves, the agent re-issues the command — and it crashes again. All git operations are broken while this extension is loaded.

---

## When It Happens

The crash occurs during the **Phase 2 agent review** block in `extensions/index.ts`. The flow is:

```
bash tool_call (git commit/push detected)
  → pi-secret-guard.on("tool_call") handler fires
    → scans diff with regex (Phase 1) — clean
    → Phase 2: builds diff summary, sets reviewState
    → returns { block: true, reason: "..." }     ← Pi shows diff to agent
      → Agent reviews, re-issues same command    ← CRASH HERE
```

The re-issue hits the same handler, but **before the handler even runs**, something crashes.

---

## Root Cause (Narrowed Down)

The crash happens somewhere in the **pi-coding-agent core** when processing the re-issued `git commit` command. Evidence:

- The crash returns `Cannot read properties of undefined (reading 'getEntries')`
- `sessionManager.getEntries()` is called in several places in the agent core (found in `agent-session.js` lines 1339, 1523, 2403)
- The `pi-secret-guard` extension calls `pi.exec("git", ["diff", "--cached", "--no-color"])` from within its `tool_call` handler
- This `pi.exec()` call triggers something in the core that eventually calls `sessionManager.getEntries()` on an **undefined sessionManager**

**Most likely cause:** `pi.exec()` in the extension context somehow triggers a session compaction or event emission that fires before the session manager is initialized, or accesses `sessionManager` on an undefined object.

---

## Where to Look

### 1. `pi-secret-guard/extensions/index.ts` — the entry point

The `tool_call` handler is at line 47. The `pi.exec()` calls are at lines 66-83:

```typescript
if (gitAction === "commit") {
    const result = await pi.exec("git", ["diff", "--cached", "--no-color"]);
    // ...
}
```

**Suspect:** Calling `pi.exec()` from within a `tool_call` event handler. The re-entrant nature (handler fires, blocks, same command re-issued, handler fires again) may expose a race condition.

### 2. `pi-coding-agent/dist/core/exec.js` — what `pi.exec()` does

`execCommand()` is a simple `spawn()` wrapper. It does **not** call `getEntries`. So the crash is elsewhere in the call chain triggered by `pi.exec()`.

### 3. `pi-coding-agent/dist/core/agent-session.js` — the crash site

Lines 1339, 1523, 2403 call `this.sessionManager.getEntries()`. The crash means `this.sessionManager` is `undefined` at one of those call sites.

Key areas:
- **Line ~150-155:** `_installAgentToolHooks` → `runner.emitToolCall()`. This fires the extension's `tool_call` handler. But the crash happens on the **re-issue**, not the first call.
- **Line ~1339:** Inside a compaction result handler
- **Line ~1523:** Inside auto-compaction
- **Line ~2403:** Unknown context

### 4. `pi-coding-agent/dist/core/extensions/runner.js` — extension runner

- `emitToolCall()` at line 471 creates a `ctx = this.createContext()` which includes `sessionManager: this.sessionManager` (line 361)
- `sessionManager` is passed to the constructor at line 112
- The crash could be in `createContext()` itself if `this.sessionManager` is undefined at that moment

### 5. `pi-coding-agent/dist/core/session-manager.js` — `getEntries()` definition

The actual `getEntries()` method. Not the crash site — it's called on an undefined reference.

---

## Key Files

| File | Role |
|------|------|
| `pi-secret-guard/extensions/index.ts` | Extension entry, calls `pi.exec()` in `tool_call` handler |
| `pi-secret-guard/extensions/scanner.ts` | Regex scanning (not related to crash) |
| `pi-coding-agent/dist/core/agent-session.js` | Where `getEntries()` is called on undefined `sessionManager` |
| `pi-coding-agent/dist/core/extensions/runner.js` | Extension runner, creates context with `sessionManager` |
| `pi-coding-agent/dist/core/exec.js` | `pi.exec()` implementation (not the crash site) |

---

## Minimal Reproduction

```bash
cd /mnt/storage/projects/trendyol
git add .
git commit -m "test"
# → extension blocks, shows diff, agent reviews
# → re-issue → CRASH: "Cannot read properties of undefined (reading 'getEntries')"
```

---

## Hypotheses (ranked by likelihood)

1. **Re-entrant crash:** The `tool_call` handler fires twice in quick succession (first call blocks, re-issue triggers a second call before the first completes or cleans up state). The second call accesses `sessionManager` before it's bound. Fix: add a mutex/lock in the handler.

2. **`pi.exec()` triggers session event:** Calling `pi.exec()` from within the `tool_call` handler causes pi's core to emit a session event (e.g. `session_before_compact`) that calls `getEntries()` before the session manager is ready. Fix: avoid `pi.exec()` from `tool_call`; use a different approach (e.g. direct `spawn` from extension).

3. **Extension context `sessionManager` is undefined:** The `ExtensionContext` passed to the handler has `sessionManager: undefined` for certain event types or session states. Fix: add null check in extension.

4. **Auto-compaction race:** An auto-compaction runs at the exact moment the re-issued command is processed, and `getEntries()` is called on a session manager that's been replaced/nullified. Fix: guard in agent-session.js.

---

## Suggested Fix Approaches

### Option A — Fix in pi-secret-guard (simplest)

In `extensions/index.ts`, instead of using `pi.exec()` from the `tool_call` handler, use a direct Node.js `spawn`:

```typescript
import { spawn } from "node:child_process";

// Replace:
//   const result = await pi.exec("git", ["diff", "--cached", "--no-color"]);
// With:
const result = await new Promise((resolve) => {
    const proc = spawn("git", ["diff", "--cached", "--no-color"], { cwd: "/mnt/storage/projects/trendyol" });
    let stdout = "", stderr = "";
    proc.stdout?.on("data", d => stdout += d);
    proc.stderr?.on("data", d => stderr += d);
    proc.on("close", code => resolve({ code, stdout, stderr }));
});
```

This avoids whatever re-entrant behavior `pi.exec()` triggers.

### Option B — Add null guard in the extension

Check if `ctx.sessionManager` is available before the `tool_call` handler does anything:

```typescript
pi.on("tool_call", async (event, ctx) => {
    // Guard against undefined sessionManager
    if (!ctx.sessionManager) {
        return; // Let pi handle it normally
    }
    // ... rest of handler
});
```

### Option C — Investigate pi-coding-agent core

Find where `sessionManager` becomes undefined in the call chain from `tool_call` → `emitToolCall()` → crash. This would be a bug in pi-coding-agent itself, not the extension.

---

## Setup for Debugging

```
pi v0.62.0
pi-secret-guard v1.2.0
Node.js environment (extension uses TypeScript)
Extension path: /mnt/storage/projects/pi-extensions/pi-secret-guard/
Agent session: /mnt/storage/projects/trendyol/
```

The repo at `/mnt/storage/projects/trendyol` has a staged rename from `project1-vlm-product-understanding/` to `multimodal-product-understanding/` that is ready to commit — this is the use case that triggers the bug.

---

## What Was Tried

- Re-issuing the exact same command after the block → same crash
- `--no-verify` flag → same crash
- Disabling git hooks globally (`core.hooksPath /dev/null`) → same crash
- Environment variable flags (`GIT_PI_SECRET_GUARD=0`) → same crash
- Basic `echo hello` works fine — bash tool itself is functional
- `ls`, `git status` work fine — only `git commit` and `git push` are intercepted by the extension and crash

**Conclusion:** The crash is entirely within pi's extension mechanism, not git itself.
