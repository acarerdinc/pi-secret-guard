# pi-secret-guard 🔐

A [pi](https://github.com/badlogic/pi) extension that prevents accidental commits of secrets, API keys, and credentials to git repositories.

Uses a **hybrid approach**: fast regex pre-scan for known secret patterns, followed by LLM-powered contextual review of the full diff.

## How It Works

```
git commit / git push intercepted
         │
         ▼
  ┌─────────────┐
  │ Get the diff │  (staged changes for commit, unpushed commits for push)
  └──────┬──────┘
         │
         ▼
  ┌──────────────────┐      Found secrets
  │ Phase 1: Regex   │ ──────────────────► 🚨 HARD BLOCK
  │ pattern scan     │                     (must remove secrets)
  └──────┬───────────┘
         │ No regex hits
         ▼
  ┌──────────────────┐      Agent finds secrets
  │ Phase 2: Agent   │ ──────────────────► 🚫 Agent explains
  │ reviews the diff │                     and helps fix
  └──────┬───────────┘
         │ Agent says clean
         ▼
  ┌──────────────────┐
  │ Agent re-issues  │ ──► ✅ Allowed
  │ the command      │     (diff hash verified unchanged)
  └──────────────────┘
```

### Why hybrid?

- **Regex** is fast and catches well-known patterns (AWS keys, GitHub tokens, private keys) with zero latency and zero cost.
- **Agent review** catches subtle things regex can't: hardcoded database URLs in config objects, passwords that look like normal strings, tokens in unusual formats. The agent already has full project context, so it understands _what_ the code does and _whether_ a value is sensitive.

## Installation

### From GitHub (recommended)

```bash
pi install https://github.com/acarerdinc/pi-secret-guard
```

### Manual (global)

Clone into your pi extensions directory:

```bash
git clone https://github.com/acarerdinc/pi-secret-guard ~/.pi/agent/extensions/pi-secret-guard
```

### Manual (project-local)

```bash
git clone https://github.com/acarerdinc/pi-secret-guard .pi/extensions/pi-secret-guard
```

### Quick test (no install)

```bash
pi -e /path/to/pi-secret-guard
```

## What It Detects

### Phase 1 — Regex Patterns (instant block)

| Category | Patterns |
|----------|----------|
| **Cloud Providers** | AWS Access Key ID (`AKIA...`), AWS Secret Key, Azure Connection Strings, Azure Storage Keys, GCP Service Account Keys |
| **API Keys** | OpenAI (`sk-...`), Anthropic (`sk-ant-...`), Google (`AIza...`), Stripe (`sk_live_...`/`sk_test_...`), SendGrid (`SG....`), Twilio (`SK...`), Slack (`xox...`), Discord, Mailgun |
| **VCS Tokens** | GitHub PAT (`ghp_...`), GitHub OAuth/App/Fine-grained tokens, GitLab (`glpat-...`), Bitbucket (`ATBB...`) |
| **Private Keys** | RSA, EC, DSA, OpenSSH, PGP private key headers |
| **Auth Tokens** | JWT (`eyJ...`), Generic token/secret/password/api_key assignments |
| **URLs** | Credentials embedded in URLs, Database connection strings with passwords |

### Phase 1 — Suspicious File Detection (warning)

Files matching these patterns trigger an extra warning during agent review:

`.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `id_rsa`, `id_ed25519`, `credentials.json`, `service_account*.json`, `secrets.json/yaml/toml`, `.htpasswd`, `.netrc`

### Phase 2 — Agent Review (contextual)

The LLM reviews the full diff with project context, catching:

- Hardcoded passwords in config objects
- Database URLs with embedded credentials
- API tokens in unusual formats
- Secrets assigned to non-obvious variable names
- Anything that looks like it shouldn't be public

## Behavior

### On `git commit`

1. Retrieves `git diff --cached` (or includes unstaged changes for `git commit -a`)
2. Runs regex scan on all added lines
3. If secrets found → **hard block** with details of what was found
4. If clean → blocks and sends diff to agent for review
5. Agent reviews and either re-issues the command (clean) or explains the issue

### On `git push`

1. Retrieves diff of unpushed commits (`@{u}..HEAD`)
2. Same scan + review flow as commit
3. Falls back to `origin/main` or `origin/master` if no upstream is set

### Re-issue verification

When the agent re-issues a command after review, the extension verifies the diff hasn't changed by comparing SHA-256 hashes. If the diff changed (e.g., new files staged), a fresh review is required. Reviews expire after 5 minutes.

## Examples

### Regex catches an AWS key

```
🚨 SECRET GUARD: BLOCKED — Found 1 potential secret(s) in staged changes.

Secret patterns detected:
  🔴 [AWS Access Key ID] in config/aws.ts
     const accessKey = "███ AWS Access Key ID ███";

Action required:
  1. Remove or rotate the detected secrets
  2. Add sensitive files to .gitignore
  3. If these are FALSE POSITIVES, explain why to the user and let them decide
```

### Agent catches a hardcoded password

```
🔍 SECRET GUARD: Review required before commit.

[Agent reviews diff and responds:]

I found a potential issue in src/database.ts:

  const dbConfig = {
    host: "prod-db.internal",
    password: "super_secret_p4ssw0rd!",
  };

This hardcoded password should be moved to an environment variable.
I will NOT re-issue the commit.
```

## Why not just rely on GitHub Push Protection?

GitHub has its own [push protection](https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations/about-push-protection) that blocks pushes containing known secret patterns. It's a great last line of defense — but it operates at a fundamentally different stage:

```
Code is written
      │
      ▼
 pi-secret-guard        ← Blocks BEFORE the commit (secret never enters git history)
      │
      ▼
 git commit
      │
      ▼
 GitHub Push Protection  ← Blocks BEFORE the push (secret is in local history)
      │
      ▼
 GitHub Secret Scanning  ← Alerts AFTER the push (async, broader coverage)
```

| | pi-secret-guard | GitHub Push Protection |
|---|---|---|
| **When** | Before `git commit` | Before `git push` |
| **Secret in git history?** | ❌ Never | ✅ Already committed locally |
| **Cleanup needed?** | Just fix the file | Rewrite git history (`reset`, `rebase`, `filter-branch`) |
| **Contextual review** | ✅ LLM reads the diff with project context | ❌ Pattern matching only |
| **Catches subtle secrets** | ✅ Hardcoded passwords, internal URLs, config objects | ❌ Only known token formats |
| **Works offline** | ✅ Regex phase works without network | ❌ Requires GitHub remote |

The earlier you catch a secret, the cheaper the fix. This extension ensures secrets never make it into a commit in the first place — GitHub Push Protection is a safety net for anything that slips through.

## Limitations

- **Regex false positives**: Some patterns (e.g., generic password assignment) may flag non-sensitive values. The agent review helps distinguish real secrets from false positives.
- **Binary files**: Only text diffs are scanned. Secrets embedded in binary files won't be detected.
- **Agent judgment**: Phase 2 relies on the LLM's ability to identify secrets. Quality depends on the model used.
- **Large diffs**: Diffs are truncated to ~30KB for agent review. Extremely large commits may not be fully reviewed.
- **Existing history**: Only scans the current diff, not the full repository history. Use tools like [truffleHog](https://github.com/trufflesecurity/trufflehog) or [gitleaks](https://github.com/gitleaks/gitleaks) to scan existing history.

## License

MIT
