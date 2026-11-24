/**
 * Unit tests for the secret scanner engine.
 * Run with: npx tsx test/test-scanner.ts
 */

import {
	SECRET_PATTERNS,
	SUSPICIOUS_FILE_PATTERNS,
	detectGitAction,
	isCommitAll,
	hashDiff,
	scanDiffForSecrets,
	scanFileNames,
	formatFindings,
} from "../extensions/scanner.ts";

// ============================================================================
// Test Harness
// ============================================================================

let passed = 0;
let failed = 0;
let currentGroup = "";

function group(name: string) {
	currentGroup = name;
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

function assertMatch(patternName: string, input: string) {
	const pattern = SECRET_PATTERNS.find((p) => p.name === patternName);
	if (!pattern) {
		failed++;
		console.log(`  ❌ Pattern not found: "${patternName}"`);
		return;
	}
	assert(`${patternName} matches: ${input.slice(0, 60)}...`, pattern.pattern.test(input));
}

function assertNoMatch(patternName: string, input: string) {
	const pattern = SECRET_PATTERNS.find((p) => p.name === patternName);
	if (!pattern) {
		failed++;
		console.log(`  ❌ Pattern not found: "${patternName}"`);
		return;
	}
	assert(`${patternName} does NOT match: ${input.slice(0, 60)}...`, !pattern.pattern.test(input));
}

// ============================================================================
// Helper: build a fake git diff
// ============================================================================

function makeDiff(files: { path: string; addedLines: string[] }[]): string {
	const parts: string[] = [];
	for (const file of files) {
		parts.push(`diff --git a/${file.path} b/${file.path}`);
		parts.push(`--- a/${file.path}`);
		parts.push(`+++ b/${file.path}`);
		parts.push(`@@ -0,0 +1,${file.addedLines.length} @@`);
		for (const line of file.addedLines) {
			parts.push(`+${line}`);
		}
	}
	return parts.join("\n");
}

// ============================================================================
// Tests: Regex Patterns
// ============================================================================

group("AWS Patterns");
// Build at runtime to avoid GitHub push protection
const fakeAwsKeyId = "AKIA" + "IOSFODNN7EXAMPLE";
const fakeAwsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY00";
assertMatch("AWS Access Key ID", `const key = '${fakeAwsKeyId}'`);
assertMatch("AWS Access Key ID", fakeAwsKeyId);
assertNoMatch("AWS Access Key ID", "AKIA_short");
assertMatch("AWS Secret Access Key", `aws_secret_access_key = ${fakeAwsSecret}`);
assertMatch("AWS Secret Access Key", `aws_secret: "${fakeAwsSecret}"`);

group("Google / GCP");
assertMatch("Google API Key", "const key = AIzaSyA1234567890abcdefghijklmnopqrstuv");
assertNoMatch("Google API Key", "AIzaShort");
assertMatch("Google Cloud Service Account Key", '"private_key": "-----BEGIN RSA PRIVATE KEY-----');

group("OpenAI / Anthropic");
// Build at runtime to avoid GitHub push protection
const fakeOpenAi1 = "sk" + "-abc123def456ghi789jkl012mno";
const fakeOpenAi2 = ["sk", "proj", "abc123def456ghi789jklmnopqrstuv"].join("-");
const fakeOpenAi3 = ["sk", "svcacct", "abc123def456ghi789jklmno"].join("-");
const fakeAnthropic = ["sk", "ant", "abc123", "def456ghi789jkl012mno"].join("-");
assertMatch("OpenAI API Key", `const key = ${fakeOpenAi1}`);
assertMatch("OpenAI API Key", fakeOpenAi2);
assertMatch("OpenAI API Key", fakeOpenAi3);
assertNoMatch("OpenAI API Key", "sk-short");
assertMatch("Anthropic API Key", fakeAnthropic);

group("Stripe");
// Build test values at runtime to avoid GitHub push protection flagging them
const skLive = ["sk", "live", "FAKEFAKEFAKEFAKEFAKEFAKE"].join("_");
const skTest = ["sk", "test", "FAKEFAKEFAKEFAKEFAKEFAKE"].join("_");
const pkLive = ["pk", "live", "FAKEFAKEFAKEFAKEFAKEFAKE"].join("_");
assertMatch("Stripe Secret Key", skLive);
assertMatch("Stripe Secret Key", skTest);
assertMatch("Stripe Publishable Key", pkLive);
assertNoMatch("Stripe Secret Key", ["sk", "live", "short"].join("_"));

group("SendGrid");
// Build at runtime to avoid GitHub push protection
const sgKey = "SG" + "." + "FAKEFAKEFAKEFAKEFAKEFA" + "." + "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEfakeXYZ";
assertMatch("SendGrid API Key", sgKey);

group("Slack / Discord / Mailgun");
// Build at runtime to avoid GitHub push protection
const slackToken = "xoxb" + "-123456789012-abcdefgh";
const mailgunKey = "key" + "-" + "abcdefghijklmnopqrstuvwxyz012345";
assertMatch("Slack Token", slackToken);
assertMatch("Mailgun API Key", mailgunKey);
assertNoMatch("Slack Token", "xoxb-short");

group("GitHub / GitLab / Bitbucket Tokens");
// Build at runtime to avoid GitHub push protection
const ghpToken = "ghp" + "_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
const ghPatToken = "github" + "_pat_" + "ABCDEFGHIJKLMNOPQRSTUVW";
const glToken = "glpat" + "-" + "ABCDEFGHIJKLMNOPQRSTUv";
const bbToken = "ATBB" + "0123456789abcdef0123456789abcdef";
assertMatch("GitHub Personal Access Token", ghpToken);
assertMatch("GitHub Fine-grained Token", ghPatToken);
assertMatch("GitLab Token", glToken);
assertMatch("Bitbucket App Password", bbToken);

group("Private Keys");
assertMatch("Private Key", "-----BEGIN RSA PRIVATE KEY-----");
assertMatch("Private Key", "-----BEGIN PRIVATE KEY-----");
assertMatch("Private Key", "-----BEGIN EC PRIVATE KEY-----");
assertMatch("Private Key", "-----BEGIN OPENSSH PRIVATE KEY-----");
assertNoMatch("Private Key", "-----BEGIN PUBLIC KEY-----");

group("JWT");
assertMatch(
	"JWT Token",
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
);
assertNoMatch("JWT Token", "eyJshort.eyJshort.short");

group("Credentials in URLs");
assertMatch("Credentials in URL", "https://admin:supersecret@example.com/api");
assertMatch("Database URL with Credentials", "postgresql://user:pass@localhost:5432/db");
assertMatch("Database URL with Credentials", "mongodb://admin:p4ssw0rd@cluster.mongodb.net/mydb");
assertMatch("Database URL with Credentials", "redis://default:secret@cache.example.com:6379");
assertNoMatch("Credentials in URL", "https://example.com/path");

group("Azure");
assertMatch(
	"Azure Connection String",
	"DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=abc123+def456==;",
);

group("Generic Patterns");
assertMatch("Generic API Key Assignment", 'api_key = "abcdefghijklmnopqrstuvwxyz1234"');
assertMatch("Generic API Key Assignment", "apikey: ABCDEFghijklmnopqrstuv1234");
assertMatch("Generic Secret Assignment", 'client_secret = "abcdefghijklmnopqrstuvwxyz1234"');
assertMatch("Generic Password Assignment", 'password = "my_super_secret_pw"');
assertMatch("Generic Password Assignment", "pwd: hunter2isnotgood");
assertMatch(
	"Generic Token Assignment",
	'access_token = "abcdefghijklmnopqrstuvwxyz1234"',
);
// Should NOT match short values
assertNoMatch("Generic Password Assignment", "password = short");
assertNoMatch("Generic API Key Assignment", "api_key = abc");

// ============================================================================
// Tests: Reference Values
// ----------------------------------------------------------------------------
// The patterns above still match these lines; what changes is that
// scanDiffForSecrets does not report them, because the value names where a
// secret lives instead of being one. These go through scanDiffForSecrets rather
// than assertMatch for that reason.
// ============================================================================

function scanLine(line: string): string[] {
	return scanDiffForSecrets(`+++ b/probe.yaml\n+${line}`).map((f) => f.name);
}

function assertNotFlagged(description: string, line: string) {
	const findings = scanLine(line);
	assert(`${description} — not flagged`, findings.length === 0);
	if (findings.length > 0) console.log(`     unexpected: ${findings.join(", ")}`);
}

function assertFlagged(description: string, line: string) {
	assert(`${description} — still flagged`, scanLine(line).length > 0);
}

group("Reference Values: not secrets");
assertNotFlagged("LiteLLM os.environ/ form", "      api_key: os.environ/VENICE_INFERENCE_KEY");
assertNotFlagged("os.environ dotted form", "      api_key: os.environ.DEEPINFRA_API_KEY");
assertNotFlagged("quoted", '      api_key: "os.environ/VENICE_INFERENCE_KEY"');
assertNotFlagged("JSON style", '        "api_key": "os.environ/VENICE_INFERENCE_KEY"');
assertNotFlagged("shell ${VAR}", "      api_key: ${VENICE_INFERENCE_KEY}");
assertNotFlagged("shell ${VAR:-default}", "      api_key: ${VENICE_INFERENCE_KEY:-none}");
assertNotFlagged("shell $VAR", "      api_key: $VENICE_INFERENCE_KEY");
assertNotFlagged("compose !secret", "      api_key: !secret venice_key");
assertNotFlagged("password reference", 'password = "${DB_PASSWORD}"');
assertNotFlagged("token reference", "      access_token: os.environ/GITHUB_TOKEN");
assertNotFlagged("secret reference", "      client_secret: os.environ/OAUTH_CLIENT_SECRET");

group("Reference Values: real secrets still block");
// Built at runtime to avoid push protection, matching the fixtures above.
const fakeGenericKey = "abcdefghijklmnopqrstuvwxyz" + "1234";
const fakePwValue = "my_super" + "_secret_pw";
const fakePunctuatedRef = "os.environ/NOT_A_VAR_NAME" + "!";
const fakeOpenAiKey = ["sk", "proj", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"].join("-");
const fakeSmuggledKey = ["sk", "proj", "AbCdEfGhIjKlMnOpQrStUvWx"].join("-");
assertFlagged("opaque key", `      api_key: ${fakeGenericKey}`);
assertFlagged("plaintext password", `password = "${fakePwValue}"`);
assertFlagged("OpenAI format", `      api_key: ${fakeOpenAiKey}`);
// A reference marker alone must not launder a secret placed after it.
assertFlagged("smuggle via os.environ/", `      api_key: os.environ/${fakeSmuggledKey}`);
assertFlagged("reference with punctuation tail", `      api_key: ${fakePunctuatedRef}`);
// A reference marker must not launder a secret sharing the same value.
assertFlagged(
	"reference plus a real key",
	`      api_key: os.environ/A_B,${fakeOpenAiKey}`,
);

// Suppression is per match, not per line. A line-level boolean would let the
// reference below vouch for the real secret sitting next to it, whichever order
// they appear in, because the first match would classify the whole line.
assertFlagged(
	"reference launders a second key (ref first)",
	`password: \${DB_PASS} api_key: ${fakeGenericKey}`,
);
assertFlagged(
	"reference launders a second key (secret first)",
	`api_key: os.environ/A_B password: ${fakePwValue}`,
);
assertFlagged(
	"reference launders a same-named key",
	`api_key: os.environ/A_B api_key: ${fakeGenericKey}`,
);
assertFlagged(
	"reference launders a token key",
	`access_token: \${OK} bearer = ${fakeGenericKey}`,
);

// The suppression is limited to the generic patterns. A provider-specific format
// is unambiguous, so sharing a line with a reference must not excuse it. This is
// the property the whole filter rests on: it narrows generic findings only.
assertFlagged(
	"aws key beside a reference",
	`api_key: os.environ/A_B aws_access_key_id = AKIA${"A".repeat(16)}`,
);
assertFlagged(
	"openai key beside a reference",
	`password: \${OK} key = ${fakeOpenAiKey}`,
);

// These carry no secret-shaped value at all, so no pattern fires with or without
// the reference filter. Asserted so a future pattern change cannot quietly start
// or stop matching them.
group("Reference Values: no pattern fires");
assertNotFlagged("empty reference tail", "      api_key: os.environ/");
assertNotFlagged("shell expansion with a dash", "      api_key: ${not-a-var-name}");


// ============================================================================
// Tests: Git Command Detection
// ============================================================================

group("Git Command Detection");

assert('detects "git commit"', detectGitAction("git commit -m 'msg'") === "commit");
assert('detects "git push"', detectGitAction("git push origin main") === "push");
assert("detects compound command", detectGitAction("cd /app && git commit -am 'msg'") === "commit");
assert("returns null for non-git", detectGitAction("echo hello") === null);
assert("returns null for git status", detectGitAction("git status") === null);
assert('detects "git push --force"', detectGitAction("git push --force origin main") === "push");
assert("detects env-prefixed git commit", detectGitAction("FOO=1 git commit -m 'msg'") === "commit");
assert("ignores .git paths containing commit", detectGitAction("python - <<'PY'\nprint('/repo/.git/pi-secret-guard/review-commit.json')\nPY") === null);
assert("ignores plain text mentioning git push", detectGitAction("echo 'please git push origin main later'") === null);

// Shell-wrapped commands (bash -c, sh -c, etc.)
assert('detects bash -c "git commit"', detectGitAction("bash -c \"git commit -m 'msg'\"") === "commit");
assert('detects sh -c "git commit"', detectGitAction("sh -c 'git commit -m msg'") === "commit");
assert('detects bash -c "git push"', detectGitAction("bash -c \"git push origin main\"") === "push");
assert('detects sh -c "git push"', detectGitAction("sh -c 'git push origin main'") === "push");
assert('detects bash -c git commit -am', detectGitAction("bash -c 'git commit -am \"Update\"'") === "commit");

group("Git Commit -a Detection");

assert('detects "git commit -a"', isCommitAll("git commit -a -m 'msg'") === true);
assert('detects "git commit -am"', isCommitAll("git commit -am 'msg'") === true);
assert('detects "git commit --all"', isCommitAll("git commit --all -m 'msg'") === true);
assert('detects "git commit -sam"', isCommitAll("git commit -sam 'msg'") === true);
assert("no -a flag", isCommitAll("git commit -m 'msg'") === false);
// Shell-wrapped commands
assert('detects bash -c "git commit -am"', isCommitAll("bash -c 'git commit -am msg'") === true);
assert('no -a flag in bash -c', isCommitAll("bash -c 'git commit -m msg'") === false);

// ============================================================================
// Tests: Diff Scanning
// ============================================================================

group("Diff Scanning — Secrets Found");
{
	const fakeAwsKeyInDiff = "AKIA" + "IOSFODNN7EXAMPLE";
	const diff = makeDiff([
		{
			path: "config/aws.ts",
			addedLines: [
				`export const AWS_KEY = "${fakeAwsKeyInDiff}";`,
				'export const region = "us-east-1";', // clean line
			],
		},
		{
			path: "src/db.ts",
			addedLines: [
				'const dbUrl = "postgresql://admin:supersecret@prod.db.com:5432/myapp";',
			],
		},
	]);

	const findings = scanDiffForSecrets(diff);
	assert(`Found ${findings.length} secrets (expected 2)`, findings.length === 2);
	assert(
		"First finding is AWS key",
		findings[0]?.name === "AWS Access Key ID",
	);
	assert("First finding in correct file", findings[0]?.file === "config/aws.ts");
	assert(
		"Second finding is DB URL",
		findings[1]?.name === "Database URL with Credentials",
	);
	assert("Second finding in correct file", findings[1]?.file === "src/db.ts");
	assert(
		"Snippet is masked",
		findings[0]?.snippet?.includes("███") ?? false,
	);
}

group("Diff Scanning — Clean Diff");
{
	const diff = makeDiff([
		{
			path: "src/app.ts",
			addedLines: [
				'console.log("Hello, world!");',
				"const x = 42;",
				'import { foo } from "./bar";',
			],
		},
	]);

	const findings = scanDiffForSecrets(diff);
	assert("No secrets found in clean diff", findings.length === 0);
}

group("Diff Scanning — Only Added Lines");
{
	// Lines starting with - (removed) should not be scanned
	const removedAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";
	const diff = [
		"diff --git a/config.ts b/config.ts",
		"--- a/config.ts",
		"+++ b/config.ts",
		"@@ -1,3 +1,3 @@",
		`-const key = "${removedAwsKey}";`, // removed — should NOT trigger
		'+const key = process.env.AWS_KEY;', // added — clean
	].join("\n");

	const findings = scanDiffForSecrets(diff);
	assert("Removed lines are not scanned", findings.length === 0);
}

// ============================================================================
// Tests: Suspicious File Names
// ============================================================================

group("Suspicious File Detection");
{
	const diff = makeDiff([
		{ path: ".env", addedLines: ["FOO=bar"] },
		{ path: ".env.production", addedLines: ["DB_HOST=prod.db.com"] },
		{ path: "certs/server.pem", addedLines: ["...cert..."] },
		{ path: "keys/id_rsa", addedLines: ["...key..."] },
		{ path: "config/credentials.json", addedLines: ['{"key": "val"}'] },
		{ path: "src/app.ts", addedLines: ["// normal file"] },
	]);

	const findings = scanFileNames(diff);
	assert(`Found ${findings.length} suspicious files (expected 5)`, findings.length === 5);

	const fileNames = findings.map((f) => f.file);
	assert(".env detected", fileNames.includes(".env"));
	assert(".env.production detected", fileNames.includes(".env.production"));
	assert("server.pem detected", fileNames.includes("certs/server.pem"));
	assert("id_rsa detected", fileNames.includes("keys/id_rsa"));
	assert("credentials.json detected", fileNames.includes("config/credentials.json"));
	assert("app.ts NOT flagged", !fileNames.includes("src/app.ts"));
}

// ============================================================================
// Tests: Hash Function
// ============================================================================

group("Diff Hashing");
{
	const diff1 = "some diff content";
	const diff2 = "some diff content";
	const diff3 = "different diff content";

	assert("Same content produces same hash", hashDiff(diff1) === hashDiff(diff2));
	assert("Different content produces different hash", hashDiff(diff1) !== hashDiff(diff3));
	assert("Hash is 64-char hex string", /^[0-9a-f]{64}$/.test(hashDiff(diff1)));
}

// ============================================================================
// Tests: Format Findings
// ============================================================================

group("Format Findings");
{
	const findings = [
		{ type: "secret" as const, name: "AWS Access Key ID", file: "config.ts", snippet: "███ AWS ███" },
		{ type: "suspicious-file" as const, name: ".env file", file: ".env" },
	];

	const formatted = formatFindings(findings);
	assert("Contains secret heading", formatted.includes("Secret patterns detected:"));
	assert("Contains file heading", formatted.includes("Suspicious files detected:"));
	assert("Contains 🔴 marker", formatted.includes("🔴"));
	assert("Contains 🟡 marker", formatted.includes("🟡"));
	assert("Contains file path", formatted.includes("config.ts"));
}

// ============================================================================
// Summary
// ============================================================================

console.log(`\n${"═".repeat(60)}`);
console.log(`  Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
console.log(`${"═".repeat(60)}\n`);

process.exit(failed > 0 ? 1 : 0);
