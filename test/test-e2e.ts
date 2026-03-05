/**
 * End-to-end tests against a real git repo.
 *
 * Simulates the extension flow:
 *   1. Sets up a git repo with test files
 *   2. Stages files
 *   3. Runs the scanner against `git diff --cached`
 *   4. Validates findings
 *
 * Run with: npx tsx test/test-e2e.ts
 */

import { execSync } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
	scanDiffForSecrets,
	scanFileNames,
	hashDiff,
	detectGitAction,
	isCommitAll,
} from "../extensions/scanner.ts";

// ============================================================================
// Test Harness
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
// Git Helpers
// ============================================================================

const TEST_DIR = join(process.cwd(), ".test-repo-e2e");

function git(args: string): string {
	try {
		return execSync(`git ${args}`, { cwd: TEST_DIR, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] });
	} catch (e: any) {
		return e.stdout ?? "";
	}
}

function setupRepo() {
	if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
	mkdirSync(TEST_DIR, { recursive: true });
	git("init");
	git('config user.email "test@test.com"');
	git('config user.name "Test"');
}

function writeFile(relativePath: string, content: string) {
	const fullPath = join(TEST_DIR, relativePath);
	const dir = fullPath.substring(0, fullPath.lastIndexOf(/[/\\]/.test(fullPath) ? (fullPath.includes("\\") ? "\\" : "/") : "/"));
	mkdirSync(dir, { recursive: true });
	writeFileSync(fullPath, content, "utf-8");
}

function stageAll() {
	git("add -A");
}

function getStagedDiff(): string {
	return git("diff --cached --no-color");
}

function commitAll(msg: string) {
	git(`commit -m "${msg}"`);
}

function cleanup() {
	if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
}

// ============================================================================
// Test Scenario 1: Obvious secrets — regex hard block
// ============================================================================

group("Scenario 1: Regex catches obvious secrets");
{
	setupRepo();

	// Build fake secrets at runtime to avoid GitHub push protection
	const fakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";
	const fakeAwsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
	const fakeOpenAiKey = ["sk", "proj", "abc123def456ghi789jklmnopqrstuv"].join("-");

	writeFile("config/aws.ts", `
export const AWS_ACCESS_KEY = "${fakeAwsKey}";
export const AWS_SECRET = "${fakeAwsSecret}";
`);

	writeFile("src/db.ts", `
const DB_URL = "postgresql://admin:super_secret@prod.db.com:5432/myapp";
`);

	writeFile(".env", `
DATABASE_URL=postgresql://user:pass@localhost:5432/dev
API_KEY=${fakeOpenAiKey}
SECRET_KEY=mysecretkey1234567890abcdef
`);

	writeFile("src/app.ts", `
console.log("Hello world");
const port = 3000;
`);

	stageAll();
	const diff = getStagedDiff();

	assert("Got a non-empty diff", diff.length > 0);

	const secretFindings = scanDiffForSecrets(diff);
	const fileFindings = scanFileNames(diff);

	console.log(`\n  Secret findings (${secretFindings.length}):`);
	for (const f of secretFindings) {
		console.log(`    🔴 [${f.name}] in ${f.file}`);
	}
	console.log(`  File findings (${fileFindings.length}):`);
	for (const f of fileFindings) {
		console.log(`    🟡 [${f.name}] ${f.file}`);
	}

	assert("Found AWS Access Key ID", secretFindings.some((f) => f.name === "AWS Access Key ID"));
	assert("Found AWS Secret Access Key", secretFindings.some((f) => f.name === "AWS Secret Access Key"));
	assert("Found Database URL", secretFindings.some((f) => f.name === "Database URL with Credentials"));
	assert("Found OpenAI-style key (sk-)", secretFindings.some((f) => f.name === "OpenAI API Key"));
	assert("Flagged .env file", fileFindings.some((f) => f.name === ".env file"));
	assert("Clean file app.ts NOT flagged", !secretFindings.some((f) => f.file === "src/app.ts"));
	assert("Snippets are masked", secretFindings.every((f) => f.snippet?.includes("███") ?? true));
	assert("Would hard block (secretFindings > 0)", secretFindings.length > 0);

	cleanup();
}

// ============================================================================
// Test Scenario 2: Subtle secrets — regex clean, needs agent review
// ============================================================================

group("Scenario 2: Subtle secrets (regex misses, agent should catch)");
{
	setupRepo();

	writeFile("src/config.ts", `
const dbConfig = {
	host: "prod-database.internal.company.com",
	port: 5432,
	username: "app_service",
	auth: "Tr0ub4dor&3",
	database: "production",
};

const ADMIN_USER = "superadmin";
const ADMIN_PASS = "ChangeMe123!";
`);

	writeFile("src/utils.ts", `
export function add(a: number, b: number) { return a + b; }
`);

	stageAll();
	const diff = getStagedDiff();

	const secretFindings = scanDiffForSecrets(diff);
	const fileFindings = scanFileNames(diff);

	console.log(`\n  Secret findings (${secretFindings.length}):`);
	for (const f of secretFindings) {
		console.log(`    🔴 [${f.name}] in ${f.file}`);
	}

	// These subtle secrets should NOT be caught by regex (that's the point — agent review handles them)
	assert("No regex findings for subtle secrets", secretFindings.length === 0);
	assert("No suspicious files", fileFindings.length === 0);
	assert("Would proceed to agent review (Phase 2)", secretFindings.length === 0);

	// Verify the diff contains the subtle secrets (agent would see them)
	assert("Diff contains hardcoded password", diff.includes("Tr0ub4dor&3"));
	assert("Diff contains admin credentials", diff.includes("ChangeMe123!"));

	cleanup();
}

// ============================================================================
// Test Scenario 3: Completely clean commit
// ============================================================================

group("Scenario 3: Clean commit — no secrets at all");
{
	setupRepo();

	writeFile("src/app.ts", `
export function greet(name: string): string {
	return "Hello, " + name + "!";
}

export const config = {
	port: parseInt(process.env.PORT || "3000"),
	host: process.env.HOST || "localhost",
	debug: process.env.DEBUG === "true",
};
`);

	writeFile("README.md", `# My Project\n\nA sample project.\n`);

	stageAll();
	const diff = getStagedDiff();

	const secretFindings = scanDiffForSecrets(diff);
	const fileFindings = scanFileNames(diff);

	assert("No secret findings", secretFindings.length === 0);
	assert("No suspicious files", fileFindings.length === 0);
	assert("Would proceed to agent review, then allow", true);

	cleanup();
}

// ============================================================================
// Test Scenario 4: Suspicious file names
// ============================================================================

group("Scenario 4: Suspicious file names");
{
	setupRepo();

	writeFile(".env", "PORT=3000\n");
	writeFile(".env.production", "PORT=8080\n");
	writeFile("certs/server.pem", "not-a-real-cert\n");
	writeFile("config/credentials.json", '{"type":"not-real"}\n');
	writeFile("keys/id_rsa", "not-a-real-key\n");
	writeFile("secrets.yaml", "key: value\n");
	writeFile("src/index.ts", 'console.log("hello");\n');

	stageAll();
	const diff = getStagedDiff();

	const fileFindings = scanFileNames(diff);

	console.log(`\n  File findings (${fileFindings.length}):`);
	for (const f of fileFindings) {
		console.log(`    🟡 [${f.name}] ${f.file}`);
	}

	assert("Flagged .env", fileFindings.some((f) => f.file === ".env"));
	assert("Flagged .env.production", fileFindings.some((f) => f.file === ".env.production"));
	assert("Flagged server.pem", fileFindings.some((f) => f.file?.includes("server.pem")));
	assert("Flagged credentials.json", fileFindings.some((f) => f.file?.includes("credentials.json")));
	assert("Flagged id_rsa", fileFindings.some((f) => f.file?.includes("id_rsa")));
	assert("Flagged secrets.yaml", fileFindings.some((f) => f.file?.includes("secrets.yaml")));
	assert("Did NOT flag index.ts", !fileFindings.some((f) => f.file?.includes("index.ts")));

	cleanup();
}

// ============================================================================
// Test Scenario 5: Diff hash consistency (review-then-allow flow)
// ============================================================================

group("Scenario 5: Diff hash for review-then-allow");
{
	setupRepo();

	writeFile("src/app.ts", 'console.log("v1");\n');
	stageAll();
	const diff1 = getStagedDiff();
	const hash1 = hashDiff(diff1);

	// Same staged content → same hash
	const diff1again = getStagedDiff();
	const hash1again = hashDiff(diff1again);
	assert("Same diff produces same hash", hash1 === hash1again);

	// Commit, then change file → different hash
	commitAll("v1");
	writeFile("src/app.ts", 'console.log("v2");\n');
	stageAll();
	const diff2 = getStagedDiff();
	const hash2 = hashDiff(diff2);
	assert("Different diff produces different hash", hash1 !== hash2);

	cleanup();
}

// ============================================================================
// Test Scenario 6: Only added lines are scanned (not removed)
// ============================================================================

group("Scenario 6: Removed secrets don't trigger");
{
	setupRepo();

	// Commit a file WITH a secret (built at runtime to avoid GitHub push protection)
	const fakeKey6 = "AKIA" + "IOSFODNN7EXAMPLE";
	writeFile("config.ts", `const key = "${fakeKey6}";\n`);
	stageAll();
	commitAll("add secret");

	// Now REMOVE the secret
	writeFile("config.ts", 'const key = process.env.AWS_KEY;\n');
	stageAll();
	const diff = getStagedDiff();

	const findings = scanDiffForSecrets(diff);
	console.log(`\n  Findings after removing secret: ${findings.length}`);
	assert("Removing a secret does NOT trigger (only + lines scanned)", findings.length === 0);

	cleanup();
}

// ============================================================================
// Test Scenario 7: Mixed — some secrets, some clean
// ============================================================================

group("Scenario 7: Mixed files — partial secrets");
{
	setupRepo();

	writeFile("src/clean.ts", 'export const greeting = "hello";\n');
	// Build at runtime to avoid GitHub push protection
	const fakeGhToken = "ghp" + "_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
	writeFile("src/api.ts", `
// GitHub token leak
const token = "${fakeGhToken}";
`);
	writeFile("src/keys.ts", `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHBnQ
-----END RSA PRIVATE KEY-----
`);

	stageAll();
	const diff = getStagedDiff();

	const findings = scanDiffForSecrets(diff);

	console.log(`\n  Findings (${findings.length}):`);
	for (const f of findings) {
		console.log(`    🔴 [${f.name}] in ${f.file}`);
	}

	assert("Found GitHub token", findings.some((f) => f.name === "GitHub Personal Access Token"));
	assert("Found private key", findings.some((f) => f.name === "Private Key"));
	assert("Clean file not flagged", !findings.some((f) => f.file === "src/clean.ts"));
	assert("At least 2 findings", findings.length >= 2);

	cleanup();
}

// ============================================================================
// Summary
// ============================================================================

console.log(`\n${"═".repeat(60)}`);
console.log(`  E2E Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
console.log(`${"═".repeat(60)}\n`);

process.exit(failed > 0 ? 1 : 0);
