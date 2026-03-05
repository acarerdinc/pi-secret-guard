/**
 * Secret scanning engine — patterns, scanning functions, and git command detection.
 * Separated from the extension entry point for testability.
 */

import { createHash } from "node:crypto";

// ============================================================================
// Types
// ============================================================================

export interface SecretPattern {
	name: string;
	pattern: RegExp;
}

export interface Finding {
	type: "secret" | "suspicious-file";
	name: string;
	file?: string;
	line?: number;
	snippet?: string;
}

export interface ReviewState {
	diffHash: string;
	timestamp: number;
}

// ============================================================================
// Secret Patterns — ordered by specificity (most specific first)
// ============================================================================

export const SECRET_PATTERNS: SecretPattern[] = [
	// ── Cloud Providers ──────────────────────────────────────────────────────
	{ name: "AWS Access Key ID", pattern: /\bAKIA[0-9A-Z]{16}\b/ },
	{
		name: "AWS Secret Access Key",
		pattern: /(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/i,
	},
	{
		name: "Azure Connection String",
		pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+/i,
	},
	{ name: "Azure Storage Account Key", pattern: /AccountKey=[A-Za-z0-9+/=]{44,}/i },
	{
		name: "Google Cloud Service Account Key",
		pattern: /"private_key"\s*:\s*"-----BEGIN/,
	},

	// ── API Keys (provider-specific) ─────────────────────────────────────────
	{ name: "Google API Key", pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
	{ name: "OpenAI API Key", pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b/ },
	{ name: "Anthropic API Key", pattern: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/ },
	{ name: "Stripe Secret Key", pattern: /\bsk_(live|test)_[0-9a-zA-Z]{24,}\b/ },
	{ name: "Stripe Publishable Key", pattern: /\bpk_(live|test)_[0-9a-zA-Z]{24,}\b/ },
	{
		name: "SendGrid API Key",
		pattern: /\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b/,
	},
	{ name: "Twilio API Key", pattern: /\bSK[0-9a-fA-F]{32}\b/ },
	{ name: "Slack Token", pattern: /\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b/ },
	{
		name: "Discord Bot Token",
		pattern: /\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b/,
	},
	{ name: "Mailgun API Key", pattern: /\bkey-[0-9a-zA-Z]{32}\b/ },

	// ── Version Control Tokens ───────────────────────────────────────────────
	{ name: "GitHub Personal Access Token", pattern: /\bghp_[A-Za-z0-9_]{36,}\b/ },
	{ name: "GitHub OAuth Token", pattern: /\bgho_[A-Za-z0-9_]{36,}\b/ },
	{ name: "GitHub App Token", pattern: /\b(ghu|ghs)_[A-Za-z0-9_]{36,}\b/ },
	{
		name: "GitHub Fine-grained Token",
		pattern: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/,
	},
	{ name: "GitLab Token", pattern: /\bglpat-[0-9A-Za-z\-_]{20,}\b/ },
	{ name: "Bitbucket App Password", pattern: /\bATBB[A-Za-z0-9]{32,}\b/ },

	// ── Private Keys ─────────────────────────────────────────────────────────
	{
		name: "Private Key",
		pattern:
			/-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY(\s+BLOCK)?-----/,
	},

	// ── JWT ──────────────────────────────────────────────────────────────────
	{
		name: "JWT Token",
		pattern: /\beyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]{10,}\b/,
	},

	// ── Credentials in URLs (specific before generic) ────────────────────────
	{
		name: "Database URL with Credentials",
		pattern: /(?:mongodb|postgres|postgresql|mysql|redis|amqp):\/\/[^:]+:[^@]+@/i,
	},
	{ name: "Credentials in URL", pattern: /[a-zA-Z]+:\/\/[^:\/\s]+:[^@\/\s]{3,}@[^\s]+/ },

	// ── Generic Patterns (broader, checked last) ─────────────────────────────
	{
		name: "Generic API Key Assignment",
		pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9\-_./+=]{20,}['"]?/i,
	},
	{
		name: "Generic Secret Assignment",
		pattern:
			/(?:secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[=:]\s*['"]?[A-Za-z0-9\-_./+=]{20,}['"]?/i,
	},
	{
		name: "Generic Password Assignment",
		pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?/i,
	},
	{
		name: "Generic Token Assignment",
		pattern:
			/(?:auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer)\s*[=:]\s*['"]?[A-Za-z0-9\-_./+=]{20,}['"]?/i,
	},
];

// ============================================================================
// Suspicious File Patterns
// ============================================================================

export const SUSPICIOUS_FILE_PATTERNS: { name: string; pattern: RegExp }[] = [
	{ name: ".env file", pattern: /(?:^|\/)\.env$/ },
	{ name: ".env variant", pattern: /(?:^|\/)\.env\.[a-zA-Z.]+$/ },
	{ name: "PEM certificate/key", pattern: /\.pem$/ },
	{ name: "Private key file", pattern: /\.key$/ },
	{ name: "PKCS#12 keystore", pattern: /\.p12$/ },
	{ name: "PFX certificate", pattern: /\.pfx$/ },
	{ name: "Java keystore", pattern: /\.jks$/ },
	{ name: "SSH private key", pattern: /(?:^|\/)id_(rsa|ed25519|ecdsa|dsa)$/ },
	{ name: "Keystore file", pattern: /\.keystore$/ },
	{ name: "Credentials JSON", pattern: /(?:^|\/)credentials\.json$/ },
	{
		name: "Service account key",
		pattern: /(?:^|\/)service[_-]?account.*\.json$/i,
	},
	{ name: "Secrets file", pattern: /(?:^|\/)secrets?\.(json|ya?ml|toml)$/i },
	{ name: "htpasswd file", pattern: /(?:^|\/)\.htpasswd$/ },
	{ name: "netrc file", pattern: /(?:^|\/)\.netrc$/ },
];

// ============================================================================
// Git Command Detection
// ============================================================================

const GIT_COMMIT_RE = /\bgit\b.*\bcommit\b/;
const GIT_PUSH_RE = /\bgit\b.*\bpush\b/;
const GIT_COMMIT_ALL_RE = /\bgit\b.*\bcommit\b.*(?:-a\b|--all\b|-[a-zA-Z]*a[a-zA-Z]*\b)/;

export function detectGitAction(command: string): "commit" | "push" | null {
	if (GIT_COMMIT_RE.test(command)) return "commit";
	if (GIT_PUSH_RE.test(command)) return "push";
	return null;
}

export function isCommitAll(command: string): boolean {
	return GIT_COMMIT_ALL_RE.test(command);
}

// ============================================================================
// Scanning
// ============================================================================

export function hashDiff(diff: string): string {
	return createHash("sha256").update(diff).digest("hex");
}

/**
 * Scan a git diff for secret patterns. Only checks added lines (starting with +).
 */
export function scanDiffForSecrets(diff: string): Finding[] {
	const findings: Finding[] = [];
	const lines = diff.split("\n");
	let currentFile: string | undefined;

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];

		// Track current file from diff headers
		if (line.startsWith("+++ b/")) {
			currentFile = line.slice(6);
			continue;
		}

		// Only scan added lines (not diff headers)
		if (!line.startsWith("+") || line.startsWith("+++")) continue;

		const addedContent = line.slice(1); // Remove leading +

		for (const { name, pattern } of SECRET_PATTERNS) {
			if (pattern.test(addedContent)) {
				// Mask the matched secret in the snippet
				const masked = addedContent.replace(pattern, `███ ${name} ███`);
				findings.push({
					type: "secret",
					name,
					file: currentFile,
					line: i + 1,
					snippet: masked.trim().slice(0, 120),
				});
				break; // One finding per line is enough
			}
		}
	}

	return findings;
}

/**
 * Check file names in the diff for suspicious patterns (e.g., .env, .pem, id_rsa).
 */
export function scanFileNames(diff: string): Finding[] {
	const findings: Finding[] = [];
	const lines = diff.split("\n");

	for (const line of lines) {
		if (!line.startsWith("+++ b/")) continue;
		const filePath = line.slice(6);

		for (const { name, pattern } of SUSPICIOUS_FILE_PATTERNS) {
			if (pattern.test(filePath)) {
				findings.push({
					type: "suspicious-file",
					name,
					file: filePath,
				});
				break;
			}
		}
	}

	return findings;
}

/**
 * Format findings into a readable string for the block reason.
 */
export function formatFindings(findings: Finding[]): string {
	const secretFindings = findings.filter((f) => f.type === "secret");
	const fileFindings = findings.filter((f) => f.type === "suspicious-file");

	const parts: string[] = [];

	if (secretFindings.length > 0) {
		parts.push("Secret patterns detected:");
		for (const f of secretFindings) {
			parts.push(`  🔴 [${f.name}] in ${f.file || "unknown"}`);
			if (f.snippet) parts.push(`     ${f.snippet}`);
		}
	}

	if (fileFindings.length > 0) {
		parts.push("Suspicious files detected:");
		for (const f of fileFindings) {
			parts.push(`  🟡 [${f.name}] ${f.file}`);
		}
	}

	return parts.join("\n");
}
