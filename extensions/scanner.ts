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

const ENV_PREFIX_RE = "(?:[A-Za-z_][A-Za-z0-9_]*=(?:[^\\s'\";|&]+|'[^']*'|\"[^\"]*\")\\s+)*";
const SHELL_WRAPPER_RE = "(?:bash|sh|zsh|fish|dash|ash|csh|tcsh)\\s+-(?:c|e)\\s+";
const GIT_COMMIT_SEGMENT_RE = new RegExp(`^\\s*${ENV_PREFIX_RE}(?:${SHELL_WRAPPER_RE})?git\\s+.*\\bcommit\\b`);
const GIT_PUSH_SEGMENT_RE = new RegExp(`^\\s*${ENV_PREFIX_RE}(?:${SHELL_WRAPPER_RE})?git\\s+.*\\bpush\\b`);
const GIT_COMMIT_ALL_SEGMENT_RE = new RegExp(
	`^\\s*${ENV_PREFIX_RE}(?:${SHELL_WRAPPER_RE})?git\\s+.*\\bcommit\\b.*(?:-a\\b|--all\\b|-[a-zA-Z]*a[a-zA-Z]*\\b)`,
);
const GIT_ADD_SEGMENT_RE = new RegExp(`^\\s*${ENV_PREFIX_RE}(?:${SHELL_WRAPPER_RE})?git\\s+add\\b`);

function splitShellSegments(command: string): string[] {
	return command
		.split(/(?:&&|\|\||;|\n)/)
		.map((segment) => segment.trim())
		.filter(Boolean);
}

/**
 * Extract files that would be added by git add commands in the command line.
 * Handles patterns like: git add .env, git add ., git add src/*.ts, etc.
 */
function extractGitAddFiles(command: string): string[] {
	const segments = splitShellSegments(command);
	const files: string[] = [];

	for (const segment of segments) {
		// Check if this segment is a git add command
		if (!GIT_ADD_SEGMENT_RE.test(segment)) continue;

		// Extract the inner command if wrapped in shell
		const innerSegment = extractGitFromShellWrapper(segment);

		// Parse the git add command to extract file arguments
		// Match: git add <options> <files...>
		const addMatch = innerSegment.match(/git\s+add\s+(.+)/);
		if (!addMatch) continue;

		const addArgs = addMatch[1];
		// Skip if -u (update) or -A/--all flags are used (we'll use diff instead)
		if (/\s-[uA]|\s--all|\s--update\b/.test(addArgs)) continue;

		// Extract file patterns (everything that's not a flag)
		const filePatternMatch = addArgs.match(/(?:^|\s)([^-\s][^\s]*)/g);
		if (filePatternMatch) {
			for (const pattern of filePatternMatch) {
				const trimmed = pattern.trim();
				// Skip flag values and options
				if (trimmed.startsWith("-")) continue;
				files.push(trimmed);
			}
		}
	}

	return files;
}

/**
 * Extract git command from shell-wrapped commands like `bash -c "git commit ..."`
 */
function extractGitFromShellWrapper(segment: string): string {
	// Match patterns like:
	// - bash -c "git commit ..."
	// - sh -c 'git push ...'
	// - bash -e "git commit -m 'msg'"
	const wrapperMatch = segment.match(/^(?:\S+\s+)+-\s*c\s+['"](.+?)['"]\s*$/);
	if (wrapperMatch) {
		return wrapperMatch[1];
	}
	return segment;
}

export function detectGitAction(command: string): "commit" | "push" | null {
	for (const segment of splitShellSegments(command)) {
		// First try the direct regex match
		if (GIT_COMMIT_SEGMENT_RE.test(segment)) return "commit";
		if (GIT_PUSH_SEGMENT_RE.test(segment)) return "push";

		// Then try extracting git command from shell wrappers
		const extractedSegment = extractGitFromShellWrapper(segment);
		if (extractedSegment !== segment) {
			// Check the extracted command
			if (GIT_COMMIT_SEGMENT_RE.test(extractedSegment)) return "commit";
			if (GIT_PUSH_SEGMENT_RE.test(extractedSegment)) return "push";
		}
	}
	return null;
}

export function isCommitAll(command: string): boolean {
	return splitShellSegments(command).some((segment) => {
		// Direct check
		if (GIT_COMMIT_ALL_SEGMENT_RE.test(segment)) return true;

		// Check shell-wrapped commands
		const extracted = extractGitFromShellWrapper(segment);
		if (extracted !== segment && GIT_COMMIT_ALL_SEGMENT_RE.test(extracted)) return true;

		return false;
	});
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
