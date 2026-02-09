import type { KeyFinding } from "@shared/schema";

/**
 * Calculate Shannon entropy of a string.
 * Higher entropy indicates more randomness (likely a secret/key).
 */
export function calculateShannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq: Map<string, number> = new Map();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of Array.from(freq.values())) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

// Keywords that commonly appear near secrets in source code
const SECRET_KEYWORDS = [
  "key",
  "secret",
  "token",
  "password",
  "passwd",
  "pwd",
  "credential",
  "apikey",
  "api_key",
  "api-key",
  "auth",
  "access_key",
  "private_key",
  "signing_key",
  "encryption_key",
  "client_secret",
  "app_secret",
  "session_secret",
];

// Assignment pattern: keyword followed by = or : and a quoted or unquoted value
// Matches patterns like:
//   key = "value"
//   secret: 'value'
//   token = "value"
//   PASSWORD: "value"
//   API_KEY="value"
const ASSIGNMENT_PATTERN = new RegExp(
  `(?:^|[\\s,;({])(?:${SECRET_KEYWORDS.map(k => k.replace(/[_-]/g, "[_\\-]?")).join("|")})` +
  `[\\w]*\\s*[:=]\\s*["'\`]([^"'\`\\s]{8,})["'\`]`,
  "gim"
);

// Environment variable pattern for .env files: KEY=value (no spaces around =)
const ENV_VAR_PATTERN = new RegExp(
  `^(?:[A-Z_]*(?:${SECRET_KEYWORDS.map(k => k.toUpperCase().replace(/[_-]/g, "[_\\-]?")).join("|")})[A-Z_]*)` +
  `=["']?([^"'\\s]{8,})["']?\\s*$`,
  "gim"
);

// Common placeholder / test values that should be excluded
const PLACEHOLDER_PATTERNS = [
  /^(test|example|demo|sample|placeholder|dummy|fake|mock|temp|tmp)/i,
  /^(your[_-]|my[_-]|change[_-]?me|replace[_-]?me|insert[_-]?here)/i,
  /^(TODO|FIXME|HACK|XXX|CHANGEME)/i,
  /^x{3,}$/i,
  /^\*+$/,
  /^\.{3,}$/,
  /^0+$/,
  /^1+$/,
  /^(abcdef|123456|qwerty)/i,
];

// Known constant literals to exclude
const KNOWN_CONSTANTS = new Set([
  "true",
  "false",
  "null",
  "undefined",
  "none",
  "nil",
  "nan",
  "infinity",
]);

/**
 * Check if a value string is a common false positive.
 * Returns true if the value should be filtered out.
 */
function isFalsePositive(value: string): boolean {
  // Paths
  if (/^\.{0,2}\//.test(value)) return true;

  // URLs without embedded credentials
  if (/^https?:\/\//i.test(value)) {
    // Allow URLs that contain credentials (user:pass@host)
    if (/@/.test(value) && /:.*@/.test(value)) return false;
    return true;
  }

  // CSS / HTML fragments
  if (/[{}<>;]/.test(value)) return true;

  // All lowercase letters only (likely a regular word, not a secret)
  if (/^[a-z]+$/.test(value)) return true;

  // Import / require paths
  if (/^(@[a-z]|[a-z])[a-z0-9_\-/]*$/i.test(value) && value.includes("/")) return true;

  // Known constant literals
  if (KNOWN_CONSTANTS.has(value.toLowerCase())) return true;

  // Placeholder patterns
  for (const pattern of PLACEHOLDER_PATTERNS) {
    if (pattern.test(value)) return true;
  }

  // Template variable references like ${VAR} or $VAR or %ENV%
  if (/^\$\{[^}]+\}$/.test(value)) return true;
  if (/^\$[A-Z_]+$/i.test(value)) return true;
  if (/^%[A-Z_]+%$/i.test(value)) return true;

  return false;
}

/**
 * Determine severity based on entropy value.
 */
function getSeverity(entropy: number): "high" | "medium" {
  return entropy >= 5.0 ? "high" : "medium";
}

/**
 * Check whether a string meets the entropy threshold for its length.
 */
function meetsEntropyThreshold(value: string, entropy: number): boolean {
  if (value.length >= 12 && entropy >= 4.0) return true;
  if (value.length >= 8 && value.length <= 11 && entropy >= 4.5) return true;
  return false;
}

/**
 * Detect high-entropy strings in content that appear near secret-related keywords.
 * This catches secrets that don't match any known regex pattern.
 */
export function detectHighEntropyStrings(content: string, filename: string): KeyFinding[] {
  const findings: KeyFinding[] = [];
  const seen = new Set<string>();
  const lines = content.split("\n");

  // Helper to compute line number from a match index in the full content
  function getLineNumber(matchIndex: number): number {
    const before = content.substring(0, matchIndex);
    return before.split("\n").length;
  }

  // Process assignment patterns (key = "value", secret: 'value', etc.)
  const assignmentRegex = new RegExp(ASSIGNMENT_PATTERN.source, ASSIGNMENT_PATTERN.flags);
  let match: RegExpExecArray | null;

  while ((match = assignmentRegex.exec(content)) !== null) {
    const value = match[1];
    if (!value || value.length < 8) continue;

    // Strip trailing punctuation that may have been captured
    const cleanValue = value.replace(/[,;)\]}]+$/, "");
    if (cleanValue.length < 8) continue;

    if (isFalsePositive(cleanValue)) continue;
    if (seen.has(cleanValue)) continue;

    const entropy = calculateShannonEntropy(cleanValue);
    if (!meetsEntropyThreshold(cleanValue, entropy)) continue;

    seen.add(cleanValue);
    const lineNum = getLineNumber(match.index);

    findings.push({
      keyType: `High Entropy String (entropy: ${entropy.toFixed(2)})`,
      value: cleanValue,
      file: filename,
      line: lineNum,
      severity: getSeverity(entropy),
    });
  }

  // Process .env-style patterns (ENV_VAR=value)
  const envRegex = new RegExp(ENV_VAR_PATTERN.source, ENV_VAR_PATTERN.flags);

  while ((match = envRegex.exec(content)) !== null) {
    const value = match[1];
    if (!value || value.length < 8) continue;

    const cleanValue = value.replace(/[,;)\]}]+$/, "");
    if (cleanValue.length < 8) continue;

    if (isFalsePositive(cleanValue)) continue;
    if (seen.has(cleanValue)) continue;

    const entropy = calculateShannonEntropy(cleanValue);
    if (!meetsEntropyThreshold(cleanValue, entropy)) continue;

    seen.add(cleanValue);
    const lineNum = getLineNumber(match.index);

    findings.push({
      keyType: `High Entropy String (entropy: ${entropy.toFixed(2)})`,
      value: cleanValue,
      file: filename,
      line: lineNum,
      severity: getSeverity(entropy),
    });
  }

  return findings;
}
