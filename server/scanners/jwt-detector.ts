export interface JWTFinding {
  token: string;
  header: Record<string, any>;
  payload: Record<string, any>;
  isExpired: boolean;
  expiresAt?: string;
  issuedAt?: string;
  issuer?: string;
  hasUserData: boolean;
  file: string;
  line: number;
  severity: "critical" | "high" | "medium" | "low";
}

// Regex to match JWT tokens: three base64url-encoded segments separated by dots.
// JWTs always start with "eyJ" (base64url of '{"').
const JWT_REGEX = /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g;

// Fields that indicate user-identifiable data in a JWT payload
const USER_DATA_FIELDS = new Set([
  "email",
  "name",
  "given_name",
  "family_name",
  "preferred_username",
  "username",
  "user_name",
  "user_id",
  "uid",
  "sub",
  "phone",
  "phone_number",
  "address",
  "profile",
  "picture",
  "nickname",
  "first_name",
  "last_name",
]);

// Known public JWT prefixes already caught by regex-based scanners (e.g., Supabase anon keys)
const KNOWN_PUBLIC_JWT_PREFIXES = [
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6",
];

/**
 * Decode a base64url-encoded string.
 * Handles the base64url -> base64 conversion by replacing URL-safe characters
 * and adding padding as needed.
 */
function decodeBase64Url(segment: string): string {
  // Replace base64url-specific characters with standard base64 equivalents
  let base64 = segment.replace(/-/g, "+").replace(/_/g, "/");

  // Add padding if necessary
  const paddingNeeded = (4 - (base64.length % 4)) % 4;
  base64 += "=".repeat(paddingNeeded);

  return Buffer.from(base64, "base64").toString("utf-8");
}

/**
 * Safely decode and parse a JWT segment (header or payload) as JSON.
 * Returns null if decoding or parsing fails.
 */
function decodeJWTSegment(segment: string): Record<string, any> | null {
  try {
    const decoded = decodeBase64Url(segment);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

/**
 * Check whether a JWT payload contains user-identifiable data.
 */
function containsUserData(payload: Record<string, any>): boolean {
  for (const key of Object.keys(payload)) {
    if (USER_DATA_FIELDS.has(key.toLowerCase())) {
      // "sub" is very common and sometimes contains a generic ID rather than
      // user-identifying info, but we still flag it as user data since it
      // typically identifies a specific user/principal.
      return true;
    }
  }
  return false;
}

/**
 * Determine whether a JWT token is a known public key that is already
 * detected by regex pattern scanners (e.g., Supabase anon keys).
 */
function isKnownPublicJWT(token: string): boolean {
  for (const prefix of KNOWN_PUBLIC_JWT_PREFIXES) {
    if (token.startsWith(prefix)) return true;
  }
  return false;
}

/**
 * Determine severity based on user data presence and expiration status.
 *
 * - "critical": contains user data AND is not expired (or no expiry set)
 * - "high":     contains user data but is expired
 * - "medium":   no user data but is not expired (or no expiry set)
 * - "low":      expired and no user data
 */
function determineSeverity(
  hasUserData: boolean,
  isExpired: boolean
): "critical" | "high" | "medium" | "low" {
  if (hasUserData && !isExpired) return "critical";
  if (hasUserData && isExpired) return "high";
  if (!hasUserData && !isExpired) return "medium";
  return "low";
}

/**
 * Mask a JWT token for safe display.
 * Shows the first 20 characters and last 10, masking the middle.
 */
function maskToken(token: string): string {
  if (token.length <= 40) {
    return token.substring(0, 10) + "..." + token.substring(token.length - 5);
  }
  return token.substring(0, 20) + "..." + token.substring(token.length - 10);
}

/**
 * Compute the line number for a given character index within the content string.
 */
function getLineNumber(content: string, matchIndex: number): number {
  const before = content.substring(0, matchIndex);
  return before.split("\n").length;
}

/**
 * Detect JWT tokens in content, decode their headers and payloads,
 * and return structured findings with severity ratings.
 */
export function detectJWTTokens(content: string, filename: string): JWTFinding[] {
  const findings: JWTFinding[] = [];
  const seen = new Set<string>();

  const regex = new RegExp(JWT_REGEX.source, JWT_REGEX.flags);
  let match: RegExpExecArray | null;

  while ((match = regex.exec(content)) !== null) {
    const token = match[1];

    // Skip duplicates
    if (seen.has(token)) continue;
    seen.add(token);

    // Skip known public JWTs already caught by pattern scanners
    if (isKnownPublicJWT(token)) continue;

    // Split token into segments
    const segments = token.split(".");
    if (segments.length !== 3) continue;

    const [headerSegment, payloadSegment] = segments;

    // Attempt to decode header and payload
    try {
      const header = decodeJWTSegment(headerSegment);
      const payload = decodeJWTSegment(payloadSegment);

      // Skip tokens that fail to decode as valid JSON
      if (!header || !payload) continue;

      // Check expiration
      let isExpired = false;
      let expiresAt: string | undefined;
      if (typeof payload.exp === "number") {
        const expDate = new Date(payload.exp * 1000);
        expiresAt = expDate.toISOString();
        isExpired = expDate.getTime() < Date.now();
      }

      // Check issued-at time
      let issuedAt: string | undefined;
      if (typeof payload.iat === "number") {
        issuedAt = new Date(payload.iat * 1000).toISOString();
      }

      // Extract issuer
      const issuer = typeof payload.iss === "string" ? payload.iss : undefined;

      // Check for user data
      const hasUserData = containsUserData(payload);

      // Determine severity
      const severity = determineSeverity(hasUserData, isExpired);

      // Compute line number
      const line = getLineNumber(content, match.index);

      findings.push({
        token: maskToken(token),
        header,
        payload,
        isExpired,
        expiresAt,
        issuedAt,
        issuer,
        hasUserData,
        file: filename,
        line,
        severity,
      });
    } catch {
      // Skip tokens that cause any decoding error
      continue;
    }
  }

  return findings;
}
