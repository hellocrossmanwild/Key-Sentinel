export interface BundleSecret {
  type: string;
  key: string;
  value: string;
  file: string;
  line: number;
  severity: "critical" | "high" | "medium" | "low";
}

export interface BundleAnalysisResult {
  bundlesAnalyzed: number;
  secretsFound: BundleSecret[];
}

// ---------- Helpers ----------

/** Minimum file size (in characters) to consider a file as a JS bundle. */
const MIN_BUNDLE_SIZE = 10_000;

/** Common webpack/rollup/esbuild bundle signatures. */
const BUNDLE_SIGNATURES = [
  /\bwebpackJsonp\b/,
  /\b__webpack_require__\b/,
  /\b__webpack_modules__\b/,
  /\bdefine\(\s*\[/,                   // AMD modules
  /\bObject\.defineProperty\(exports\b/,
  /\bmodule\.exports\s*=/,
  /\b_interopRequireDefault\b/,
  /\b__esModule\b/,
  /\bimport\.meta\b/,
  /\bcreateRequire\b/,
];

/** Returns true if the file looks like a JavaScript bundle worth analyzing. */
function isBundle(path: string, content: string): boolean {
  // Accept any .js file large enough
  if (path.endsWith(".js") && content.length >= MIN_BUNDLE_SIZE) {
    return true;
  }

  // Also accept smaller .js files that contain bundle signatures
  if (path.endsWith(".js")) {
    for (const sig of BUNDLE_SIGNATURES) {
      if (sig.test(content)) return true;
    }
  }

  return false;
}

/** Common placeholder values that are not real secrets. */
const PLACEHOLDER_PATTERNS = [
  /^YOUR[_\-]?API[_\-]?KEY$/i,
  /^REPLACE[_\-]?ME$/i,
  /^INSERT[_\-]?HERE$/i,
  /^CHANGE[_\-]?ME$/i,
  /^TODO$/i,
  /^xxx+$/i,
  /^example/i,
  /^test[_\-]?key/i,
  /^demo/i,
  /^sample/i,
  /^placeholder/i,
  /^dummy/i,
  /^fake/i,
  /^mock/i,
  /^your[_\-]/i,
  /^my[_\-]/i,
  /^sk[_\-]test[_\-]/i,
  /^pk[_\-]test[_\-]/i,
];

function isPlaceholder(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return true;
  for (const pat of PLACEHOLDER_PATTERNS) {
    if (pat.test(trimmed)) return true;
  }
  return false;
}

/** Get the 1-based line number for a character index within content. */
function lineAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === "\n") line++;
  }
  return line;
}

/** Returns true if a value looks like a real API key or token (not a short generic word). */
function looksLikeRealSecret(value: string): boolean {
  if (value.length < 8) return false;
  if (isPlaceholder(value)) return false;
  // Contains mix of character classes typical of secrets
  const hasUpper = /[A-Z]/.test(value);
  const hasLower = /[a-z]/.test(value);
  const hasDigit = /\d/.test(value);
  const hasSpecial = /[_\-+/=]/.test(value);
  const classes = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
  return classes >= 2 || value.length >= 20;
}

// ---------- Detection functions ----------

type Detector = (
  content: string,
  filePath: string
) => BundleSecret[];

/**
 * 1. Detect webpack/Vite environment variable injections where env vars
 *    have been replaced with their actual string values in the bundle.
 */
const detectEnvVarInjection: Detector = (content, filePath) => {
  const secrets: BundleSecret[] = [];
  const seen = new Set<string>();

  // Pattern: "REACT_APP_*":"value" or "NEXT_PUBLIC_*":"value" etc. (JSON-style in bundles)
  const jsonStyleRegex =
    /["']((REACT_APP|NEXT_PUBLIC|VITE|VUE_APP|NUXT)_[A-Z_0-9]+)["']\s*:\s*["']([^"']{1,512})["']/g;

  let match: RegExpExecArray | null;
  while ((match = jsonStyleRegex.exec(content)) !== null) {
    const key = match[1];
    const value = match[3];
    if (isPlaceholder(value) || value === "undefined" || value === "null" || value === "") continue;
    const uid = `env-json:${key}:${value}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Environment Variable",
      key,
      value,
      file: filePath,
      line: lineAt(content, match.index),
      severity: looksLikeRealSecret(value) ? "critical" : "high",
    });
  }

  // Pattern: process.env.REACT_APP_*="value" or = "value"
  const processEnvRegex =
    /process\.env\.((?:REACT_APP|NEXT_PUBLIC|VITE|VUE_APP|NUXT)_[A-Z_0-9]+)\s*=\s*["']([^"']{1,512})["']/g;

  while ((match = processEnvRegex.exec(content)) !== null) {
    const key = match[1];
    const value = match[2];
    if (isPlaceholder(value) || value === "undefined" || value === "null" || value === "") continue;
    const uid = `env-process:${key}:${value}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Environment Variable",
      key,
      value,
      file: filePath,
      line: lineAt(content, match.index),
      severity: looksLikeRealSecret(value) ? "critical" : "high",
    });
  }

  // Pattern: process.env["REACT_APP_*"] replaced with literal strings in bundle
  // e.g., a bundler might output: ("sk-abc123") where process.env.REACT_APP_KEY used to be
  // We look for: process.env.VARNAME being compared or concatenated with a literal
  const processEnvBracketRegex =
    /process\.env\[["']((?:REACT_APP|NEXT_PUBLIC|VITE|VUE_APP|NUXT)_[A-Z_0-9]+)["']\]\s*(?:=|:)\s*["']([^"']{1,512})["']/g;

  while ((match = processEnvBracketRegex.exec(content)) !== null) {
    const key = match[1];
    const value = match[2];
    if (isPlaceholder(value) || value === "undefined" || value === "null" || value === "") continue;
    const uid = `env-bracket:${key}:${value}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Environment Variable",
      key,
      value,
      file: filePath,
      line: lineAt(content, match.index),
      severity: looksLikeRealSecret(value) ? "critical" : "high",
    });
  }

  // Pattern: import.meta.env.VITE_*
  const importMetaRegex =
    /import\.meta\.env\.(VITE_[A-Z_0-9]+)\s*=\s*["']([^"']{1,512})["']/g;

  while ((match = importMetaRegex.exec(content)) !== null) {
    const key = match[1];
    const value = match[2];
    if (isPlaceholder(value) || value === "undefined" || value === "null" || value === "") continue;
    const uid = `env-importmeta:${key}:${value}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Environment Variable",
      key,
      value,
      file: filePath,
      line: lineAt(content, match.index),
      severity: looksLikeRealSecret(value) ? "critical" : "high",
    });
  }

  // Vite-style define replacements: import.meta.env resolved as a JSON object in bundle
  const importMetaJsonRegex =
    /["'](VITE_[A-Z_0-9]+)["']\s*:\s*["']([^"']{1,512})["']/g;

  while ((match = importMetaJsonRegex.exec(content)) !== null) {
    const key = match[1];
    const value = match[2];
    if (isPlaceholder(value) || value === "undefined" || value === "null" || value === "") continue;
    const uid = `env-vite-json:${key}:${value}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Environment Variable",
      key,
      value,
      file: filePath,
      line: lineAt(content, match.index),
      severity: looksLikeRealSecret(value) ? "critical" : "high",
    });
  }

  return secrets;
};

/**
 * 2. Detect hardcoded API base URLs that include tokens in query parameters,
 *    and Authorization headers with Bearer/Basic tokens in fetch/axios calls.
 */
const detectHardcodedURLTokens: Detector = (content, filePath) => {
  const secrets: BundleSecret[] = [];
  const seen = new Set<string>();

  // URLs with token-like query parameters
  const urlTokenRegex =
    /["'](https?:\/\/[^"'\s]{4,}[?&](?:key|token|api_key|apikey|access_token)=([^"'&\s]{8,}))["']/gi;

  let match: RegExpExecArray | null;
  while ((match = urlTokenRegex.exec(content)) !== null) {
    const fullUrl = match[1];
    const tokenValue = match[2];
    if (isPlaceholder(tokenValue)) continue;
    const uid = `url-token:${tokenValue}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "API Endpoint",
      key: "URL with embedded token",
      value: fullUrl.length > 200 ? fullUrl.slice(0, 197) + "..." : fullUrl,
      file: filePath,
      line: lineAt(content, match.index),
      severity: "critical",
    });
  }

  // Authorization headers: Bearer token
  const bearerRegex =
    /["']?[Aa]uthorization["']?\s*:\s*["'`]Bearer\s+([A-Za-z0-9_\-.~+/=]{20,})["'`]/g;

  while ((match = bearerRegex.exec(content)) !== null) {
    const token = match[1];
    if (isPlaceholder(token)) continue;
    const uid = `bearer:${token}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Hardcoded Config",
      key: "Authorization Bearer Token",
      value: token,
      file: filePath,
      line: lineAt(content, match.index),
      severity: "critical",
    });
  }

  // Authorization headers: Basic auth
  const basicRegex =
    /["']?[Aa]uthorization["']?\s*:\s*["'`]Basic\s+([A-Za-z0-9+/=]{8,})["'`]/g;

  while ((match = basicRegex.exec(content)) !== null) {
    const encoded = match[1];
    if (isPlaceholder(encoded)) continue;
    const uid = `basic:${encoded}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Hardcoded Config",
      key: "Authorization Basic Credentials",
      value: encoded,
      file: filePath,
      line: lineAt(content, match.index),
      severity: "critical",
    });
  }

  return secrets;
};

/**
 * 3. Detect debug/development code left in production bundles.
 */
const detectDebugCode: Detector = (content, filePath) => {
  const secrets: BundleSecret[] = [];
  const seen = new Set<string>();

  // console.log with sensitive-looking variable names
  const sensitiveLogRegex =
    /console\.log\s*\([^)]*\b(password|token|secret|key|auth|credential|session)[^)]{0,100}\)/gi;

  let match: RegExpExecArray | null;
  while ((match = sensitiveLogRegex.exec(content)) !== null) {
    const uid = `debug-log:${match.index}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    const snippet = match[0].length > 120 ? match[0].slice(0, 117) + "..." : match[0];
    secrets.push({
      type: "Debug Code",
      key: `console.log referencing "${match[1]}"`,
      value: snippet,
      file: filePath,
      line: lineAt(content, match.index),
      severity: "low",
    });
  }

  // debugger statements
  const debuggerRegex = /\bdebugger\b\s*;?/g;

  while ((match = debuggerRegex.exec(content)) !== null) {
    const uid = `debugger:${match.index}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Debug Code",
      key: "debugger statement",
      value: "debugger",
      file: filePath,
      line: lineAt(content, match.index),
      severity: "low",
    });
  }

  // TODO / HACK / FIXME near sensitive keywords (within 200 chars)
  const todoNearSensitiveRegex =
    /\/\/\s*(TODO|HACK|FIXME)\b[^\n]{0,200}\b(password|token|secret|key|auth|credential)/gi;

  while ((match = todoNearSensitiveRegex.exec(content)) !== null) {
    const uid = `todo-sensitive:${match.index}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    const snippet = match[0].length > 120 ? match[0].slice(0, 117) + "..." : match[0];
    secrets.push({
      type: "Debug Code",
      key: `${match[1]} comment near sensitive code`,
      value: snippet,
      file: filePath,
      line: lineAt(content, match.index),
      severity: "low",
    });
  }

  return secrets;
};

/**
 * 4. Detect Firebase / Supabase / cloud config objects with API keys.
 */
const detectCloudConfigs: Detector = (content, filePath) => {
  const secrets: BundleSecret[] = [];
  const seen = new Set<string>();

  // Firebase-style config: object with apiKey, authDomain, projectId, etc.
  // Look for apiKey near authDomain or projectId (within 500 chars)
  const firebaseRegex =
    /apiKey\s*:\s*["']([^"']{10,})["'][^}]{0,500}(?:authDomain|projectId|storageBucket)\s*:\s*["']([^"']+)["']/g;

  let match: RegExpExecArray | null;
  while ((match = firebaseRegex.exec(content)) !== null) {
    const apiKey = match[1];
    if (isPlaceholder(apiKey)) continue;
    const uid = `firebase:${apiKey}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Hardcoded Config",
      key: "Firebase/Cloud Config apiKey",
      value: apiKey,
      file: filePath,
      line: lineAt(content, match.index),
      severity: "medium",
    });
  }

  // Also catch the reverse order: authDomain before apiKey
  const firebaseReverseRegex =
    /(?:authDomain|projectId|storageBucket)\s*:\s*["'][^"']+["'][^}]{0,500}apiKey\s*:\s*["']([^"']{10,})["']/g;

  while ((match = firebaseReverseRegex.exec(content)) !== null) {
    const apiKey = match[1];
    if (isPlaceholder(apiKey)) continue;
    const uid = `firebase:${apiKey}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Hardcoded Config",
      key: "Firebase/Cloud Config apiKey",
      value: apiKey,
      file: filePath,
      line: lineAt(content, match.index),
      severity: "medium",
    });
  }

  // Supabase config: supabaseUrl + supabaseKey / supabaseAnonKey
  const supabaseRegex =
    /supabase(?:Url|URL)\s*[:=]\s*["']([^"']+)["'][^}]{0,300}(?:supabase(?:Anon)?Key|supabasekey|SUPABASE_KEY)\s*[:=]\s*["']([^"']{10,})["']/gi;

  while ((match = supabaseRegex.exec(content)) !== null) {
    const supabaseKey = match[2];
    if (isPlaceholder(supabaseKey)) continue;
    const uid = `supabase:${supabaseKey}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Hardcoded Config",
      key: "Supabase API Key",
      value: supabaseKey,
      file: filePath,
      line: lineAt(content, match.index),
      severity: "medium",
    });
  }

  return secrets;
};

/**
 * 5. Detect hardcoded credentials -- variables named password, secret, key, token
 *    assigned to string literals.
 */
const detectHardcodedCredentials: Detector = (content, filePath) => {
  const secrets: BundleSecret[] = [];
  const seen = new Set<string>();

  // Variable or property assignments: password = "...", secret: "...", token = '...', etc.
  const credentialRegex =
    /\b([a-zA-Z_$][\w$]*(?:password|secret|key|token|apiKey|api_key|apiSecret|api_secret|auth_token|authToken|accessToken|access_token|privateKey|private_key))\s*[:=]\s*["'`]([^"'`\n]{8,256})["'`]/gi;

  let match: RegExpExecArray | null;
  while ((match = credentialRegex.exec(content)) !== null) {
    const varName = match[1];
    const value = match[2];

    if (isPlaceholder(value)) continue;
    // Skip if the value looks like a template literal expression, URL path, or CSS
    if (/^\$\{/.test(value)) continue;
    if (/^[{<]/.test(value)) continue;
    if (/[;{}]/.test(value)) continue;
    if (/^(use strict|undefined|null|true|false|none|nil|nan|infinity|function|object|string|number|boolean|symbol|bigint|required|optional|default|inherit|initial|unset|enabled|disabled|active|inactive|pending|loading|success|failure|error|warning|unknown|anonymous|localhost|production|development|staging|changeme|password|username|admin1234|administrator)$/i.test(value)) continue;
    if (/^\.{0,2}\//.test(value)) continue;
    if (/^https?:\/\//i.test(value) && !/:.*@/.test(value)) continue;
    if (/^[a-z]+$/.test(value)) continue;
    if (/^[A-Z_]+$/.test(value)) continue;
    if (/^(example|test|demo|sample|placeholder|dummy|fake|mock|temp|your[_-]|my[_-]|replace[_-]?me|insert[_-]?here|change[_-]?me)/i.test(value)) continue;

    const uid = `cred:${varName}:${value}`;
    if (seen.has(uid)) continue;
    seen.add(uid);

    secrets.push({
      type: "Hardcoded Config",
      key: varName,
      value,
      file: filePath,
      line: lineAt(content, match.index),
      severity: looksLikeRealSecret(value) ? "critical" : "high",
    });
  }

  return secrets;
};

// ---------- All detectors ----------

const DETECTORS: Detector[] = [
  detectEnvVarInjection,
  detectHardcodedURLTokens,
  detectDebugCode,
  detectCloudConfigs,
  detectHardcodedCredentials,
];

// ---------- Main analysis function ----------

export function analyzeJSBundles(
  files: Array<{ path: string; content: string }>
): BundleAnalysisResult {
  const allSecrets: BundleSecret[] = [];
  let bundlesAnalyzed = 0;

  for (const file of files) {
    if (!isBundle(file.path, file.content)) continue;
    bundlesAnalyzed++;

    for (const detect of DETECTORS) {
      const found = detect(file.content, file.path);
      allSecrets.push(...found);
    }
  }

  // Sort by severity: critical first, then high, medium, low
  const severityOrder: Record<BundleSecret["severity"], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };
  allSecrets.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return {
    bundlesAnalyzed,
    secretsFound: allSecrets,
  };
}
