/**
 * Sensitive Path Probing
 *
 * Probes well-known paths that commonly leak secrets or sensitive
 * configuration on web servers.  A 200 response means the path is
 * publicly accessible (a finding); a 403 means it exists but is
 * access-restricted (medium finding).  The text content of accessible
 * resources is collected for downstream secret-pattern scanning.
 */

const USER_AGENT = "Mozilla/5.0 (compatible; KeyGuard-Scanner/1.0)";
const PER_REQUEST_TIMEOUT_MS = 5_000;
const TOTAL_TIMEOUT_MS = 30_000;
const BATCH_SIZE = 10;
const CONTENT_SNIPPET_LENGTH = 200;

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

export interface SensitivePathFinding {
  path: string;
  url: string;
  statusCode: number;
  contentType: string;
  contentLength: number;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  description: string;
  contentSnippet?: string;
}

export interface SensitivePathResult {
  pathsChecked: number;
  pathsFound: SensitivePathFinding[];
  contentForScanning: Array<{ path: string; content: string }>;
}

// ---------------------------------------------------------------------------
// Path definitions
// ---------------------------------------------------------------------------

interface PathEntry {
  path: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  description: string;
}

const SENSITIVE_PATHS: PathEntry[] = [
  // ---- Environment Files (critical) ----
  { path: "/.env", severity: "critical", category: "Environment File", description: "Main environment file – often contains database credentials, API keys, and secrets" },
  { path: "/.env.local", severity: "critical", category: "Environment File", description: "Local environment overrides – may contain developer-specific secrets" },
  { path: "/.env.production", severity: "critical", category: "Environment File", description: "Production environment file – contains live secrets and API keys" },
  { path: "/.env.staging", severity: "critical", category: "Environment File", description: "Staging environment file – may contain near-production secrets" },
  { path: "/.env.development", severity: "critical", category: "Environment File", description: "Development environment file – may contain development API keys" },
  { path: "/.env.backup", severity: "critical", category: "Environment File", description: "Backup of environment file – likely contains secrets" },
  { path: "/.env.old", severity: "critical", category: "Environment File", description: "Old environment file – may contain previously valid secrets" },
  { path: "/.env.save", severity: "critical", category: "Environment File", description: "Saved copy of environment file – likely contains secrets" },
  { path: "/.env.bak", severity: "critical", category: "Environment File", description: "Backup of environment file – likely contains secrets" },
  { path: "/.env.example", severity: "medium", category: "Environment File", description: "Example environment file – may reveal expected variable names and structure" },
  { path: "/.env.sample", severity: "medium", category: "Environment File", description: "Sample environment file – may reveal expected variable names and structure" },

  // ---- Version Control (critical) ----
  { path: "/.git/config", severity: "critical", category: "Version Control", description: "Git configuration – exposes repository remotes and may contain credentials" },
  { path: "/.git/HEAD", severity: "critical", category: "Version Control", description: "Git HEAD reference – confirms .git directory is exposed, enabling full repo download" },
  { path: "/.gitignore", severity: "medium", category: "Version Control", description: "Git ignore rules – reveals project structure and sensitive file names" },
  { path: "/.svn/entries", severity: "critical", category: "Version Control", description: "Subversion entries – exposes repository metadata and file listing" },
  { path: "/.svn/wc.db", severity: "critical", category: "Version Control", description: "Subversion working copy database – may contain full source tree metadata" },
  { path: "/.hg/hgrc", severity: "critical", category: "Version Control", description: "Mercurial configuration – may contain repository credentials" },

  // ---- Config Files (high) ----
  { path: "/config.js", severity: "high", category: "Config File", description: "JavaScript configuration – may contain API keys and service credentials" },
  { path: "/config.json", severity: "high", category: "Config File", description: "JSON configuration – may contain API keys and service credentials" },
  { path: "/config.yml", severity: "high", category: "Config File", description: "YAML configuration – may contain API keys and service credentials" },
  { path: "/config.yaml", severity: "high", category: "Config File", description: "YAML configuration – may contain API keys and service credentials" },
  { path: "/config.php", severity: "high", category: "Config File", description: "PHP configuration – may contain database credentials and API keys" },
  { path: "/config.xml", severity: "high", category: "Config File", description: "XML configuration – may contain service credentials" },
  { path: "/configuration.php", severity: "high", category: "Config File", description: "Joomla configuration – typically contains database credentials" },
  { path: "/settings.py", severity: "high", category: "Config File", description: "Django settings – may contain SECRET_KEY and database credentials" },
  { path: "/settings.json", severity: "high", category: "Config File", description: "JSON settings – may contain API keys and service credentials" },
  { path: "/secrets.json", severity: "high", category: "Config File", description: "Secrets file – explicitly named to hold sensitive credentials" },
  { path: "/secrets.yml", severity: "high", category: "Config File", description: "Secrets file – explicitly named to hold sensitive credentials" },
  { path: "/credentials.json", severity: "high", category: "Config File", description: "Credentials file – contains authentication credentials" },
  { path: "/serviceAccountKey.json", severity: "high", category: "Config File", description: "Google Cloud service account key – grants API access" },
  { path: "/firebase-config.js", severity: "high", category: "Config File", description: "Firebase client configuration – may expose API keys" },
  { path: "/firebase-config.json", severity: "high", category: "Config File", description: "Firebase configuration – may expose API keys" },
  { path: "/wp-config.php", severity: "high", category: "Config File", description: "WordPress configuration – contains database credentials and auth keys" },
  { path: "/wp-config.php.bak", severity: "high", category: "Config File", description: "WordPress config backup – raw PHP with database credentials" },
  { path: "/web.config", severity: "high", category: "Config File", description: "IIS/ASP.NET configuration – may contain connection strings and secrets" },
  { path: "/application.yml", severity: "high", category: "Config File", description: "Spring Boot configuration – may contain database and service credentials" },
  { path: "/application.properties", severity: "high", category: "Config File", description: "Spring Boot properties – may contain database and service credentials" },
  { path: "/appsettings.json", severity: "high", category: "Config File", description: ".NET application settings – may contain connection strings and API keys" },
  { path: "/appsettings.Development.json", severity: "high", category: "Config File", description: ".NET development settings – may contain development credentials" },

  // ---- Debug / Info (high) ----
  { path: "/phpinfo.php", severity: "high", category: "Debug Info", description: "PHP info page – exposes server configuration, environment variables, and paths" },
  { path: "/info.php", severity: "high", category: "Debug Info", description: "PHP info page – exposes server configuration details" },
  { path: "/debug", severity: "high", category: "Debug Info", description: "Debug endpoint – may expose application internals and stack traces" },
  { path: "/debug.log", severity: "high", category: "Debug Info", description: "Debug log – may contain errors with credentials or internal paths" },
  { path: "/error.log", severity: "high", category: "Debug Info", description: "Error log – may contain stack traces with sensitive information" },
  { path: "/access.log", severity: "high", category: "Debug Info", description: "Access log – may contain query parameters with tokens or API keys" },
  { path: "/server-status", severity: "high", category: "Debug Info", description: "Apache server status – exposes active connections and server internals" },
  { path: "/server-info", severity: "high", category: "Debug Info", description: "Apache server info – exposes module configuration and server details" },
  { path: "/_debug", severity: "high", category: "Debug Info", description: "Debug endpoint – may expose application internals" },
  { path: "/trace", severity: "high", category: "Debug Info", description: "Trace endpoint – may expose request tracing with sensitive headers" },
  { path: "/actuator", severity: "high", category: "Debug Info", description: "Spring Boot Actuator – exposes application health, beans, and environment" },
  { path: "/actuator/env", severity: "high", category: "Debug Info", description: "Spring Boot environment – may expose configuration properties and secrets" },
  { path: "/actuator/health", severity: "medium", category: "Debug Info", description: "Spring Boot health check – reveals running services and connectivity" },
  { path: "/api/debug", severity: "high", category: "Debug Info", description: "API debug endpoint – may expose internal application state" },
  { path: "/__debug__", severity: "high", category: "Debug Info", description: "Debug endpoint – may expose application internals and configuration" },

  // ---- Backup Files (critical) ----
  { path: "/backup.sql", severity: "critical", category: "Backup File", description: "SQL backup – may contain full database dump with user data and credentials" },
  { path: "/dump.sql", severity: "critical", category: "Backup File", description: "SQL dump – may contain full database contents" },
  { path: "/database.sql", severity: "critical", category: "Backup File", description: "Database export – may contain full database contents" },
  { path: "/db.sql", severity: "critical", category: "Backup File", description: "Database export – may contain full database contents" },
  { path: "/data.sql", severity: "critical", category: "Backup File", description: "Data export – may contain sensitive database records" },
  { path: "/backup.zip", severity: "critical", category: "Backup File", description: "Site backup archive – may contain source code, configs, and database" },
  { path: "/backup.tar.gz", severity: "critical", category: "Backup File", description: "Site backup archive – may contain source code, configs, and database" },
  { path: "/site.tar.gz", severity: "critical", category: "Backup File", description: "Site archive – may contain full application source and configuration" },
  { path: "/www.zip", severity: "critical", category: "Backup File", description: "Web root archive – may contain full application source and configuration" },

  // ---- API / Docs (medium) ----
  { path: "/swagger.json", severity: "medium", category: "API Documentation", description: "Swagger/OpenAPI spec – reveals all API endpoints and data models" },
  { path: "/swagger.yaml", severity: "medium", category: "API Documentation", description: "Swagger/OpenAPI spec – reveals all API endpoints and data models" },
  { path: "/openapi.json", severity: "medium", category: "API Documentation", description: "OpenAPI spec – reveals all API endpoints and data models" },
  { path: "/openapi.yaml", severity: "medium", category: "API Documentation", description: "OpenAPI spec – reveals all API endpoints and data models" },
  { path: "/api-docs", severity: "medium", category: "API Documentation", description: "API documentation – reveals endpoint structure and parameters" },
  { path: "/graphql", severity: "medium", category: "API Documentation", description: "GraphQL endpoint – introspection may reveal full schema" },
  { path: "/.well-known/openid-configuration", severity: "medium", category: "API Documentation", description: "OpenID Connect discovery – reveals auth endpoints and configuration" },
  { path: "/v1/api-docs", severity: "medium", category: "API Documentation", description: "Versioned API documentation – reveals endpoint structure" },
  { path: "/v2/api-docs", severity: "medium", category: "API Documentation", description: "Versioned API documentation – reveals endpoint structure" },

  // ---- Cloud / CI Config (high) ----
  { path: "/.aws/credentials", severity: "high", category: "Cloud Config", description: "AWS credentials file – contains access keys and secret keys" },
  { path: "/.docker/config.json", severity: "high", category: "Cloud Config", description: "Docker config – may contain registry authentication tokens" },
  { path: "/.npmrc", severity: "high", category: "Cloud Config", description: "npm configuration – may contain registry auth tokens" },
  { path: "/.pypirc", severity: "high", category: "Cloud Config", description: "PyPI configuration – may contain upload credentials" },
  { path: "/.gem/credentials", severity: "high", category: "Cloud Config", description: "RubyGems credentials – contains API key for publishing gems" },
  { path: "/.ssh/id_rsa", severity: "high", category: "Cloud Config", description: "SSH private key – grants server access" },
  { path: "/.ssh/id_rsa.pub", severity: "medium", category: "Cloud Config", description: "SSH public key – reveals identity and may aid targeted attacks" },
  { path: "/docker-compose.yml", severity: "high", category: "Cloud Config", description: "Docker Compose – may contain environment variables with secrets" },
  { path: "/docker-compose.yaml", severity: "high", category: "Cloud Config", description: "Docker Compose – may contain environment variables with secrets" },
  { path: "/Dockerfile", severity: "high", category: "Cloud Config", description: "Dockerfile – may contain build-time secrets or internal URLs" },
  { path: "/.circleci/config.yml", severity: "high", category: "Cloud Config", description: "CircleCI config – may reference secret variable names and deployment details" },
  { path: "/.github/workflows", severity: "high", category: "Cloud Config", description: "GitHub Actions workflows – may contain secret references and deployment steps" },
  { path: "/.travis.yml", severity: "high", category: "Cloud Config", description: "Travis CI config – may contain encrypted secrets or deployment credentials" },
  { path: "/Jenkinsfile", severity: "high", category: "Cloud Config", description: "Jenkins pipeline – may reference credentials and deployment targets" },
  { path: "/.gitlab-ci.yml", severity: "high", category: "Cloud Config", description: "GitLab CI config – may contain secret variable references and deploy keys" },

  // ---- Other (medium) ----
  { path: "/.DS_Store", severity: "medium", category: "Other", description: "macOS directory metadata – reveals file and folder names on the server" },
  { path: "/thumbs.db", severity: "medium", category: "Other", description: "Windows thumbnail cache – reveals file names and image previews" },
  { path: "/.htaccess", severity: "medium", category: "Other", description: "Apache configuration – reveals rewrite rules and access controls" },
  { path: "/.htpasswd", severity: "high", category: "Other", description: "Apache password file – contains usernames and hashed passwords" },
  { path: "/crossdomain.xml", severity: "medium", category: "Other", description: "Flash cross-domain policy – may allow unauthorized cross-origin access" },
  { path: "/robots.txt", severity: "low", category: "Other", description: "Robots exclusion – may reveal hidden paths and admin areas" },
  { path: "/sitemap.xml", severity: "low", category: "Other", description: "Sitemap – reveals site structure and all indexed pages" },
  { path: "/package.json", severity: "medium", category: "Other", description: "Node.js manifest – reveals dependencies, scripts, and project structure" },
  { path: "/composer.json", severity: "medium", category: "Other", description: "PHP Composer manifest – reveals dependencies and autoload paths" },
  { path: "/Gemfile", severity: "medium", category: "Other", description: "Ruby Gemfile – reveals dependencies and source repositories" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Fetch with a per-request timeout and the scanner User-Agent header.
 * Does NOT follow redirects to external domains.
 */
async function fetchWithTimeout(
  url: string,
  timeoutMs: number = PER_REQUEST_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.8",
      },
      signal: controller.signal,
      redirect: "manual", // we handle redirects ourselves
    });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Run an array of async functions in batches.
 */
async function batchRun<T>(
  tasks: Array<() => Promise<T>>,
  size: number,
): Promise<Array<PromiseSettledResult<T>>> {
  const results: Array<PromiseSettledResult<T>> = [];

  for (let i = 0; i < tasks.length; i += size) {
    const batch = tasks.slice(i, i + size);
    const settled = await Promise.allSettled(batch.map((fn) => fn()));
    results.push(...settled);
  }

  return results;
}

/**
 * Determine whether a Content-Type header indicates text content.
 */
function isTextContent(contentType: string): boolean {
  const textIndicators = [
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-javascript",
    "application/yaml",
    "application/x-yaml",
    "application/toml",
    "application/x-httpd-php",
    "application/xhtml",
  ];
  const lower = contentType.toLowerCase();
  return textIndicators.some((indicator) => lower.includes(indicator));
}

/**
 * Redact anything that looks like a secret key or password from a text
 * snippet, so that the contentSnippet field never leaks real credentials.
 */
function redactSecrets(text: string): string {
  let redacted = text;

  // Redact patterns that look like key=value with sensitive key names
  redacted = redacted.replace(
    /(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|api[_-]?secret|access[_-]?key|private[_-]?key|auth[_-]?token|bearer)\s*[=:]\s*\S+/gi,
    (match) => {
      const separatorIdx = match.search(/[=:]/);
      if (separatorIdx === -1) return "[REDACTED]";
      return match.substring(0, separatorIdx + 1) + " [REDACTED]";
    },
  );

  // Redact strings that look like API keys (long alphanumeric with dashes/underscores)
  redacted = redacted.replace(
    /(?:sk[_-]live|sk[_-]test|pk[_-]live|pk[_-]test|ghp_|github_pat_|gho_|xoxb-|xoxp-|SG\.|key-|shpat_|shpss_|dop_v1_|npm_|pypi-|AIza)[A-Za-z0-9_\-/.+=]{8,}/g,
    "[REDACTED]",
  );

  // Redact AWS-style keys
  redacted = redacted.replace(
    /(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    "[REDACTED]",
  );

  // Redact anything that looks like a connection string with credentials
  redacted = redacted.replace(
    /(?:mongodb\+srv|mongodb|postgres|postgresql|mysql|redis):\/\/[^\s"'`<>]+:[^\s"'`<>]+@[^\s"'`<>]+/g,
    (match) => {
      const protocol = match.split("://")[0];
      return protocol + "://[REDACTED]";
    },
  );

  // Redact base64-encoded strings that are suspiciously long (likely tokens)
  redacted = redacted.replace(
    /eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/g,
    "[REDACTED]",
  );

  // Redact private key blocks
  redacted = redacted.replace(
    /-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----/g,
    "[REDACTED]",
  );

  return redacted;
}

/**
 * Check if a redirect is to an external domain.
 */
function isExternalRedirect(originalUrl: string, locationHeader: string): boolean {
  try {
    const original = new URL(originalUrl);
    const redirect = new URL(locationHeader, originalUrl);
    return original.hostname !== redirect.hostname;
  } catch {
    return true; // treat unparseable URLs as external
  }
}

// ---------------------------------------------------------------------------
// Core probing logic
// ---------------------------------------------------------------------------

interface ProbeResult {
  finding: SensitivePathFinding | null;
  scanContent: { path: string; content: string } | null;
}

/**
 * Probe a single path entry against the target.
 */
async function probePath(
  baseUrl: string,
  entry: PathEntry,
): Promise<ProbeResult> {
  const url = new URL(entry.path, baseUrl).href;

  try {
    const response = await fetchWithTimeout(url);
    const statusCode = response.status;

    // Skip uninteresting responses
    if (statusCode === 404 || statusCode >= 500) {
      return { finding: null, scanContent: null };
    }

    // Handle redirects
    if (statusCode === 301 || statusCode === 302) {
      const location = response.headers.get("location") || "";
      const external = isExternalRedirect(url, location);
      const description = external
        ? `${entry.description} (redirects to external domain)`
        : `${entry.description} (redirects to ${location})`;

      return {
        finding: {
          path: entry.path,
          url,
          statusCode,
          contentType: response.headers.get("content-type") || "",
          contentLength: 0,
          severity: "low",
          category: entry.category,
          description,
        },
        scanContent: null,
      };
    }

    // 403 – exists but protected
    if (statusCode === 403) {
      return {
        finding: {
          path: entry.path,
          url,
          statusCode,
          contentType: response.headers.get("content-type") || "",
          contentLength: 0,
          severity: "medium",
          category: entry.category,
          description: `${entry.description} (exists but access is forbidden)`,
        },
        scanContent: null,
      };
    }

    // 200 – accessible!
    if (statusCode === 200) {
      const contentType = response.headers.get("content-type") || "";
      let bodyText: string | null = null;
      let contentLength = parseInt(
        response.headers.get("content-length") || "0",
        10,
      );
      let snippet: string | undefined;
      let scannable: { path: string; content: string } | null = null;

      if (isTextContent(contentType)) {
        bodyText = await response.text();
        contentLength = contentLength || new TextEncoder().encode(bodyText).byteLength;

        // Build a safe snippet
        const rawSnippet = bodyText.substring(0, CONTENT_SNIPPET_LENGTH);
        snippet = redactSecrets(rawSnippet);

        // Collect for downstream secret scanning
        scannable = { path: url, content: bodyText };
      } else {
        // Binary content – note the finding but do not scan contents
        contentLength = contentLength || 0;
      }

      return {
        finding: {
          path: entry.path,
          url,
          statusCode,
          contentType,
          contentLength,
          severity: entry.severity,
          category: entry.category,
          description: entry.description,
          contentSnippet: snippet,
        },
        scanContent: scannable,
      };
    }

    // Any other status – skip
    return { finding: null, scanContent: null };
  } catch {
    // Network error or timeout – skip
    return { finding: null, scanContent: null };
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Probe a target URL for well-known sensitive paths.
 *
 * @param baseUrl - The base URL of the site to probe (e.g. "https://example.com").
 * @returns A result object with discovered findings and text content for
 *          downstream secret-pattern scanning.
 */
export async function probeSensitivePaths(
  baseUrl: string,
): Promise<SensitivePathResult> {
  // Ensure baseUrl has a trailing structure we can resolve against
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";

  const findings: SensitivePathFinding[] = [];
  const contentForScanning: Array<{ path: string; content: string }> = [];

  // Create tasks for every path entry
  const tasks = SENSITIVE_PATHS.map(
    (entry) => () => probePath(normalizedBase, entry),
  );

  // Enforce total timeout by racing against a deadline
  const deadline = Date.now() + TOTAL_TIMEOUT_MS;

  // Process in batches, stopping if we exceed the total timeout
  let completed = 0;

  for (let i = 0; i < tasks.length; i += BATCH_SIZE) {
    if (Date.now() >= deadline) break;

    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) break;

    const batch = tasks.slice(i, i + BATCH_SIZE);

    const batchPromise = Promise.allSettled(batch.map((fn) => fn()));
    const timeoutPromise = new Promise<"timeout">((resolve) =>
      setTimeout(() => resolve("timeout"), remainingMs),
    );

    const result = await Promise.race([batchPromise, timeoutPromise]);

    if (result === "timeout") {
      // Total timeout reached mid-batch
      completed += i;
      break;
    }

    for (const settled of result) {
      if (settled.status === "fulfilled") {
        const { finding, scanContent } = settled.value;
        if (finding) findings.push(finding);
        if (scanContent) contentForScanning.push(scanContent);
      }
    }

    completed = i + batch.length;
  }

  // Sort findings: critical first, then by category
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };
  findings.sort((a, b) => {
    const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.category.localeCompare(b.category);
  });

  return {
    pathsChecked: Math.min(completed, SENSITIVE_PATHS.length),
    pathsFound: findings,
    contentForScanning,
  };
}
