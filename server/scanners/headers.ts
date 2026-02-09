export interface HeaderFinding {
  header: string;
  value?: string;
  status: "missing" | "present" | "insecure";
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  recommendation: string;
}

export interface HeaderAnalysisResult {
  url: string;
  statusCode: number;
  serverInfo?: string;
  findings: HeaderFinding[];
  score: number;
}

// ---------- Security headers that SHOULD be present ----------

interface ExpectedHeader {
  name: string;
  severity: HeaderFinding["severity"];
  category: string;
  description: string;
  recommendation: string;
  /** Optional validator: if the header IS present, check whether the value is acceptable. */
  validate?: (value: string) => string | null; // returns issue description or null if OK
}

const EXPECTED_HEADERS: ExpectedHeader[] = [
  {
    name: "strict-transport-security",
    severity: "high",
    category: "Security",
    description:
      "HTTP Strict-Transport-Security (HSTS) header is missing. Browsers will not enforce HTTPS connections to this site.",
    recommendation:
      'Add the header: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
  },
  {
    name: "content-security-policy",
    severity: "high",
    category: "Security",
    description:
      "Content-Security-Policy (CSP) header is missing. The site is more vulnerable to XSS and data injection attacks.",
    recommendation:
      "Define a Content-Security-Policy that restricts resource loading to trusted origins.",
  },
  {
    name: "x-content-type-options",
    severity: "medium",
    category: "Security",
    description:
      "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, leading to security issues.",
    recommendation: 'Add the header: X-Content-Type-Options: nosniff',
    validate(value: string): string | null {
      if (value.toLowerCase() !== "nosniff") {
        return `X-Content-Type-Options is set to "${value}" instead of "nosniff".`;
      }
      return null;
    },
  },
  {
    name: "x-frame-options",
    severity: "medium",
    category: "Security",
    description:
      "X-Frame-Options header is missing. The site may be vulnerable to clickjacking attacks.",
    recommendation: 'Add the header: X-Frame-Options: DENY or SAMEORIGIN',
    validate(value: string): string | null {
      const upper = value.toUpperCase();
      if (upper !== "DENY" && upper !== "SAMEORIGIN") {
        return `X-Frame-Options is set to "${value}" which is not a recommended value (use DENY or SAMEORIGIN).`;
      }
      return null;
    },
  },
  {
    name: "x-xss-protection",
    severity: "low",
    category: "Security",
    description:
      "X-XSS-Protection header is missing. While deprecated in modern browsers, it still provides a layer of defense in older ones.",
    recommendation: 'Add the header: X-XSS-Protection: 1; mode=block',
  },
  {
    name: "referrer-policy",
    severity: "medium",
    category: "Security",
    description:
      "Referrer-Policy header is missing. The browser may leak the full URL in the Referer header to third-party sites.",
    recommendation:
      'Add the header: Referrer-Policy: strict-origin-when-cross-origin (or stricter)',
  },
  {
    name: "permissions-policy",
    severity: "low",
    category: "Security",
    description:
      "Permissions-Policy (formerly Feature-Policy) header is missing. Browser features like camera, microphone, and geolocation are not explicitly restricted.",
    recommendation:
      'Add a Permissions-Policy header to disable unnecessary browser features, e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()',
    /**
     * Also accept the legacy Feature-Policy header as an alternative.
     * This is handled specially in the analysis loop.
     */
  },
  {
    name: "cross-origin-opener-policy",
    severity: "low",
    category: "Security",
    description:
      "Cross-Origin-Opener-Policy header is missing. The site may be vulnerable to cross-origin attacks such as Spectre.",
    recommendation: 'Add the header: Cross-Origin-Opener-Policy: same-origin',
  },
  {
    name: "cross-origin-resource-policy",
    severity: "low",
    category: "Security",
    description:
      "Cross-Origin-Resource-Policy header is missing. Resources may be loaded by cross-origin pages.",
    recommendation:
      'Add the header: Cross-Origin-Resource-Policy: same-origin (or same-site)',
  },
  {
    name: "cross-origin-embedder-policy",
    severity: "low",
    category: "Security",
    description:
      "Cross-Origin-Embedder-Policy header is missing. The document cannot use SharedArrayBuffer and high-resolution timers without this header.",
    recommendation:
      'Add the header: Cross-Origin-Embedder-Policy: require-corp',
  },
];

// ---------- Information-leaking headers that should NOT be present ----------

interface LeakHeader {
  name: string;
  severity: HeaderFinding["severity"];
  description: string;
  recommendation: string;
  /** If true, only flag when the value contains a version number. */
  requiresVersion?: boolean;
}

const LEAK_HEADERS: LeakHeader[] = [
  {
    name: "server",
    severity: "medium",
    description:
      "The Server header reveals server software and potentially its version, aiding targeted attacks.",
    recommendation:
      "Remove the Server header or set it to a generic value without version information.",
    requiresVersion: true,
  },
  {
    name: "x-powered-by",
    severity: "medium",
    description:
      "The X-Powered-By header reveals the technology stack (e.g. Express, PHP, ASP.NET).",
    recommendation: "Remove the X-Powered-By header entirely.",
  },
  {
    name: "x-aspnet-version",
    severity: "medium",
    description:
      "The X-AspNet-Version header reveals the ASP.NET framework version.",
    recommendation:
      "Disable the header in web.config: <httpRuntime enableVersionHeader=\"false\" />",
  },
  {
    name: "x-aspnetmvc-version",
    severity: "medium",
    description: "The X-AspNetMvc-Version header reveals the ASP.NET MVC version.",
    recommendation:
      "Remove the header by adding MvcHandler.DisableMvcResponseHeader = true in Application_Start.",
  },
  {
    name: "x-generator",
    severity: "low",
    description:
      "The X-Generator header reveals the CMS or framework used to build the site.",
    recommendation: "Remove the X-Generator header.",
  },
  {
    name: "x-debug-token",
    severity: "high",
    description:
      "The X-Debug-Token header exposes a debug profiler token, indicating the site is running in debug mode.",
    recommendation:
      "Disable debug mode in production and remove the X-Debug-Token header.",
  },
  {
    name: "x-debug-token-link",
    severity: "high",
    description:
      "The X-Debug-Token-Link header exposes a URL to the debug profiler, indicating the site is running in debug mode.",
    recommendation:
      "Disable debug mode in production and remove the X-Debug-Token-Link header.",
  },
];

// Regex that matches RFC-1918 private/internal IPv4 addresses
const INTERNAL_IP_REGEX =
  /(?:^|[^0-9])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)/;

// Version number pattern (e.g. /2.4.41, 1.19.0)
const VERSION_REGEX = /\/?\d+\.\d+/;

/** Sanitize a header value so it is safe to include in findings (truncate excessively long values). */
function sanitize(value: string): string {
  if (value.length > 256) {
    return value.slice(0, 253) + "...";
  }
  return value;
}

// ---------- Scoring ----------

const SEVERITY_DEDUCTIONS: Record<HeaderFinding["severity"], number> = {
  critical: 25,
  high: 15,
  medium: 10,
  low: 5,
  info: 0,
};

function computeScore(findings: HeaderFinding[]): number {
  let score = 100;
  for (const f of findings) {
    score -= SEVERITY_DEDUCTIONS[f.severity];
  }
  return Math.max(0, score);
}

// ---------- Main analysis function ----------

export async function analyzeHeaders(url: string): Promise<HeaderAnalysisResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; Key-Sentinel-Scanner/1.0)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
  } catch (err: any) {
    clearTimeout(timeout);
    const message =
      err?.name === "AbortError"
        ? "Request timed out after 10 seconds"
        : err?.message ?? "Unknown fetch error";
    return {
      url,
      statusCode: 0,
      findings: [
        {
          header: "N/A",
          status: "insecure",
          severity: "critical",
          category: "Security",
          description: `Failed to fetch the URL: ${message}`,
          recommendation: "Verify the URL is reachable and try again.",
        },
      ],
      score: 0,
    };
  } finally {
    clearTimeout(timeout);
  }

  const findings: HeaderFinding[] = [];
  const headers = response.headers;

  // --- Check expected security headers ---
  for (const expected of EXPECTED_HEADERS) {
    // Special case: accept Feature-Policy as a fallback for Permissions-Policy
    let headerValue = headers.get(expected.name);
    if (!headerValue && expected.name === "permissions-policy") {
      headerValue = headers.get("feature-policy");
    }

    if (!headerValue) {
      findings.push({
        header: expected.name,
        status: "missing",
        severity: expected.severity,
        category: expected.category,
        description: expected.description,
        recommendation: expected.recommendation,
      });
    } else if (expected.validate) {
      const issue = expected.validate(headerValue);
      if (issue) {
        findings.push({
          header: expected.name,
          value: sanitize(headerValue),
          status: "insecure",
          severity: expected.severity,
          category: expected.category,
          description: issue,
          recommendation: expected.recommendation,
        });
      }
    }
  }

  // --- Check information-leaking headers ---
  for (const leak of LEAK_HEADERS) {
    const headerValue = headers.get(leak.name);
    if (!headerValue) continue;

    if (leak.requiresVersion && !VERSION_REGEX.test(headerValue)) {
      // Header present but no version info exposed -- skip
      continue;
    }

    findings.push({
      header: leak.name,
      value: sanitize(headerValue),
      status: "present",
      severity: leak.severity,
      category: "Information Leak",
      description: leak.description,
      recommendation: leak.recommendation,
    });
  }

  // --- Check ALL headers for internal IP addresses ---
  headers.forEach((value, name) => {
    if (INTERNAL_IP_REGEX.test(value)) {
      findings.push({
        header: name,
        value: sanitize(value),
        status: "present",
        severity: "high",
        category: "Information Leak",
        description: `The "${name}" header contains an internal/private IP address, potentially revealing internal network topology.`,
        recommendation:
          "Remove internal IP addresses from response headers. Configure reverse proxies to strip internal addresses.",
      });
    }
  });

  // --- CORS checks ---
  const acao = headers.get("access-control-allow-origin");
  const acac = headers.get("access-control-allow-credentials");

  if (acao === "*" && acac?.toLowerCase() === "true") {
    findings.push({
      header: "access-control-allow-origin / access-control-allow-credentials",
      value: "Origin: *, Credentials: true",
      status: "insecure",
      severity: "high",
      category: "CORS",
      description:
        "CORS is configured with a wildcard origin AND credentials allowed. This is a dangerous misconfiguration that browsers will actually block, but it indicates a server-side logic error.",
      recommendation:
        "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Use a specific, validated origin instead.",
    });
  } else if (acao === "*") {
    findings.push({
      header: "access-control-allow-origin",
      value: "*",
      status: "insecure",
      severity: "medium",
      category: "CORS",
      description:
        "Access-Control-Allow-Origin is set to wildcard (*), allowing any website to make cross-origin requests to this server.",
      recommendation:
        "Restrict the allowed origins to specific trusted domains instead of using a wildcard.",
    });
  }

  // --- Cache-related checks ---
  const cacheControl = headers.get("cache-control");
  if (!cacheControl) {
    findings.push({
      header: "cache-control",
      status: "missing",
      severity: "low",
      category: "Cache",
      description:
        "Cache-Control header is missing. Sensitive pages may be stored in browser or proxy caches.",
      recommendation:
        'For sensitive pages, add: Cache-Control: no-store, no-cache, must-revalidate, private',
    });
  }

  const xCache = headers.get("x-cache");
  if (xCache) {
    findings.push({
      header: "x-cache",
      value: sanitize(xCache),
      status: "present",
      severity: "low",
      category: "Cache",
      description:
        "The X-Cache header reveals caching infrastructure details (e.g. CDN cache hit/miss status).",
      recommendation:
        "Consider removing the X-Cache header to avoid exposing infrastructure details.",
    });
  }

  const xCacheHits = headers.get("x-cache-hits");
  if (xCacheHits) {
    findings.push({
      header: "x-cache-hits",
      value: sanitize(xCacheHits),
      status: "present",
      severity: "low",
      category: "Cache",
      description:
        "The X-Cache-Hits header reveals cache hit count information about the caching infrastructure.",
      recommendation:
        "Consider removing the X-Cache-Hits header to avoid exposing infrastructure details.",
    });
  }

  // --- Extract server info for the result ---
  const serverHeader = headers.get("server") ?? undefined;

  return {
    url,
    statusCode: response.status,
    serverInfo: serverHeader,
    findings,
    score: computeScore(findings),
  };
}
