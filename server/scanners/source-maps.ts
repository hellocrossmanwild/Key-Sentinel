/**
 * Source Map Discovery and Scanning
 *
 * Detects exposed .js.map files which contain original source code.
 * The mere existence of publicly accessible source maps is a security
 * concern because they reveal application internals, original file
 * paths, and unminified source that may contain secrets.
 */

const USER_AGENT = "Mozilla/5.0 (compatible; KeyGuard-Scanner/1.0)";
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_SOURCE_MAP_BYTES = 50 * 1024 * 1024; // 50 MB
const BATCH_SIZE = 5;

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

export interface SourceMapFile {
  mapUrl: string;
  originalFiles: string[];     // original source file paths found in the map
  totalOriginalFiles: number;
  contentSize: number;         // bytes
}

export interface SourceMapResult {
  mapsFound: number;
  mapsScanned: number;
  exposedFiles: SourceMapFile[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Fetch with a per-request timeout and the scanner User-Agent header.
 */
async function fetchWithTimeout(
  url: string,
  options: RequestInit & { timeout?: number } = {},
): Promise<Response> {
  const { timeout = REQUEST_TIMEOUT_MS, ...fetchOpts } = options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...fetchOpts,
      signal: controller.signal,
      headers: {
        "User-Agent": USER_AGENT,
        ...(fetchOpts.headers as Record<string, string> | undefined),
      },
    });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Run an array of async functions in batches of `size`.
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
 * Extract `//# sourceMappingURL=<url>` from JavaScript content.
 * Returns the resolved absolute URL or null.
 */
function extractSourceMappingURL(
  scriptContent: string,
  scriptUrl: string,
): string | null {
  // Match the last occurrence (there should only be one, but play safe)
  const regex = /\/\/[#@]\s*sourceMappingURL=(\S+)/g;
  let lastMatch: string | null = null;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(scriptContent)) !== null) {
    lastMatch = m[1];
  }

  if (!lastMatch) return null;

  // If it's a data URI, skip it – we only care about external .map files
  if (lastMatch.startsWith("data:")) return null;

  try {
    return new URL(lastMatch, scriptUrl).href;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Discovery: find candidate .map URLs
// ---------------------------------------------------------------------------

interface DiscoveryContext {
  /** Script URLs to inspect */
  scriptUrls: string[];
  /** Base URL of the site being scanned */
  baseUrl: string;
}

/**
 * Discover source map URLs via three strategies:
 * 1. Append `.map` to each script URL.
 * 2. Check the script response for a `//# sourceMappingURL=` comment.
 * 3. Check `X-SourceMap` / `SourceMap` HTTP headers on script responses.
 */
async function discoverMapUrls(ctx: DiscoveryContext): Promise<Set<string>> {
  const candidates = new Set<string>();

  // Strategy 1: append .map
  for (const scriptUrl of ctx.scriptUrls) {
    candidates.add(scriptUrl + ".map");
  }

  // Strategies 2 & 3 require fetching each script.  We do this in batches
  // to respect the concurrency limit and reuse the response for both checks.
  const tasks = ctx.scriptUrls.map((scriptUrl) => async () => {
    try {
      const res = await fetchWithTimeout(scriptUrl, { method: "GET" });
      if (!res.ok) return;

      // Strategy 3: HTTP header
      const headerMap =
        res.headers.get("X-SourceMap") ||
        res.headers.get("SourceMap");
      if (headerMap) {
        try {
          candidates.add(new URL(headerMap, scriptUrl).href);
        } catch {
          // invalid URL – ignore
        }
      }

      // Strategy 2: inline comment (read only the tail of large files)
      const contentType = res.headers.get("content-type") || "";
      if (
        contentType.includes("javascript") ||
        contentType.includes("text") ||
        scriptUrl.endsWith(".js")
      ) {
        const text = await res.text();
        const inlineUrl = extractSourceMappingURL(text, scriptUrl);
        if (inlineUrl) {
          candidates.add(inlineUrl);
        }
      }
    } catch {
      // Network error or timeout – skip this script
    }
  });

  await batchRun(tasks, BATCH_SIZE);

  return candidates;
}

// ---------------------------------------------------------------------------
// Scanning: verify and parse discovered .map URLs
// ---------------------------------------------------------------------------

interface ParsedSourceMap {
  mapUrl: string;
  sources: string[];
  contentSize: number;
}

/**
 * HEAD-check a candidate map URL, then GET and parse if it exists.
 */
async function fetchAndParseMap(
  mapUrl: string,
): Promise<ParsedSourceMap | null> {
  try {
    // HEAD first to see if it exists and check size
    const headRes = await fetchWithTimeout(mapUrl, { method: "HEAD" });
    if (!headRes.ok) return null;

    const contentLength = parseInt(
      headRes.headers.get("content-length") || "0",
      10,
    );
    if (contentLength > MAX_SOURCE_MAP_BYTES) {
      // Too large – skip but still note it exists (caller handles this)
      return { mapUrl, sources: [], contentSize: contentLength };
    }

    // GET the full source map
    const getRes = await fetchWithTimeout(mapUrl, { method: "GET" });
    if (!getRes.ok) return null;

    const text = await getRes.text();

    // Enforce size limit on actual body
    const actualSize = new TextEncoder().encode(text).byteLength;
    if (actualSize > MAX_SOURCE_MAP_BYTES) {
      return { mapUrl, sources: [], contentSize: actualSize };
    }

    // Parse JSON and extract sources array
    let sources: string[] = [];
    try {
      const json = JSON.parse(text);
      if (Array.isArray(json.sources)) {
        sources = json.sources.map(String);
      }
    } catch {
      // Not valid JSON – might still be a source map (v3 with sections, etc.)
      // We still count it as found.
    }

    return { mapUrl, sources, contentSize: actualSize };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Discover and scan source maps for the given script URLs.
 *
 * @param scriptUrls - Absolute URLs of JavaScript files to check.
 * @param baseUrl    - The base URL of the site being scanned.
 * @returns A summary of discovered source maps and their original file lists.
 */
export async function discoverAndScanSourceMaps(
  scriptUrls: string[],
  baseUrl: string,
): Promise<SourceMapResult> {
  // 1. Discover candidate .map URLs
  const candidates = await discoverMapUrls({ scriptUrls, baseUrl });

  if (candidates.size === 0) {
    return { mapsFound: 0, mapsScanned: 0, exposedFiles: [] };
  }

  // 2. Fetch & parse each candidate in batches
  const candidateList = Array.from(candidates);
  const tasks = candidateList.map((url) => () => fetchAndParseMap(url));
  const settled = await batchRun(tasks, BATCH_SIZE);

  const exposedFiles: SourceMapFile[] = [];

  for (const result of settled) {
    if (result.status === "fulfilled" && result.value !== null) {
      const parsed = result.value;
      exposedFiles.push({
        mapUrl: parsed.mapUrl,
        originalFiles: parsed.sources,
        totalOriginalFiles: parsed.sources.length,
        contentSize: parsed.contentSize,
      });
    }
  }

  return {
    mapsFound: exposedFiles.length,
    mapsScanned: exposedFiles.length,
    exposedFiles,
  };
}

/**
 * Fetch and return the raw content of a source map so it can be fed into
 * the pattern scanner for secret detection.
 *
 * @param mapUrl - Absolute URL of the .map file.
 * @returns An object with `path` (the URL) and `content` (the raw text),
 *          or `null` if the map cannot be fetched.
 */
export async function getSourceMapContent(
  mapUrl: string,
): Promise<{ path: string; content: string } | null> {
  try {
    // HEAD first to check existence and size
    const headRes = await fetchWithTimeout(mapUrl, { method: "HEAD" });
    if (!headRes.ok) return null;

    const contentLength = parseInt(
      headRes.headers.get("content-length") || "0",
      10,
    );
    if (contentLength > MAX_SOURCE_MAP_BYTES) return null;

    // GET the content
    const getRes = await fetchWithTimeout(mapUrl, { method: "GET" });
    if (!getRes.ok) return null;

    const content = await getRes.text();

    const actualSize = new TextEncoder().encode(content).byteLength;
    if (actualSize > MAX_SOURCE_MAP_BYTES) return null;

    return { path: mapUrl, content };
  } catch {
    return null;
  }
}
