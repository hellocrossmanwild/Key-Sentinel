/**
 * Multi-page web crawler for comprehensive website scanning.
 * Discovers and fetches pages on the same domain using BFS traversal,
 * collecting HTML, inline scripts, external scripts, and stylesheets.
 */

export interface CrawlResult {
  pagesDiscovered: number;
  pagesCrawled: number;
  files: Array<{ path: string; content: string }>; // Content for pattern scanning
  scriptUrls: string[]; // All discovered script URLs (for source map scanning)
  errors: string[];
}

const USER_AGENT = "Mozilla/5.0 (compatible; KeyGuard-Scanner/1.0)";
const PER_REQUEST_TIMEOUT_MS = 10_000;
const TOTAL_CRAWL_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_PAGES = 20;
const DEFAULT_MAX_DEPTH = 2;
const CONCURRENT_BATCH_SIZE = 5;
const MAX_EXTERNAL_SCRIPTS = 30;
const MAX_EXTERNAL_STYLESHEETS = 10;

/** File extensions to skip when following links. */
const SKIP_EXTENSIONS: string[] = [
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".svg",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".mp4", ".avi", ".mov", ".mkv", ".webm", ".flv", ".wmv",
  ".mp3", ".wav", ".ogg", ".flac", ".aac", ".wma",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz",
  ".exe", ".dmg", ".iso", ".bin",
];

/** URL path segments that indicate non-content pages. */
const SKIP_PATH_SEGMENTS = [
  "/logout", "/signout", "/sign-out", "/log-out",
  "/auth", "/oauth", "/cdn-cgi/",
];

/**
 * Normalize a URL by removing trailing slashes and fragment identifiers
 * so that duplicate pages are not visited twice.
 */
function normalizeUrl(urlStr: string): string {
  try {
    const parsed = new URL(urlStr);
    parsed.hash = "";
    // Remove trailing slash unless it is the root path
    if (parsed.pathname.length > 1 && parsed.pathname.endsWith("/")) {
      parsed.pathname = parsed.pathname.slice(0, -1);
    }
    return parsed.href;
  } catch {
    return urlStr;
  }
}

/**
 * Determine whether a URL should be skipped based on extension,
 * scheme, or path segment rules.
 */
function shouldSkipUrl(urlStr: string): boolean {
  // Skip non-http(s) schemes
  if (urlStr.startsWith("mailto:") || urlStr.startsWith("tel:") || urlStr.startsWith("javascript:")) {
    return true;
  }

  // Skip URLs with fragments only (e.g. "#section")
  try {
    const parsed = new URL(urlStr);

    // Skip if the URL has a file extension we want to ignore
    const pathname = parsed.pathname.toLowerCase();
    for (const ext of SKIP_EXTENSIONS) {
      if (pathname.endsWith(ext)) return true;
    }

    // Skip non-content path segments
    const lowerPath = pathname.toLowerCase();
    for (const segment of SKIP_PATH_SEGMENTS) {
      if (lowerPath.includes(segment)) return true;
    }
  } catch {
    return true;
  }

  return false;
}

/**
 * Check if a candidate URL is on the same origin (hostname) as the base URL.
 */
function isSameOrigin(baseUrl: string, candidateUrl: string): boolean {
  try {
    const base = new URL(baseUrl);
    const candidate = new URL(candidateUrl);
    return base.hostname === candidate.hostname;
  } catch {
    return false;
  }
}

/**
 * Fetch a single URL with a per-request timeout. Returns the response text
 * and content-type, or null if the fetch fails.
 */
async function fetchWithTimeout(
  url: string,
  timeoutMs: number,
): Promise<{ text: string; contentType: string } | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(url, {
      headers: {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      redirect: "follow",
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!res.ok) return null;

    const contentType = res.headers.get("content-type") || "";
    // Skip binary content types
    if (
      contentType.includes("image") ||
      contentType.includes("font") ||
      contentType.includes("video") ||
      contentType.includes("audio") ||
      contentType.includes("application/octet-stream")
    ) {
      return null;
    }

    const text = await res.text();
    // Reject unreasonably large responses (> 2 MB)
    if (text.length > 2_000_000) return null;

    return { text, contentType };
  } catch {
    return null;
  }
}

/**
 * Run an array of async tasks in batches of a given concurrency limit.
 */
async function batchProcess<T>(
  items: T[],
  concurrency: number,
  processor: (item: T) => Promise<void>,
): Promise<void> {
  for (let i = 0; i < items.length; i += concurrency) {
    const batch = items.slice(i, i + concurrency);
    await Promise.allSettled(batch.map(processor));
  }
}

/**
 * Crawl a website starting from `baseUrl`, discovering pages via BFS.
 *
 * @param baseUrl    - The starting URL to crawl.
 * @param maxPages   - Maximum number of pages to crawl (default: 20).
 * @param maxDepth   - Maximum link-follow depth from the start page (default: 2).
 * @returns A CrawlResult containing all discovered content and metadata.
 */
export async function crawlWebsite(
  baseUrl: string,
  maxPages: number = DEFAULT_MAX_PAGES,
  maxDepth: number = DEFAULT_MAX_DEPTH,
): Promise<CrawlResult> {
  const files: Array<{ path: string; content: string }> = [];
  const allScriptUrls: string[] = [];
  const errors: string[] = [];

  const visited = new Set<string>();
  const discoveredUrls = new Set<string>();

  // Track external resource fetching limits
  let externalScriptsFetched = 0;
  let externalStylesheetsFetched = 0;
  const fetchedExternalUrls = new Set<string>();

  const crawlStartTime = Date.now();

  /** Check whether we have exceeded the total crawl timeout. */
  function isTimedOut(): boolean {
    return Date.now() - crawlStartTime >= TOTAL_CRAWL_TIMEOUT_MS;
  }

  // BFS queue: each entry is [normalizedUrl, depth]
  const queue: Array<[string, number]> = [];

  const startNormalized = normalizeUrl(baseUrl);
  queue.push([startNormalized, 0]);
  discoveredUrls.add(startNormalized);

  // --- Attempt to discover additional URLs from robots.txt and sitemap.xml ---
  await discoverFromRobotsAndSitemap(baseUrl, discoveredUrls, queue, maxDepth);

  const { load } = await import("cheerio");

  // BFS loop
  while (queue.length > 0 && visited.size < maxPages && !isTimedOut()) {
    // Dequeue a batch of URLs at the same depth level for concurrent fetching
    const currentBatch: Array<[string, number]> = [];
    while (
      currentBatch.length < CONCURRENT_BATCH_SIZE &&
      queue.length > 0 &&
      visited.size + currentBatch.length < maxPages
    ) {
      const next = queue.shift()!;
      const [url] = next;
      if (visited.has(url)) continue;
      currentBatch.push(next);
    }

    if (currentBatch.length === 0) continue;

    // Fetch all pages in the current batch concurrently
    const fetchResults = await Promise.allSettled(
      currentBatch.map(async ([url, depth]) => {
        visited.add(url);
        const result = await fetchWithTimeout(url, PER_REQUEST_TIMEOUT_MS);
        return { url, depth, result };
      }),
    );

    for (const settled of fetchResults) {
      if (isTimedOut()) break;
      if (settled.status !== "fulfilled") continue;

      const { url, depth, result } = settled.value;

      if (!result) {
        errors.push(`Failed to fetch: ${url}`);
        continue;
      }

      const { text: html, contentType } = result;

      // Only parse HTML pages for links
      const isHtml =
        contentType.includes("text/html") ||
        contentType.includes("application/xhtml");

      if (!isHtml) {
        // Non-HTML text content (e.g., plain text, JSON) -- still scan it
        files.push({ path: url, content: html });
        continue;
      }

      // Store the HTML page for scanning
      files.push({ path: url, content: html });

      // Parse with cheerio
      let $: ReturnType<typeof load>;
      try {
        $ = load(html);
      } catch {
        errors.push(`Failed to parse HTML: ${url}`);
        continue;
      }

      // --- Extract inline scripts ---
      $("script:not([src])").each((i, el) => {
        const content = $(el).html();
        if (content && content.trim().length > 0) {
          files.push({
            path: `${url}#inline-script-${i + 1}`,
            content: content,
          });
        }
      });

      // --- Extract external script URLs ---
      $("script[src]").each((_, el) => {
        const src = $(el).attr("src");
        if (!src) return;
        try {
          const absoluteUrl = new URL(src, url).href;
          if (!allScriptUrls.includes(absoluteUrl)) {
            allScriptUrls.push(absoluteUrl);
          }
        } catch { /* ignore malformed URLs */ }
      });

      // --- Extract stylesheet URLs ---
      const stylesheetUrls: string[] = [];
      $('link[rel="stylesheet"], link[href$=".css"]').each((_, el) => {
        const href = $(el).attr("href");
        if (!href) return;
        try {
          const absoluteUrl = new URL(href, url).href;
          if (!fetchedExternalUrls.has(absoluteUrl)) {
            stylesheetUrls.push(absoluteUrl);
          }
        } catch { /* ignore malformed URLs */ }
      });

      // --- Discover same-origin links for further crawling ---
      if (depth < maxDepth) {
        $("a[href]").each((_, el) => {
          const href = $(el).attr("href");
          if (!href) return;

          // Skip fragment-only links
          if (href.startsWith("#")) return;

          try {
            const absoluteUrl = new URL(href, url).href;

            if (shouldSkipUrl(absoluteUrl)) return;
            if (!isSameOrigin(baseUrl, absoluteUrl)) return;

            const normalized = normalizeUrl(absoluteUrl);
            if (!discoveredUrls.has(normalized)) {
              discoveredUrls.add(normalized);
              queue.push([normalized, depth + 1]);
            }
          } catch { /* ignore malformed URLs */ }
        });
      }

      // --- Fetch external stylesheets (respecting limit) ---
      for (const cssUrl of stylesheetUrls) {
        if (externalStylesheetsFetched >= MAX_EXTERNAL_STYLESHEETS) break;
        if (fetchedExternalUrls.has(cssUrl)) continue;
        if (isTimedOut()) break;

        fetchedExternalUrls.add(cssUrl);
        const cssResult = await fetchWithTimeout(cssUrl, PER_REQUEST_TIMEOUT_MS);
        if (cssResult) {
          files.push({ path: cssUrl, content: cssResult.text });
          externalStylesheetsFetched++;
        }
      }
    }
  }

  // --- Fetch external scripts discovered across all pages ---
  const scriptsToFetch = allScriptUrls.filter(
    (u) => !fetchedExternalUrls.has(u),
  );

  await batchProcess(
    scriptsToFetch.slice(0, MAX_EXTERNAL_SCRIPTS - externalScriptsFetched),
    CONCURRENT_BATCH_SIZE,
    async (scriptUrl) => {
      if (isTimedOut()) return;
      if (externalScriptsFetched >= MAX_EXTERNAL_SCRIPTS) return;
      if (fetchedExternalUrls.has(scriptUrl)) return;

      fetchedExternalUrls.add(scriptUrl);
      const scriptResult = await fetchWithTimeout(scriptUrl, PER_REQUEST_TIMEOUT_MS);
      if (scriptResult) {
        files.push({ path: scriptUrl, content: scriptResult.text });
        externalScriptsFetched++;
      } else {
        errors.push(`Failed to fetch script: ${scriptUrl}`);
      }
    },
  );

  return {
    pagesDiscovered: discoveredUrls.size,
    pagesCrawled: visited.size,
    files,
    scriptUrls: allScriptUrls,
    errors,
  };
}

/**
 * Attempt to fetch robots.txt and sitemap.xml from the site root,
 * extracting any additional same-origin URLs to seed the BFS queue.
 */
async function discoverFromRobotsAndSitemap(
  baseUrl: string,
  discoveredUrls: Set<string>,
  queue: Array<[string, number]>,
  maxDepth: number,
): Promise<void> {
  let rootOrigin: string;
  try {
    const parsed = new URL(baseUrl);
    rootOrigin = parsed.origin;
  } catch {
    return;
  }

  // --- robots.txt ---
  try {
    const robotsResult = await fetchWithTimeout(
      `${rootOrigin}/robots.txt`,
      PER_REQUEST_TIMEOUT_MS,
    );
    if (robotsResult) {
      const lines = robotsResult.text.split("\n");
      for (const line of lines) {
        const trimmed = line.trim();

        // Extract Sitemap directives
        if (trimmed.toLowerCase().startsWith("sitemap:")) {
          const sitemapUrl = trimmed.slice("sitemap:".length).trim();
          if (sitemapUrl) {
            await parseSitemapInto(sitemapUrl, baseUrl, discoveredUrls, queue, maxDepth);
          }
        }

        // Extract Allow/Disallow paths as potential URLs to explore
        const allowMatch = trimmed.match(/^Allow:\s*(.+)/i);
        if (allowMatch) {
          const path = allowMatch[1].trim().split(/\s/)[0];
          if (path && path !== "/" && !path.includes("*")) {
            try {
              const fullUrl = new URL(path, rootOrigin).href;
              const normalized = normalizeUrl(fullUrl);
              if (!shouldSkipUrl(fullUrl) && !discoveredUrls.has(normalized)) {
                discoveredUrls.add(normalized);
                // Add at depth 1 since they are one link away from root
                if (maxDepth >= 1) {
                  queue.push([normalized, 1]);
                }
              }
            } catch { /* ignore */ }
          }
        }
      }
    }
  } catch { /* robots.txt not available, continue */ }

  // --- sitemap.xml (if not already discovered via robots.txt) ---
  await parseSitemapInto(
    `${rootOrigin}/sitemap.xml`,
    baseUrl,
    discoveredUrls,
    queue,
    maxDepth,
  );
}

/**
 * Fetch and parse a sitemap XML, extracting <loc> URLs and adding
 * same-origin ones to the BFS queue.
 */
async function parseSitemapInto(
  sitemapUrl: string,
  baseUrl: string,
  discoveredUrls: Set<string>,
  queue: Array<[string, number]>,
  maxDepth: number,
): Promise<void> {
  try {
    const result = await fetchWithTimeout(sitemapUrl, PER_REQUEST_TIMEOUT_MS);
    if (!result) return;

    // Simple regex extraction of <loc> tags from sitemap XML
    const locRegex = /<loc>\s*(.*?)\s*<\/loc>/gi;
    let match: RegExpExecArray | null;

    while ((match = locRegex.exec(result.text)) !== null) {
      const url = match[1].trim();
      if (!url) continue;

      if (!isSameOrigin(baseUrl, url)) continue;
      if (shouldSkipUrl(url)) continue;

      const normalized = normalizeUrl(url);
      if (!discoveredUrls.has(normalized)) {
        discoveredUrls.add(normalized);
        // Sitemap URLs are treated as depth 1
        if (maxDepth >= 1) {
          queue.push([normalized, 1]);
        }
      }
    }
  } catch { /* sitemap not available or unparseable, continue */ }
}
