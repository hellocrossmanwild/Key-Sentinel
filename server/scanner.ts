import type { KeyFinding, ScanResult } from "@shared/schema";
import { randomUUID } from "crypto";

// Scanner modules
import { KEY_PATTERNS } from "./scanners/patterns";
import { detectHighEntropyStrings } from "./scanners/entropy";
import { detectJWTTokens } from "./scanners/jwt-detector";
import { analyzeHeaders } from "./scanners/headers";
import { probeSensitivePaths } from "./scanners/sensitive-paths";
import { discoverAndScanSourceMaps, getSourceMapContent } from "./scanners/source-maps";
import { crawlWebsite } from "./scanners/crawler";
import { scanGithubHistory } from "./scanners/github-history";
import { analyzeJSBundles } from "./scanners/bundle-analyzer";
import { calculateSecurityScore } from "./scanners/scoring";

// ─── Binary file extensions to skip ──────────────────────────────

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf",
  ".eot", ".otf", ".mp3", ".mp4", ".avi", ".mov", ".webm", ".ogg", ".wav",
  ".zip", ".tar", ".gz", ".rar", ".7z", ".pdf", ".doc", ".docx", ".xls",
  ".xlsx", ".ppt", ".pptx", ".exe", ".dll", ".so", ".dylib", ".pyc",
  ".class", ".o", ".obj", ".lock", ".min.css",
]);

function shouldSkipFile(filename: string): boolean {
  const lower = filename.toLowerCase();
  for (const ext of Array.from(BINARY_EXTENSIONS)) {
    if (lower.endsWith(ext)) return true;
  }
  if (lower.includes("node_modules/") || lower.includes("vendor/") || lower.includes(".git/")) return true;
  return false;
}

// ─── Pattern-based content scanning ──────────────────────────────

const KNOWN_FALSE_POSITIVE_VALUES = new Set([
  "undefined", "null", "true", "false", "none", "nil", "nan", "infinity",
  "function", "object", "string", "number", "boolean", "symbol", "bigint",
  "required", "optional", "default", "inherit", "initial", "unset",
  "enabled", "disabled", "active", "inactive", "pending", "loading",
  "success", "failure", "error", "warning", "unknown", "anonymous",
  "localhost", "production", "development", "staging", "changeme",
  "password", "username", "admin1234", "administrator",
]);

const FALSE_POSITIVE_PATTERNS = [
  /^(example|test|demo|sample|placeholder|your[_-]|my[_-]|fake[_-]|mock[_-]|dummy[_-]|temp[_-])/i,
  /^(replace[_-]?me|insert[_-]?here|change[_-]?me|todo|fixme|hack|xxx)/i,
  /^x{4,}$/i,
  /^\*+$/,
  /^\.{3,}$/,
  /^[0]+$/,
  /^[1]+$/,
  /^\$[A-Z_]+$/i,
  /^\$\{[^}]+\}$/,
  /^%[A-Z_]+%$/i,
  /^\.{0,2}\//,
  /^https?:\/\/(?!.*:.*@)/,
  /[{}<>;]/,
  /^[a-z]+$/,
  /^[A-Z_]+$/,
  /^(sk[_-]test|pk[_-]test|rk[_-]test)/i,
];

function isPatternFalsePositive(value: string): boolean {
  if (KNOWN_FALSE_POSITIVE_VALUES.has(value.toLowerCase())) return true;
  for (const pattern of FALSE_POSITIVE_PATTERNS) {
    if (pattern.test(value)) return true;
  }
  return false;
}

export function scanContent(content: string, filename: string): KeyFinding[] {
  const findings: KeyFinding[] = [];
  const seen = new Set<string>();

  for (const keyPattern of KEY_PATTERNS) {
    const regex = new RegExp(keyPattern.pattern.source, keyPattern.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const value = match[1] || match[0];
      const trimmedValue = value.replace(/^[\s="'`]+|[\s"'`]+$/g, "");

      if (trimmedValue.length < 8) continue;
      if (/^[a-z_]+$/i.test(trimmedValue)) continue;
      if (isPatternFalsePositive(trimmedValue)) continue;

      const isGenericPattern = keyPattern.name.startsWith("Generic ") ||
        keyPattern.name.startsWith("Hardcoded ") ||
        keyPattern.name.includes("Flag") ||
        keyPattern.name.includes("Common Weak");

      if (isGenericPattern) {
        const hasUpper = /[A-Z]/.test(trimmedValue);
        const hasLower = /[a-z]/.test(trimmedValue);
        const hasDigit = /\d/.test(trimmedValue);
        const hasSpecial = /[_\-+/=!@#$%^&*]/.test(trimmedValue);
        const charClasses = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
        if (charClasses < 2 && trimmedValue.length < 20) continue;
      }

      const key = `${keyPattern.name}:${trimmedValue}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const matchIndex = match.index;
      const beforeMatch = content.substring(0, matchIndex);
      const lineNumber = beforeMatch.split("\n").length;

      findings.push({
        keyType: keyPattern.name,
        value: trimmedValue,
        file: filename,
        line: lineNumber,
        severity: keyPattern.severity,
        source: "pattern",
      });
    }
  }

  return findings;
}

// ─── GitHub helpers ──────────────────────────────────────────────

function parseGithubUrl(url: string): { owner: string; repo: string; path?: string } | null {
  try {
    const parsed = new URL(url);
    if (!parsed.hostname.includes("github.com")) return null;

    const parts = parsed.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;

    const owner = parts[0];
    const repo = parts[1];
    let path: string | undefined;

    if (parts.length > 3 && (parts[2] === "tree" || parts[2] === "blob")) {
      path = parts.slice(4).join("/");
    }

    return { owner, repo, path };
  } catch {
    return null;
  }
}

async function fetchGithubRepoFiles(owner: string, repo: string): Promise<Array<{ path: string; content: string }>> {
  const files: Array<{ path: string; content: string }> = [];

  const repoUrl = `https://api.github.com/repos/${owner}/${repo}`;
  const repoRes = await fetch(repoUrl, {
    headers: {
      "Accept": "application/vnd.github.v3+json",
      "User-Agent": "KeyGuard-Scanner/1.0",
    },
  });

  if (!repoRes.ok) {
    if (repoRes.status === 404) {
      throw new Error("Repository not found or not public.");
    }
    throw new Error(`GitHub API error: ${repoRes.status} ${repoRes.statusText}`);
  }

  const repoData = await repoRes.json() as { default_branch: string };
  const defaultBranch = repoData.default_branch || "main";

  const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`;
  const treeRes = await fetch(treeUrl, {
    headers: {
      "Accept": "application/vnd.github.v3+json",
      "User-Agent": "KeyGuard-Scanner/1.0",
    },
  });

  if (!treeRes.ok) {
    throw new Error(`GitHub API error: ${treeRes.status} ${treeRes.statusText}`);
  }

  const treeData = await treeRes.json() as { tree: Array<{ path: string; type: string; size?: number }>; truncated: boolean };
  const textFiles = treeData.tree.filter(item => {
    if (item.type !== "blob") return false;
    if (shouldSkipFile(item.path)) return false;
    if (item.size && item.size > 500_000) return false;
    return true;
  });

  // Scan up to 200 files (increased from 100)
  const filesToScan = textFiles.slice(0, 200);

  const batchSize = 10;
  for (let i = 0; i < filesToScan.length; i += batchSize) {
    const batch = filesToScan.slice(i, i + batchSize);
    const results = await Promise.allSettled(
      batch.map(async (file) => {
        const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}/${file.path}`;
        const res = await fetch(rawUrl, {
          headers: { "User-Agent": "KeyGuard-Scanner/1.0" },
        });
        if (!res.ok) return null;
        const text = await res.text();
        return { path: file.path, content: text };
      })
    );

    for (const result of results) {
      if (result.status === "fulfilled" && result.value) {
        files.push(result.value);
      }
    }
  }

  return files;
}

// ─── Helpers ─────────────────────────────────────────────────────

function deduplicateFindings(findings: KeyFinding[]): KeyFinding[] {
  const seen = new Set<string>();
  const result: KeyFinding[] = [];
  for (const f of findings) {
    const key = `${f.keyType}:${f.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(f);
  }
  return result;
}

// ─── Main scan orchestrator ──────────────────────────────────────

export async function performScan(url: string): Promise<ScanResult> {
  const startTime = Date.now();
  const id = randomUUID();
  const allFindings: KeyFinding[] = [];

  const githubInfo = parseGithubUrl(url);
  const scanType = githubInfo ? "github" : "website";

  // ────────────────────────────────────────────────────────────────
  //  WEBSITE SCAN PATH
  // ────────────────────────────────────────────────────────────────
  if (!githubInfo) {
    try {
      // Phase 1: Multi-page crawl + parallel infra scans
      const [crawlSettled, sensitiveSettled, headerSettled] = await Promise.allSettled([
        crawlWebsite(url),
        probeSensitivePaths(url),
        analyzeHeaders(url),
      ]);

      const crawlResult = crawlSettled.status === "fulfilled" ? crawlSettled.value : null;
      const sensitivePathResult = sensitiveSettled.status === "fulfilled" ? sensitiveSettled.value : null;
      const headerAnalysis = headerSettled.status === "fulfilled" ? headerSettled.value : null;

      if (!crawlResult) {
        return {
          id, url, scanType, status: "error", findings: [],
          filesScanned: 0, scanDuration: Date.now() - startTime,
          error: crawlSettled.status === "rejected" ? crawlSettled.reason?.message : "Crawl failed",
        };
      }

      const files = [...crawlResult.files];
      const pagesScanned = crawlResult.pagesCrawled;

      // Phase 1b: Source map discovery (needs script URLs from crawl)
      let sourceMapResult = null;
      try {
        sourceMapResult = await discoverAndScanSourceMaps(crawlResult.scriptUrls, url);
        if (sourceMapResult.mapsFound > 0) {
          const mapContents = await Promise.allSettled(
            sourceMapResult.exposedFiles.map(f => getSourceMapContent(f.mapUrl))
          );
          for (const mc of mapContents) {
            if (mc.status === "fulfilled" && mc.value) {
              files.push(mc.value);
            }
          }
        }
      } catch (err) {
        console.error("Source map scan error:", err);
      }

      // Add sensitive path content for scanning
      if (sensitivePathResult) {
        files.push(...sensitivePathResult.contentForScanning);
      }

      // Phase 2: Scan all content with all engines
      const jwtFindings = [];
      for (const file of files) {
        allFindings.push(...scanContent(file.content, file.path));
        allFindings.push(...detectHighEntropyStrings(file.content, file.path));
        jwtFindings.push(...detectJWTTokens(file.content, file.path));
      }

      // Bundle analysis
      const bundleResult = analyzeJSBundles(files);
      for (const secret of bundleResult.secretsFound) {
        allFindings.push({
          keyType: `${secret.type}: ${secret.key}`,
          value: secret.value,
          file: secret.file,
          line: secret.line,
          severity: secret.severity,
          source: "bundle",
        });
      }

      // Phase 3: Deduplicate and sort
      const deduped = deduplicateFindings(allFindings);
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      deduped.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

      // Phase 4: Security score
      const spClean = sensitivePathResult
        ? { pathsChecked: sensitivePathResult.pathsChecked, pathsFound: sensitivePathResult.pathsFound }
        : undefined;

      const securityScore = calculateSecurityScore({
        findings: deduped,
        headerAnalysis: headerAnalysis ?? undefined,
        sensitivePathResult: spClean,
        sourceMapResult: sourceMapResult ?? undefined,
        jwtFindings: jwtFindings.length > 0 ? jwtFindings : undefined,
      });

      return {
        id, url, scanType,
        status: "complete",
        findings: deduped,
        filesScanned: files.length,
        scanDuration: Date.now() - startTime,
        securityScore,
        headerAnalysis: headerAnalysis ?? undefined,
        sensitivePathResult: spClean,
        sourceMapResult: sourceMapResult ?? undefined,
        jwtFindings: jwtFindings.length > 0 ? jwtFindings : undefined,
        pagesScanned,
      };
    } catch (error: any) {
      return {
        id, url, scanType, status: "error", findings: [],
        filesScanned: 0, scanDuration: Date.now() - startTime,
        error: error.message || "Failed to scan website",
      };
    }
  }

  // ────────────────────────────────────────────────────────────────
  //  GITHUB SCAN PATH
  // ────────────────────────────────────────────────────────────────
  let files: Array<{ path: string; content: string }>;
  try {
    files = await fetchGithubRepoFiles(githubInfo.owner, githubInfo.repo);
  } catch (error: any) {
    return {
      id, url, scanType, status: "error", findings: [],
      filesScanned: 0, scanDuration: Date.now() - startTime,
      error: error.message || "Failed to fetch repository",
    };
  }

  // Pattern + entropy scan all files
  const jwtFindings = [];
  for (const file of files) {
    allFindings.push(...scanContent(file.content, file.path));
    allFindings.push(...detectHighEntropyStrings(file.content, file.path));
    jwtFindings.push(...detectJWTTokens(file.content, file.path));
  }

  // Bundle analysis
  const bundleResult = analyzeJSBundles(files);
  for (const secret of bundleResult.secretsFound) {
    allFindings.push({
      keyType: `${secret.type}: ${secret.key}`,
      value: secret.value,
      file: secret.file,
      line: secret.line,
      severity: secret.severity,
      source: "bundle",
    });
  }

  // Git commit history scanning (best-effort)
  let gitHistoryFindings: KeyFinding[] = [];
  let commitsScanned = 0;
  try {
    const historyResult = await scanGithubHistory(githubInfo.owner, githubInfo.repo);
    commitsScanned = historyResult.commitsScanned;
    for (const patchFile of historyResult.patchFiles) {
      const patchFindings = scanContent(patchFile.content, patchFile.path);
      for (const f of patchFindings) {
        f.source = "git-history";
      }
      gitHistoryFindings.push(...patchFindings);
    }
  } catch (err) {
    console.error("Git history scan error:", err);
  }

  // Deduplicate and sort
  const allDeduped = deduplicateFindings(allFindings);
  const gitDeduped = deduplicateFindings(gitHistoryFindings);
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allDeduped.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  gitDeduped.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Security score
  const securityScore = calculateSecurityScore({
    findings: [...allDeduped, ...gitDeduped],
    jwtFindings: jwtFindings.length > 0 ? jwtFindings : undefined,
  });

  return {
    id, url, scanType,
    status: "complete",
    findings: allDeduped,
    filesScanned: files.length,
    scanDuration: Date.now() - startTime,
    securityScore,
    jwtFindings: jwtFindings.length > 0 ? jwtFindings : undefined,
    gitHistoryFindings: gitDeduped.length > 0 ? gitDeduped : undefined,
    commitsScanned: commitsScanned > 0 ? commitsScanned : undefined,
  };
}
