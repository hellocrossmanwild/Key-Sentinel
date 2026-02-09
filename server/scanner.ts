import type { KeyFinding, ScanResult } from "@shared/schema";
import { randomUUID } from "crypto";

interface KeyPattern {
  name: string;
  pattern: RegExp;
  severity: KeyFinding["severity"];
}

const KEY_PATTERNS: KeyPattern[] = [
  { name: "AWS Access Key ID", pattern: /(?:^|[^A-Za-z0-9/+=])((?: |=|"|'|`)?(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?:[^A-Za-z0-9/+=]|$)/g, severity: "critical" },
  { name: "AWS Secret Access Key", pattern: /(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi, severity: "critical" },
  { name: "Stripe Secret Key", pattern: /(sk_live_[A-Za-z0-9]{20,})/g, severity: "critical" },
  { name: "Stripe Publishable Key", pattern: /(pk_live_[A-Za-z0-9]{20,})/g, severity: "medium" },
  { name: "Stripe Test Secret Key", pattern: /(sk_test_[A-Za-z0-9]{20,})/g, severity: "low" },
  { name: "OpenAI API Key", pattern: /(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})/g, severity: "critical" },
  { name: "OpenAI API Key (proj)", pattern: /(sk-proj-[A-Za-z0-9_-]{40,})/g, severity: "critical" },
  { name: "GitHub Token (Classic)", pattern: /(ghp_[A-Za-z0-9]{36,})/g, severity: "critical" },
  { name: "GitHub Token (Fine-grained)", pattern: /(github_pat_[A-Za-z0-9_]{22,})/g, severity: "critical" },
  { name: "GitHub OAuth Token", pattern: /(gho_[A-Za-z0-9]{36,})/g, severity: "high" },
  { name: "Google API Key", pattern: /(AIza[0-9A-Za-z\-_]{35})/g, severity: "high" },
  { name: "Google OAuth Client Secret", pattern: /client_secret["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{24,})["']?/gi, severity: "high" },
  { name: "Firebase Config", pattern: /apiKey["']?\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi, severity: "high" },
  { name: "Slack Bot Token", pattern: /(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})/g, severity: "critical" },
  { name: "Slack Webhook URL", pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)/g, severity: "high" },
  { name: "Twilio API Key", pattern: /(SK[0-9a-f]{32})/g, severity: "high" },
  { name: "Twilio Auth Token", pattern: /twilio.*auth.*token["']?\s*[:=]\s*["']?([0-9a-f]{32})["']?/gi, severity: "critical" },
  { name: "SendGrid API Key", pattern: /(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})/g, severity: "critical" },
  { name: "Mailgun API Key", pattern: /(key-[0-9a-z]{32})/g, severity: "high" },
  { name: "Heroku API Key", pattern: /heroku.*api.*key["']?\s*[:=]\s*["']?([0-9a-f-]{36})["']?/gi, severity: "high" },
  { name: "Private Key", pattern: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g, severity: "critical" },
  { name: "Supabase Key", pattern: /(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,})/g, severity: "high" },
  { name: "Discord Bot Token", pattern: /([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})/g, severity: "critical" },
  { name: "Telegram Bot Token", pattern: /(\d{8,10}:[A-Za-z0-9_-]{35})/g, severity: "high" },
  { name: "Shopify Access Token", pattern: /(shpat_[A-Fa-f0-9]{32})/g, severity: "critical" },
  { name: "Shopify Shared Secret", pattern: /(shpss_[A-Fa-f0-9]{32})/g, severity: "critical" },
  { name: "Cloudflare API Key", pattern: /cloudflare.*api.*key["']?\s*[:=]\s*["']?([0-9a-f]{37})["']?/gi, severity: "high" },
  { name: "DigitalOcean Token", pattern: /(dop_v1_[a-f0-9]{64})/g, severity: "critical" },
  { name: "npm Token", pattern: /(npm_[A-Za-z0-9]{36})/g, severity: "high" },
  { name: "PyPI Token", pattern: /(pypi-[A-Za-z0-9_-]{50,})/g, severity: "high" },
  { name: "Database Connection String", pattern: /((?:mongodb\+srv|mongodb|postgres|postgresql|mysql|redis):\/\/[^\s"'`<>{}|\\^]+:[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+)/g, severity: "critical" },
  { name: "Generic API Key", pattern: /(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?/gi, severity: "medium" },
  { name: "Generic Secret", pattern: /(?:secret|password|passwd|pwd)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-!@#$%^&*]{8,})["']?/gi, severity: "medium" },
];

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf",
  ".eot", ".otf", ".mp3", ".mp4", ".avi", ".mov", ".webm", ".ogg", ".wav",
  ".zip", ".tar", ".gz", ".rar", ".7z", ".pdf", ".doc", ".docx", ".xls",
  ".xlsx", ".ppt", ".pptx", ".exe", ".dll", ".so", ".dylib", ".pyc",
  ".class", ".o", ".obj", ".lock", ".min.js", ".min.css", ".map",
]);

function shouldSkipFile(filename: string): boolean {
  const lower = filename.toLowerCase();
  for (const ext of BINARY_EXTENSIONS) {
    if (lower.endsWith(ext)) return true;
  }
  if (lower.includes("node_modules/") || lower.includes("vendor/") || lower.includes(".git/")) return true;
  return false;
}

export function scanContent(content: string, filename: string): KeyFinding[] {
  const findings: KeyFinding[] = [];
  const seen = new Set<string>();

  const lines = content.split("\n");

  for (const keyPattern of KEY_PATTERNS) {
    const regex = new RegExp(keyPattern.pattern.source, keyPattern.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const value = match[1] || match[0];
      const trimmedValue = value.replace(/^[\s="'`]+|[\s"'`]+$/g, "");

      if (trimmedValue.length < 8) continue;
      if (/^[a-z_]+$/i.test(trimmedValue)) continue;
      if (/^(example|test|demo|sample|placeholder|your[_-])/i.test(trimmedValue)) continue;
      if (/^x{4,}$/i.test(trimmedValue) || /^\*+$/.test(trimmedValue)) continue;
      if (/^[0]+$/.test(trimmedValue) || /^[1]+$/.test(trimmedValue)) continue;
      if (/^\$[A-Z_]+$/i.test(trimmedValue)) continue;
      if (/^\$\{[^}]+\}$/.test(trimmedValue)) continue;

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
      });
    }
  }

  return findings;
}

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

  const treeData = await treeRes.json() as { tree: Array<{ path: string; type: string; size?: number }>, truncated: boolean };
  const textFiles = treeData.tree.filter(item => {
    if (item.type !== "blob") return false;
    if (shouldSkipFile(item.path)) return false;
    if (item.size && item.size > 500_000) return false;
    return true;
  });

  const filesToScan = textFiles.slice(0, 100);

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

async function fetchWebsiteContent(url: string): Promise<Array<{ path: string; content: string }>> {
  const files: Array<{ path: string; content: string }> = [];

  const res = await fetch(url, {
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; KeyGuard-Scanner/1.0)",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    redirect: "follow",
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch URL: ${res.status} ${res.statusText}`);
  }

  const html = await res.text();
  files.push({ path: url, content: html });

  const { load } = await import("cheerio");
  const $ = load(html);

  const scriptUrls: string[] = [];
  $("script[src]").each((_, el) => {
    const src = $(el).attr("src");
    if (src) {
      try {
        const absoluteUrl = new URL(src, url).href;
        scriptUrls.push(absoluteUrl);
      } catch {}
    }
  });

  const linkUrls: string[] = [];
  $("link[href]").each((_, el) => {
    const href = $(el).attr("href");
    const rel = $(el).attr("rel");
    if (href && (rel === "stylesheet" || href.endsWith(".css"))) {
      try {
        const absoluteUrl = new URL(href, url).href;
        linkUrls.push(absoluteUrl);
      } catch {}
    }
  });

  const inlineScripts: string[] = [];
  $("script:not([src])").each((_, el) => {
    const content = $(el).html();
    if (content && content.trim()) {
      inlineScripts.push(content);
    }
  });

  inlineScripts.forEach((script, i) => {
    files.push({ path: `inline-script-${i + 1}`, content: script });
  });

  const allExternalUrls = [...scriptUrls.slice(0, 15), ...linkUrls.slice(0, 5)];

  const batchSize = 5;
  for (let i = 0; i < allExternalUrls.length; i += batchSize) {
    const batch = allExternalUrls.slice(i, i + batchSize);
    const results = await Promise.allSettled(
      batch.map(async (fileUrl) => {
        try {
          const fileRes = await fetch(fileUrl, {
            headers: { "User-Agent": "Mozilla/5.0 (compatible; KeyGuard-Scanner/1.0)" },
            redirect: "follow",
          });
          if (!fileRes.ok) return null;
          const contentType = fileRes.headers.get("content-type") || "";
          if (contentType.includes("image") || contentType.includes("font") || contentType.includes("video")) return null;
          const text = await fileRes.text();
          if (text.length > 2_000_000) return null;
          return { path: fileUrl, content: text };
        } catch {
          return null;
        }
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

export async function performScan(url: string): Promise<ScanResult> {
  const startTime = Date.now();
  const id = randomUUID();
  const allFindings: KeyFinding[] = [];

  const githubInfo = parseGithubUrl(url);
  const scanType = githubInfo ? "github" : "website";

  let files: Array<{ path: string; content: string }>;

  try {
    if (githubInfo) {
      files = await fetchGithubRepoFiles(githubInfo.owner, githubInfo.repo);
    } else {
      files = await fetchWebsiteContent(url);
    }
  } catch (error: any) {
    return {
      id,
      url,
      scanType,
      status: "error",
      findings: [],
      filesScanned: 0,
      scanDuration: Date.now() - startTime,
      error: error.message || "Failed to fetch content",
    };
  }

  for (const file of files) {
    const findings = scanContent(file.content, file.path);
    allFindings.push(...findings);
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return {
    id,
    url,
    scanType,
    status: "complete",
    findings: allFindings,
    filesScanned: files.length,
    scanDuration: Date.now() - startTime,
  };
}
