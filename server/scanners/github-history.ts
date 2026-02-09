/**
 * Scans GitHub commit history for secrets that may have been committed
 * and subsequently "deleted" -- secrets that still live in git history.
 */

export interface GitHistoryFinding {
  commitSha: string;
  commitMessage: string;
  commitDate: string;
  author: string;
  file: string;
  patch: string; // The diff content (truncated)
  severity: "critical" | "high" | "medium" | "low";
  keyType: string;
  value: string;
  isDeleted: boolean; // Was this in a deletion (line starts with -)
}

export interface GitHistoryResult {
  commitsScanned: number;
  patchFiles: Array<{ path: string; content: string }>; // patch content for scanning
  commitInfo: Array<{
    sha: string;
    message: string;
    date: string;
    author: string;
  }>;
}

const GITHUB_API_BASE = "https://api.github.com";
const USER_AGENT = "KeyGuard-Scanner/1.0";
const ACCEPT_HEADER = "application/vnd.github.v3+json";
const COMMITS_PER_PAGE = 30;
const COMMIT_BATCH_SIZE = 5;
const MAX_PATCH_SIZE_BYTES = 100 * 1024; // 100 KB per commit

/**
 * Internal state for tracking rate-limit status across requests.
 */
interface RateLimitState {
  remaining: number | null;
  isLimited: boolean;
}

/**
 * Execute a GET request against the GitHub API, respecting rate limits.
 * Returns the parsed JSON body or null if the request fails or is rate-limited.
 */
async function githubApiFetch<T>(
  url: string,
  rateLimitState: RateLimitState,
): Promise<T | null> {
  if (rateLimitState.isLimited) return null;

  try {
    const res = await fetch(url, {
      headers: {
        "User-Agent": USER_AGENT,
        "Accept": ACCEPT_HEADER,
      },
    });

    // Update rate-limit tracking from response headers
    const remainingHeader = res.headers.get("X-RateLimit-Remaining");
    if (remainingHeader !== null) {
      rateLimitState.remaining = parseInt(remainingHeader, 10);
      if (rateLimitState.remaining <= 0) {
        rateLimitState.isLimited = true;
      }
    }

    if (res.status === 403 || res.status === 429) {
      rateLimitState.isLimited = true;
      return null;
    }

    if (!res.ok) return null;

    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/**
 * Represents a single commit from the GitHub list-commits endpoint.
 */
interface GitHubCommitListItem {
  sha: string;
  commit: {
    message: string;
    author: {
      name: string;
      date: string;
    };
  };
  parents: Array<{ sha: string }>;
}

/**
 * Represents the detailed commit response including file patches.
 */
interface GitHubCommitDetail {
  sha: string;
  commit: {
    message: string;
    author: {
      name: string;
      date: string;
    };
  };
  files?: Array<{
    filename: string;
    status: string;
    patch?: string;
    changes: number;
  }>;
}

/**
 * Represents a file entry from the GitHub contents API.
 */
interface GitHubContentEntry {
  name: string;
  path: string;
  type: string;
  download_url: string | null;
  size: number;
}

/**
 * Run an array of async tasks in batches of a given concurrency limit.
 */
async function batchProcess<T, R>(
  items: T[],
  concurrency: number,
  processor: (item: T) => Promise<R>,
): Promise<Array<{ status: "fulfilled"; value: R } | { status: "rejected"; reason: unknown }>> {
  const allResults: Array<
    { status: "fulfilled"; value: R } | { status: "rejected"; reason: unknown }
  > = [];

  for (let i = 0; i < items.length; i += concurrency) {
    const batch = items.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(batch.map(processor));
    allResults.push(
      ...(batchResults as Array<
        { status: "fulfilled"; value: R } | { status: "rejected"; reason: unknown }
      >),
    );
  }

  return allResults;
}

/**
 * Check whether a commit is a merge commit (has 2+ parents).
 */
function isMergeCommit(commit: GitHubCommitListItem): boolean {
  return commit.parents && commit.parents.length >= 2;
}

/**
 * Check whether all files in a commit detail are binary-only
 * (no patch field present on any file).
 */
function isAllBinaryFiles(detail: GitHubCommitDetail): boolean {
  if (!detail.files || detail.files.length === 0) return true;
  return detail.files.every((f) => !f.patch);
}

/**
 * Scan a GitHub repository's recent commit history for secrets.
 *
 * This function fetches the most recent commits, retrieves the diffs,
 * and returns the patch content as files that can be scanned by the
 * orchestrator's pattern-matching engine.
 *
 * @param owner - GitHub repository owner (user or organization).
 * @param repo  - GitHub repository name.
 * @returns A GitHistoryResult with patch data and commit metadata.
 */
export async function scanGithubHistory(
  owner: string,
  repo: string,
): Promise<GitHistoryResult> {
  const rateLimitState: RateLimitState = {
    remaining: null,
    isLimited: false,
  };

  const patchFiles: Array<{ path: string; content: string }> = [];
  const commitInfo: Array<{
    sha: string;
    message: string;
    date: string;
    author: string;
  }> = [];
  let commitsScanned = 0;

  // --- 1. Fetch the list of recent commits ---
  const commitsUrl =
    `${GITHUB_API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits?per_page=${COMMITS_PER_PAGE}`;

  const commitsList = await githubApiFetch<GitHubCommitListItem[]>(
    commitsUrl,
    rateLimitState,
  );

  if (!commitsList || !Array.isArray(commitsList)) {
    return { commitsScanned: 0, patchFiles: [], commitInfo: [] };
  }

  // Filter out merge commits
  const nonMergeCommits = commitsList.filter((c) => !isMergeCommit(c));

  // --- 2. Fetch detailed diffs for each commit in batches ---
  const batchResults = await batchProcess(
    nonMergeCommits,
    COMMIT_BATCH_SIZE,
    async (commit): Promise<{
      detail: GitHubCommitDetail;
      listItem: GitHubCommitListItem;
    } | null> => {
      if (rateLimitState.isLimited) return null;

      const detailUrl =
        `${GITHUB_API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits/${commit.sha}`;

      const detail = await githubApiFetch<GitHubCommitDetail>(
        detailUrl,
        rateLimitState,
      );

      if (!detail) return null;
      return { detail, listItem: commit };
    },
  );

  for (const result of batchResults) {
    if (rateLimitState.isLimited) break;
    if (result.status !== "fulfilled" || !result.value) continue;

    const { detail, listItem } = result.value;

    // Skip commits with only binary files
    if (isAllBinaryFiles(detail)) continue;

    const sha = detail.sha;
    const message = detail.commit.message.split("\n")[0]; // First line only
    const date = detail.commit.author.date;
    const author = detail.commit.author.name;

    commitInfo.push({ sha, message, date, author });
    commitsScanned++;

    if (!detail.files) continue;

    // Aggregate patches per commit, respecting size limit
    let commitPatchSize = 0;

    for (const file of detail.files) {
      if (!file.patch) continue; // Binary file, skip

      const patchBytes = new TextEncoder().encode(file.patch).length;
      if (commitPatchSize + patchBytes > MAX_PATCH_SIZE_BYTES) {
        // Skip remaining files for this commit to stay under the limit
        break;
      }
      commitPatchSize += patchBytes;

      // Create a virtual file path for the orchestrator to scan:
      // "git-history/{owner}/{repo}/{sha_short}/{filename}"
      const shortSha = sha.substring(0, 7);
      const virtualPath = `git-history/${owner}/${repo}/${shortSha}/${file.filename}`;

      patchFiles.push({
        path: virtualPath,
        content: file.patch,
      });
    }
  }

  // --- 3. Check GitHub Actions workflow files for hardcoded secrets ---
  if (!rateLimitState.isLimited) {
    await scanWorkflowFiles(owner, repo, rateLimitState, patchFiles);
  }

  return {
    commitsScanned,
    patchFiles,
    commitInfo,
  };
}

/**
 * Scan GitHub Actions workflow files (.github/workflows/) for hardcoded
 * secrets in env: blocks and other common locations.
 */
async function scanWorkflowFiles(
  owner: string,
  repo: string,
  rateLimitState: RateLimitState,
  patchFiles: Array<{ path: string; content: string }>,
): Promise<void> {
  const workflowsUrl =
    `${GITHUB_API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/.github/workflows`;

  const entries = await githubApiFetch<GitHubContentEntry[]>(
    workflowsUrl,
    rateLimitState,
  );

  if (!entries || !Array.isArray(entries)) return;

  // Only scan YAML workflow files
  const yamlFiles = entries.filter(
    (entry) =>
      entry.type === "file" &&
      (entry.name.endsWith(".yml") || entry.name.endsWith(".yaml")) &&
      entry.download_url &&
      entry.size < 500_000, // Skip unreasonably large workflow files
  );

  await batchProcess(
    yamlFiles,
    COMMIT_BATCH_SIZE,
    async (entry) => {
      if (rateLimitState.isLimited || !entry.download_url) return;

      try {
        const res = await fetch(entry.download_url, {
          headers: {
            "User-Agent": USER_AGENT,
          },
        });

        if (!res.ok) return;

        // Check for rate limiting on raw content requests
        const remaining = res.headers.get("X-RateLimit-Remaining");
        if (remaining !== null) {
          const val = parseInt(remaining, 10);
          if (val <= 0) {
            rateLimitState.isLimited = true;
            return;
          }
        }

        const content = await res.text();
        const virtualPath = `github-workflows/${owner}/${repo}/${entry.path}`;

        patchFiles.push({
          path: virtualPath,
          content,
        });
      } catch {
        // Failed to fetch this workflow file; continue with others
      }
    },
  );
}
