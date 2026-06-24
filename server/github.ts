const GITHUB_API = 'https://api.github.com';
const TEXT_FILE_RE = /\.(ts|tsx|js|jsx|mjs|cjs|py|rb|go|java|php|json|yml|yaml|env|conf|toml|md|html|css)$/i;
const EXCLUDED_PATH_RE = /(^|\/)(node_modules|\.git|dist|build|vendor)\//;

function encodePath(filePath: string): string {
  return filePath.split('/').map(encodeURIComponent).join('/');
}

async function ghFetch(token: string, path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${GITHUB_API}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(init?.headers || {}),
    },
  });
}

export async function validateRepoAccess(
  token: string,
  repoFullName: string,
): Promise<{ ok: true; defaultBranch: string } | { ok: false; error: string }> {
  const res = await ghFetch(token, `/repos/${repoFullName}`);
  if (!res.ok) {
    return {
      ok: false,
      error: res.status === 404
        ? 'Repository not found, or this token does not have access to it.'
        : `GitHub returned HTTP ${res.status} while checking repo access.`,
    };
  }
  const data = await res.json();
  return { ok: true, defaultBranch: data.default_branch };
}

/** Flat list of text-file paths in the repo, filtered to plausible patch targets. */
export async function getRepoTree(token: string, repoFullName: string, branch: string): Promise<string[]> {
  const res = await ghFetch(token, `/repos/${repoFullName}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  if (!res.ok) throw new Error(`Failed to read repository file tree (HTTP ${res.status}).`);
  const data = await res.json();
  return (data.tree || [])
    .filter((e: any) => e.type === 'blob' && TEXT_FILE_RE.test(e.path) && !EXCLUDED_PATH_RE.test(e.path))
    .map((e: any) => e.path as string)
    .slice(0, 800);
}

export async function getFileContent(
  token: string,
  repoFullName: string,
  filePath: string,
  ref: string,
): Promise<{ content: string; sha: string } | null> {
  const res = await ghFetch(token, `/repos/${repoFullName}/contents/${encodePath(filePath)}?ref=${encodeURIComponent(ref)}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Failed to read file "${filePath}" (HTTP ${res.status}).`);
  const data = await res.json();
  if (Array.isArray(data) || data.type !== 'file' || typeof data.content !== 'string') return null;
  return { content: Buffer.from(data.content, 'base64').toString('utf-8'), sha: data.sha };
}

export async function getBranchSha(token: string, repoFullName: string, branch: string): Promise<string> {
  const res = await ghFetch(token, `/repos/${repoFullName}/git/ref/heads/${encodeURIComponent(branch)}`);
  if (!res.ok) throw new Error(`Failed to resolve branch "${branch}" (HTTP ${res.status}).`);
  const data = await res.json();
  return data.object.sha;
}

/** Idempotent — treats "branch already exists" (422) as success. */
export async function createBranch(token: string, repoFullName: string, newBranch: string, fromSha: string): Promise<void> {
  const res = await ghFetch(token, `/repos/${repoFullName}/git/refs`, {
    method: 'POST',
    body: JSON.stringify({ ref: `refs/heads/${newBranch}`, sha: fromSha }),
  });
  if (!res.ok && res.status !== 422) {
    throw new Error(`Failed to create branch "${newBranch}" (HTTP ${res.status}).`);
  }
}

export async function upsertFile(
  token: string,
  repoFullName: string,
  filePath: string,
  content: string,
  message: string,
  branch: string,
  sha?: string,
): Promise<void> {
  const res = await ghFetch(token, `/repos/${repoFullName}/contents/${encodePath(filePath)}`, {
    method: 'PUT',
    body: JSON.stringify({
      message,
      content: Buffer.from(content, 'utf-8').toString('base64'),
      branch,
      ...(sha ? { sha } : {}),
    }),
  });
  if (!res.ok) throw new Error(`Failed to commit "${filePath}" (HTTP ${res.status}).`);
}

export async function createPullRequest(
  token: string,
  repoFullName: string,
  title: string,
  body: string,
  head: string,
  base: string,
): Promise<{ url: string; number: number }> {
  const res = await ghFetch(token, `/repos/${repoFullName}/pulls`, {
    method: 'POST',
    body: JSON.stringify({ title, body, head, base }),
  });
  if (!res.ok) throw new Error(`Failed to open pull request (HTTP ${res.status}).`);
  const data = await res.json();
  return { url: data.html_url, number: data.number };
}
