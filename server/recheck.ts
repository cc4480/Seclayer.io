import { Finding } from '../src/types.js';
import { runDiagnostics, compileStaticFindings } from './scanner.js';
import { runCrawl } from './crawler.js';

/** Significant lowercase word tokens (drops short/common words). */
function tokens(s: string): Set<string> {
  return new Set(
    (s || '')
      .toLowerCase()
      .replace(/[^a-z0-9 ]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 3),
  );
}

/** Token-overlap ratio against the smaller token set (0..1). */
function overlap(a: string, b: string): number {
  const A = tokens(a);
  const B = tokens(b);
  if (!A.size || !B.size) return 0;
  let inter = 0;
  for (const t of A) if (B.has(t)) inter++;
  return inter / Math.min(A.size, B.size);
}

/**
 * A stored finding (possibly AI-reworded) "matches" a freshly-detected one when
 * they share a category and the titles overlap, or they point at the same
 * endpoint. Bridges the gap between AI-rewritten titles and deterministic
 * scanner/crawler titles.
 */
function matches(stored: Finding, fresh: Finding): boolean {
  const sameCat = (stored.category || '').toUpperCase() === (fresh.category || '').toUpperCase();
  if (stored.endpoint && fresh.endpoint && stored.endpoint === fresh.endpoint) return true;
  if (sameCat && overlap(stored.title, fresh.title) >= 0.4) return true;
  // Fall back to description overlap for AI-reworded titles in the same category
  if (sameCat && overlap(stored.title + ' ' + stored.description, fresh.title) >= 0.5) return true;
  return false;
}

export interface RecheckResult {
  stillPresent: boolean;
  detail: string;
  checkedAt: string;
}

/**
 * Re-run the real scan pipeline (diagnostics + static analysis + deep crawl)
 * against the target and determine whether the given finding is still present.
 * This is a genuine re-test — no probe is faked.
 */
export async function recheckFinding(url: string, finding: Finding, authHeader?: string): Promise<RecheckResult> {
  const checkedAt = new Date().toISOString();
  try {
    const diagnostics = await runDiagnostics(url, authHeader);
    const compiled = compileStaticFindings(diagnostics);
    const crawl = await runCrawl(url, { authHeader });
    const fresh: Finding[] = [...compiled.findings, ...crawl.findings];

    const hit = fresh.find(f => matches(finding, f));
    if (hit) {
      return {
        stillPresent: true,
        detail: `Re-test still detects this issue (matched "${hit.title}"). The fix is not yet effective at ${url}.`,
        checkedAt,
      };
    }
    return {
      stillPresent: false,
      detail: `Re-test no longer detects this issue at ${url}. Marked as verified.`,
      checkedAt,
    };
  } catch (err: any) {
    throw new Error(`Re-check failed: ${err?.message || 'target unreachable'}`);
  }
}
