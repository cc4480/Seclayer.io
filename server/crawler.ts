import { Finding, CrawlResult, CrawlPage, CrawlForm } from '../src/types.js';
import { canonical, extractLinks, extractResources, extractTitle, extractForms } from './crawler/html-parsing.js';
import { deriveFindings } from './crawler/derive-findings.js';

// Defense-in-depth: the scan endpoint already validates the target, but the
// crawler discovers new URLs at runtime, so re-check every host it follows.
const PRIVATE_IP_RE = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|0\.0\.0\.0)/i;

interface CrawlOptions {
  authHeader?: string;
  maxPages?: number;
  maxDepth?: number;
  concurrency?: number;
  budgetMs?: number;
  onLog?: (msg: string) => void;
  /** Test-only escape hatch to crawl loopback fixture servers. Never set in production. */
  allowPrivateHosts?: boolean;
}

const USER_AGENT = 'Seclayer-Security-Scanner/2.0 (seclayer.io; scanner@seclayer.io)';

/**
 * Same-origin authenticated crawler. Bounded BFS that builds a site map and
 * harvests forms + parameterized endpoints, then derives business-logic
 * findings (insecure credential forms, missing CSRF, mixed content, IDOR-style
 * object references) from the real evidence it gathered.
 */
export async function runCrawl(targetUrl: string, opts: CrawlOptions = {}): Promise<{ result: CrawlResult; findings: Finding[] }> {
  const maxPages = opts.maxPages ?? 25;
  const maxDepth = opts.maxDepth ?? 3;
  const concurrency = opts.concurrency ?? 5;
  const budgetMs = opts.budgetMs ?? 45000;
  const log = opts.onLog ?? (() => {});
  const startedAt = Date.now();

  let start: URL;
  try {
    start = new URL(/^https?:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`);
  } catch {
    const empty: CrawlResult = { startUrl: targetUrl, pagesCrawled: 0, maxDepthReached: 0, durationMs: 0, authenticated: false, pages: [], forms: [], discoveredParams: [] };
    return { result: empty, findings: [] };
  }

  const origin = start.origin;
  const visited = new Set<string>();
  const pages: CrawlPage[] = [];
  const forms: CrawlForm[] = [];
  const params = new Set<string>();
  const idEndpoints = new Set<string>();
  const mixedContent = new Set<string>();
  let maxDepthReached = 0;

  const sameOrigin = (u: URL) => u.origin === origin && (opts.allowPrivateHosts || !PRIVATE_IP_RE.test(u.hostname));

  const reqHeaders: Record<string, string> = { 'User-Agent': USER_AGENT, Accept: 'text/html,application/xhtml+xml,*/*;q=0.8' };
  if (opts.authHeader) reqHeaders['Authorization'] = opts.authHeader;

  // Numeric / object-reference detection in discovered URLs (IDOR/BOLA signal)
  const recordObjectRefs = (u: URL) => {
    for (const [k, v] of u.searchParams) {
      params.add(k);
      if (/^\d{1,12}$/.test(v) && /(^|_|-)(id|uid|user|account|order|invoice|doc|file|num)s?$/i.test(k)) {
        idEndpoints.add(`${u.pathname}?${k}=${v}`);
      }
    }
    // /users/123, /invoice/45, /api/orders/9
    if (/\/(users?|accounts?|orders?|invoices?|documents?|files?|profiles?|tickets?)\/\d{1,12}(\/|$)/i.test(u.pathname)) {
      idEndpoints.add(u.pathname);
    }
  };

  let queue: Array<{ url: URL; depth: number }> = [{ url: start, depth: 0 }];
  visited.add(canonical(start));

  const fetchPage = async (item: { url: URL; depth: number }): Promise<Array<{ url: URL; depth: number }>> => {
    const next: Array<{ url: URL; depth: number }> = [];
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 6000);
    try {
      const res = await fetch(item.url.href, { method: 'GET', headers: reqHeaders, redirect: 'follow', signal: controller.signal });
      const ct = res.headers.get('content-type') || '';
      const page: CrawlPage = { url: item.url.href, status: res.status, depth: item.depth, contentType: ct.split(';')[0] || undefined };
      maxDepthReached = Math.max(maxDepthReached, item.depth);

      if (!ct.includes('html')) { pages.push(page); return next; }

      const html = (await res.text().catch(() => '')).slice(0, 600000); // cap parse size
      page.title = extractTitle(html);
      pages.push(page);

      for (const f of extractForms(html, item.url)) forms.push(f);

      // Mixed content: secure page pulling insecure resources
      if (item.url.protocol === 'https:') {
        for (const r of extractResources(html, item.url)) {
          if (r.protocol === 'http:') mixedContent.add(r.origin + r.pathname);
        }
      }

      if (item.depth < maxDepth) {
        for (const link of extractLinks(html, item.url)) {
          if (!sameOrigin(link)) continue;
          recordObjectRefs(link);
          const key = canonical(link);
          if (visited.has(key)) continue;
          // Skip obvious binary/asset endpoints from the BFS frontier
          if (/\.(png|jpe?g|gif|svg|ico|css|js|woff2?|ttf|map|pdf|zip|mp4|webp)(\?|$)/i.test(link.pathname)) continue;
          visited.add(key);
          next.push({ url: link, depth: item.depth + 1 });
        }
      }
    } catch {
      pages.push({ url: item.url.href, status: 0, depth: item.depth });
    } finally {
      clearTimeout(t);
    }
    return next;
  };

  // Level-by-level BFS with a bounded concurrency pool and a global time budget.
  while (queue.length > 0 && pages.length < maxPages && Date.now() - startedAt < budgetMs) {
    const batch = queue.splice(0, Math.min(concurrency, maxPages - pages.length));
    const results = await Promise.all(batch.map(fetchPage));
    const discovered = results.flat();
    queue = queue.concat(discovered);
  }

  const result: CrawlResult = {
    startUrl: start.href,
    pagesCrawled: pages.length,
    maxDepthReached,
    durationMs: Date.now() - startedAt,
    authenticated: !!opts.authHeader,
    pages,
    forms,
    discoveredParams: [...params].sort(),
  };

  log(`[CRAWL] Mapped ${pages.length} page(s), ${forms.length} form(s), ${params.size} unique parameter(s)`);

  return { result, findings: deriveFindings(result, [...idEndpoints], [...mixedContent], start) };
}
