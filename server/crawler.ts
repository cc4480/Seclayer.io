// Lightweight, bounded same-origin crawler + parameter discovery. Maps the real
// attack surface (page links, forms, and JS-referenced API endpoints) so the
// active probes can be aimed at parameters the application actually uses,
// instead of only a few hardcoded names. All network I/O is performed through
// an injected fetch (the scanner passes its SSRF-safe fetch), keeping this
// module free of circular dependencies and easy to unit test.
//
// The pure HTML parsing/extraction helpers live in ./crawler/parsing.js and are
// re-exported here so existing importers keep a single entry point.

import {
  InjectableTarget,
  paramsOf,
  extractLinks,
  targetsFromHtml,
  dedupeTargets,
  stripFragment,
} from "./crawler/parsing.js";

export * from "./crawler/parsing.js";

export interface CrawlResult {
  pagesVisited: number;
  pages: string[];
  targets: InjectableTarget[];
}

export interface CrawlOptions {
  maxPages?: number;
  maxDepth?: number;
  perRequestMs?: number;
  budgetMs?: number;
  concurrency?: number;
  seedHtml?: string; // root HTML already fetched by the scanner (avoids a re-fetch)
}

async function fetchWithTimeout(
  fetchFn: (url: string, init: RequestInit) => Promise<Response>,
  url: string,
  timeoutMs: number,
): Promise<Response> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await fetchFn(url, { method: "GET", signal: ctl.signal });
  } finally {
    clearTimeout(id);
  }
}

// Breadth-first, same-origin crawl bounded by page count, depth, and a wall-clock
// budget. Returns the deduped set of injectable targets discovered.
export async function crawlSite(
  rootUrl: string,
  fetchFn: (url: string, init: RequestInit) => Promise<Response>,
  opts: CrawlOptions = {},
): Promise<CrawlResult> {
  const maxPages = opts.maxPages ?? 10;
  const maxDepth = opts.maxDepth ?? 2;
  const perRequestMs = opts.perRequestMs ?? 3500;
  const budgetMs = opts.budgetMs ?? 15000;
  const concurrency = opts.concurrency ?? 3;

  const start = Date.now();
  const visited = new Set<string>();
  const pages: string[] = [];
  const targets: InjectableTarget[] = [];
  const queue: Array<{ url: string; depth: number }> = [{ url: stripFragment(rootUrl), depth: 0 }];

  const ingestHtml = (html: string, url: string, depth: number) => {
    pages.push(url);
    targets.push(...targetsFromHtml(html, url));
    if (depth < maxDepth) {
      for (const link of extractLinks(html, url)) {
        if (!visited.has(stripFragment(link))) queue.push({ url: link, depth: depth + 1 });
      }
    }
  };

  // Seed with the already-fetched root HTML to avoid an extra request.
  if (opts.seedHtml) {
    visited.add(stripFragment(rootUrl));
    ingestHtml(opts.seedHtml, stripFragment(rootUrl), 0);
  }

  while (queue.length && visited.size < maxPages && Date.now() - start < budgetMs) {
    const batch: Array<{ url: string; depth: number }> = [];
    while (queue.length && batch.length < concurrency && visited.size + batch.length < maxPages) {
      const item = queue.shift()!;
      if (visited.has(item.url)) continue;
      visited.add(item.url);
      batch.push(item);
    }
    if (!batch.length) break;

    await Promise.all(
      batch.map(async ({ url, depth }) => {
        try {
          const qp = paramsOf(url);
          if (qp.length) targets.push({ url, method: "GET", params: qp, source: "query" });
          const res = await fetchWithTimeout(fetchFn, url, perRequestMs);
          if (!/text\/html/i.test(res.headers.get("content-type") || "")) return;
          const html = await res.text();
          ingestHtml(html, url, depth);
        } catch {
          /* unreachable/blocked page — skip */
        }
      }),
    );
  }

  return { pagesVisited: pages.length, pages, targets: dedupeTargets(targets) };
}
