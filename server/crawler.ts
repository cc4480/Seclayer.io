/**
 * Bounded, same-origin crawler for multi-page / authenticated-flow coverage.
 *
 * Single-page scanning misses vulnerabilities that span requests — stored XSS
 * (write on page A, render on page B) and IDOR (discover an object reference,
 * then reach a neighbouring object). This crawler discovers the surface those
 * checks operate over.
 *
 * Safety: it only follows links on the SAME origin as the seed (which the route
 * layer has already SSRF-validated), only issues GETs, parses only HTML, and is
 * hard-bounded on page count, depth, and per-request time. The auth header is
 * carried through so authenticated areas are reachable.
 */

type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal },
) => Promise<{ status: number; headers: { get(name: string): string | null }; text: () => Promise<string> }>;

export interface CrawledPage {
  url: string;
  status: number;
  contentType: string;
  html: string;
  depth: number;
}

export interface DiscoveredForm {
  pageUrl: string;
  action: string; // absolute URL
  method: string; // upper-case
  fields: string[];
}

export interface IdReference {
  url: string;
  kind: 'query' | 'path';
  key: string; // query param name, or path segment index as a string
  value: number;
}

export interface CrawlResult {
  pages: CrawledPage[];
  forms: DiscoveredForm[];
  idRefs: IdReference[];
}

export interface CrawlOptions {
  maxPages?: number;
  maxDepth?: number;
  timeoutMs?: number;
  headers?: Record<string, string>;
  fetchImpl?: FetchLike;
}

const DEFAULTS = { maxPages: 8, maxDepth: 2, timeoutMs: 3000 };

/** Resolve an href against a base and return it only if it is on the same origin. */
export function sameOriginUrl(href: string, baseUrl: string): string | null {
  try {
    const base = new URL(baseUrl);
    const u = new URL(href, base);
    if (u.origin !== base.origin) return null;
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    u.hash = '';
    return u.toString();
  } catch {
    return null;
  }
}

/** Extract same-origin anchor links from an HTML page (deduped, fragment-free). */
export function extractLinks(html: string, baseUrl: string): string[] {
  const out = new Set<string>();
  const re = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const abs = sameOriginUrl(m[1], baseUrl);
    if (abs) out.add(abs);
  }
  return [...out];
}

/** Extract forms with absolute action URLs and their input/textarea field names. */
export function extractForms(html: string, baseUrl: string): DiscoveredForm[] {
  const forms: DiscoveredForm[] = [];
  const blockRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let block: RegExpExecArray | null;
  while ((block = blockRe.exec(html)) !== null) {
    const attrs = block[1] || '';
    const inner = block[2] || '';
    const methodMatch = attrs.match(/method\s*=\s*["']?\s*(get|post)/i);
    const method = (methodMatch ? methodMatch[1] : 'GET').toUpperCase();
    const actionMatch = attrs.match(/action\s*=\s*["']([^"']*)["']/i);
    const action = sameOriginUrl(actionMatch ? actionMatch[1] : baseUrl, baseUrl) || baseUrl;

    const fields = new Set<string>();
    const fieldRe = /<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi;
    let fm: RegExpExecArray | null;
    while ((fm = fieldRe.exec(inner)) !== null) fields.add(fm[1]);

    forms.push({ pageUrl: baseUrl, action, method, fields: [...fields] });
  }
  return forms;
}

/** Identify numeric object references (query `?id=N` or a numeric path segment). */
export function extractIdRefs(url: string): IdReference[] {
  const refs: IdReference[] = [];
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return refs;
  }
  // Query params that look like object ids.
  for (const [key, value] of u.searchParams.entries()) {
    if (/(^id$|_id$|^.*id$|num|no)$/i.test(key) && /^\d+$/.test(value)) {
      refs.push({ url, kind: 'query', key, value: Number(value) });
    }
  }
  // A numeric path segment (e.g. /api/orders/1).
  const segs = u.pathname.split('/').filter(Boolean);
  for (let i = 0; i < segs.length; i++) {
    if (/^\d+$/.test(segs[i])) {
      refs.push({ url, kind: 'path', key: String(i), value: Number(segs[i]) });
    }
  }
  return refs;
}

/** Replace the numeric id in a reference with a different value, producing a sibling URL. */
export function withId(ref: IdReference, newValue: number): string {
  const u = new URL(ref.url);
  if (ref.kind === 'query') {
    u.searchParams.set(ref.key, String(newValue));
  } else {
    const segs = u.pathname.split('/');
    // path index counts non-empty segments; map back to the raw split index.
    let nonEmpty = -1;
    for (let i = 0; i < segs.length; i++) {
      if (segs[i] === '') continue;
      nonEmpty++;
      if (String(nonEmpty) === ref.key) {
        segs[i] = String(newValue);
        break;
      }
    }
    u.pathname = segs.join('/');
  }
  return u.toString();
}

/** Bounded breadth-first crawl from the seed URL. */
export async function crawl(seedUrl: string, opts: CrawlOptions = {}): Promise<CrawlResult> {
  const maxPages = opts.maxPages ?? DEFAULTS.maxPages;
  const maxDepth = opts.maxDepth ?? DEFAULTS.maxDepth;
  const timeoutMs = opts.timeoutMs ?? DEFAULTS.timeoutMs;
  const headers = opts.headers ?? {};
  const doFetch = (opts.fetchImpl ?? (fetch as unknown as FetchLike));

  const pages: CrawledPage[] = [];
  const forms: DiscoveredForm[] = [];
  const idRefs: IdReference[] = [];
  const seen = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = [{ url: seedUrl, depth: 0 }];
  seen.add(sameOriginUrl(seedUrl, seedUrl) || seedUrl);

  while (queue.length > 0 && pages.length < maxPages) {
    const { url, depth } = queue.shift()!;
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await doFetch(url, { method: 'GET', headers, signal: controller.signal });
      const contentType = res.headers.get('content-type') || '';
      const html = /html/i.test(contentType) ? await res.text() : '';
      pages.push({ url, status: res.status, contentType, html, depth });

      for (const ref of extractIdRefs(url)) idRefs.push(ref);

      if (html && depth < maxDepth) {
        for (const f of extractForms(html, url)) forms.push(f);
        for (const link of extractLinks(html, url)) {
          for (const ref of extractIdRefs(link)) idRefs.push(ref);
          if (!seen.has(link) && seen.size < maxPages * 4) {
            seen.add(link);
            queue.push({ url: link, depth: depth + 1 });
          }
        }
      }
    } catch {
      /* Unreachable/slow page; skip it. */
    } finally {
      clearTimeout(id);
    }
  }

  return { pages, forms, idRefs: dedupeRefs(idRefs) };
}

function dedupeRefs(refs: IdReference[]): IdReference[] {
  const seen = new Set<string>();
  const out: IdReference[] = [];
  for (const r of refs) {
    const k = `${r.kind}:${r.key}:${r.value}:${r.url}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push(r);
    }
  }
  return out;
}
