import crypto from 'crypto';
import { isSqlInjectionEvidence } from './scan-calibration.js';
import { buildPoc, renderPocArtifact, type PocAttempt, type PocRequest, type ValidatedExploit } from './exploit-validation.js';
import type { CrawlResult } from './crawler.js';
import type { Severity } from '../src/types.js';

/**
 * Crawl-driven parameter fuzzing.
 *
 * The fixed seed probes only fuzz the homepage's `?id=` / `?q=` parameters. This
 * fuzzer instead tests the inputs the CRAWLER actually discovered — query
 * parameters on linked pages and GET-form fields — so reflected XSS and SQLi are
 * caught on endpoints the seed probes never reach.
 *
 * It is restricted to GET injection points so it never mutates server state, and
 * it reuses the same control-comparison + re-confirmation discipline (no new
 * false-positive surface). Every hit yields a reproducible PoC.
 */

type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; signal?: AbortSignal },
) => Promise<{ status: number; text: () => Promise<string> }>;

export interface InjectionPoint {
  /** URL whose query string carries the parameter (other params preserved). */
  url: string;
  param: string;
}

export interface ParamFinding {
  testName: string;
  payload: string;
  severity: Severity;
  description: string;
  fix: string;
  endpoint?: string;
  rawRequest?: string;
  rawResponse?: string;
  validated?: boolean;
}

const MAX_POINTS = 8;
const TIMEOUT = 4000;

/** True when a unique marker is reflected unencoded in the response. */
export function isReflectedXss(marker: string, body: string): boolean {
  return body.includes(`<script>${marker}</script>`);
}

/** Enumerate GET injection points from crawled pages and GET forms (deduped). */
export function enumerateInjectionPoints(crawl: CrawlResult): InjectionPoint[] {
  const points = new Map<string, InjectionPoint>();
  const add = (url: string, param: string) => {
    try {
      const u = new URL(url);
      const key = `${u.origin}${u.pathname}?${param}`;
      if (!points.has(key)) points.set(key, { url, param });
    } catch {
      /* skip malformed */
    }
  };

  for (const page of crawl.pages) {
    try {
      const u = new URL(page.url);
      for (const [param] of u.searchParams.entries()) add(page.url, param);
    } catch {
      /* skip */
    }
  }
  for (const form of crawl.forms) {
    if (form.method !== 'GET') continue; // GET-only: never mutate state
    for (const field of form.fields) add(form.action, field);
  }

  return [...points.values()].slice(0, MAX_POINTS);
}

/** Build a URL with `param` set to `value`, preserving the other parameters. */
function withParam(url: string, param: string, value: string): string {
  const u = new URL(url);
  u.searchParams.set(param, value);
  return u.toString();
}

async function get(url: string, headers: Record<string, string>, doFetch: FetchLike): Promise<{ status: number; body: string }> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), TIMEOUT);
  try {
    const res = await doFetch(url, { method: 'GET', headers, signal: controller.signal });
    return { status: res.status, body: await res.text().catch(() => '') };
  } catch {
    return { status: 0, body: '' };
  } finally {
    clearTimeout(id);
  }
}

/** Fuzz discovered GET parameters for reflected XSS and SQL injection. */
export async function runParamFuzzing(
  crawl: CrawlResult,
  headers: Record<string, string>,
  fetchImpl?: FetchLike,
): Promise<{ findings: ParamFinding[]; exploits: ValidatedExploit[] }> {
  const doFetch = fetchImpl ?? (fetch as unknown as FetchLike);
  const findings: ParamFinding[] = [];
  const exploits: ValidatedExploit[] = [];

  for (const point of enumerateInjectionPoints(crawl)) {
    // Reflected XSS via the discovered parameter.
    const marker = `xss_disc_${crypto.randomBytes(4).toString('hex')}`;
    const xssUrl = withParam(point.url, point.param, `<script>${marker}</script>`);
    const xss = await get(xssUrl, headers, doFetch);
    if (isReflectedXss(marker, xss.body)) {
      const req: PocRequest = { method: 'GET', url: xssUrl, headers, payload: `<script>${marker}</script>` };
      const reread = await get(xssUrl, headers, doFetch);
      const attempts: PocAttempt[] = [
        { ok: true, status: xss.status, matched: true },
        { ok: reread.status > 0, status: reread.status, matched: isReflectedXss(marker, reread.body) },
      ];
      const exploit = buildPoc({
        vector: 'Reflected XSS (discovered parameter)',
        severity: 'high',
        endpoint: `${new URL(point.url).pathname}?${point.param}`,
        request: req,
        signal: `Unique payload reflected unencoded via crawl-discovered parameter "${point.param}"`,
        controlAbsent: true,
        responseBody: xss.body,
        attempts,
      });
      const art = renderPocArtifact(exploit);
      findings.push({
        testName: 'Reflected XSS (discovered parameter)',
        payload: `<script>${marker}</script>`,
        severity: 'high',
        description: `The crawl-discovered parameter "${point.param}" on "${new URL(point.url).pathname}" reflects input unencoded, enabling reflected Cross-Site Scripting. This endpoint is not covered by the homepage probes; it was reached by crawling the application.`,
        fix: 'Context-aware output-encode reflected parameters and deploy a strict Content-Security-Policy.',
        endpoint: `${new URL(point.url).pathname}?${point.param}`,
        rawRequest: art.rawRequest,
        rawResponse: art.rawResponse,
        validated: exploit.validationStatus === 'validated',
      });
      exploits.push(exploit);
      continue; // one finding per point is enough
    }

    // SQL injection via the discovered parameter (control-relative).
    const control = await get(withParam(point.url, point.param, 'seclayer_ctrl_1'), headers, doFetch);
    const sqlUrl = withParam(point.url, point.param, "' OR 1=1--");
    const sql = await get(sqlUrl, headers, doFetch);
    if (isSqlInjectionEvidence(sql.body, control.body)) {
      const req: PocRequest = { method: 'GET', url: sqlUrl, headers, payload: "' OR 1=1--" };
      const reread = await get(sqlUrl, headers, doFetch);
      const attempts: PocAttempt[] = [
        { ok: true, status: sql.status, matched: true },
        { ok: reread.status > 0, status: reread.status, matched: isSqlInjectionEvidence(reread.body, control.body) },
      ];
      const exploit = buildPoc({
        vector: 'SQL Injection (discovered parameter)',
        severity: 'critical',
        endpoint: `${new URL(point.url).pathname}?${point.param}`,
        request: req,
        signal: `Database error under injection but absent in control, via crawl-discovered parameter "${point.param}"`,
        controlAbsent: true,
        responseBody: sql.body,
        attempts,
      });
      const art = renderPocArtifact(exploit);
      findings.push({
        testName: 'SQL Injection (discovered parameter)',
        payload: "' OR 1=1--",
        severity: 'critical',
        description: `The crawl-discovered parameter "${point.param}" on "${new URL(point.url).pathname}" is vulnerable to SQL injection (database error surfaced under the payload but not a benign control). This endpoint was reached by crawling, not by the homepage probes.`,
        fix: 'Use parameterized queries / prepared statements for every database access. Never concatenate request input into SQL.',
        endpoint: `${new URL(point.url).pathname}?${point.param}`,
        rawRequest: art.rawRequest,
        rawResponse: art.rawResponse,
        validated: exploit.validationStatus === 'validated',
      });
      exploits.push(exploit);
    }
  }

  return { findings, exploits };
}
