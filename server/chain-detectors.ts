import crypto from 'crypto';
import type { Severity } from '../src/types.js';
import { buildPoc, renderPocArtifact, type PocAttempt, type PocRequest, type ValidatedExploit } from './exploit-validation.js';
import { withId, type CrawlResult } from './crawler.js';

/**
 * Multi-request "chain" vulnerability detectors that operate over crawled pages:
 *
 *   - Stored XSS: submit a unique marker via a form, then confirm it renders
 *     unencoded on a subsequent GET (persistence across requests).
 *   - IDOR: given a discovered object reference, confirm a neighbouring object
 *     is readable and is a distinct object (not the same record, not a
 *     not-found page).
 *
 * Both are bounded and produce a re-confirmed, reproducible PoC.
 */

type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal },
) => Promise<{ status: number; headers: { get(name: string): string | null }; text: () => Promise<string> }>;

export interface RedTeamChainFinding {
  testName: string;
  payload: string;
  severity: Severity;
  description: string;
  fix: string;
  rawRequest?: string;
  rawResponse?: string;
  validated?: boolean;
}

export interface ApiChainFinding {
  testName: string;
  severity: Severity;
  description: string;
  fix: string;
  endpoint: string;
  rawRequest: string;
  rawResponse: string;
  validated?: boolean;
}

// ---------------------------------------------------------------------------
// Pure predicates (unit-tested without the network)
// ---------------------------------------------------------------------------

/** True when a stored marker is rendered back unencoded (real persistence). */
export function isStoredReflection(marker: string, html: string): boolean {
  return html.includes(`<script>${marker}</script>`);
}

/** True when a body is a structured object/array (not an HTML soft-404 page). */
export function objectish(body: string): boolean {
  try {
    const v = JSON.parse(body);
    if (!v || typeof v !== 'object') return false;
    return Array.isArray(v) ? v.length > 0 : Object.keys(v).length >= 2;
  } catch {
    return false;
  }
}

export interface IdorProbe {
  status: number;
  body: string;
}

/**
 * IDOR evidence: the neighbouring object is readable (200), is object-shaped,
 * and is a *distinct* record — different from both the caller's own object and
 * from the not-found response (so a uniform 403/404 or echoed shell never fires).
 */
export function isIdorEvidence(own: IdorProbe, sibling: IdorProbe, notFound: IdorProbe): boolean {
  if (own.status !== 200 || sibling.status !== 200) return false;
  if (!objectish(own.body) || !objectish(sibling.body)) return false;
  if (sibling.body === own.body) return false; // same record, not cross-object access
  if (sibling.body === notFound.body) return false; // just the not-found page
  return true;
}

// ---------------------------------------------------------------------------
// Bounded network runners
// ---------------------------------------------------------------------------

const MAX_FORMS = 3;
const MAX_REFS = 3;
const TIMEOUT = 4000;

async function fetchText(
  url: string,
  init: { method?: string; headers?: Record<string, string>; body?: string },
  doFetch: FetchLike,
): Promise<{ status: number; body: string }> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), TIMEOUT);
  try {
    const res = await doFetch(url, { ...init, signal: controller.signal });
    const body = await res.text().catch(() => '');
    return { status: res.status, body };
  } catch {
    return { status: 0, body: '' };
  } finally {
    clearTimeout(id);
  }
}

/** Submit a unique marker through forms and confirm it persists/renders unencoded. */
export async function detectStoredXss(
  crawl: CrawlResult,
  headers: Record<string, string>,
  fetchImpl?: FetchLike,
): Promise<{ findings: RedTeamChainFinding[]; exploits: ValidatedExploit[] }> {
  const doFetch = fetchImpl ?? (fetch as unknown as FetchLike);
  const findings: RedTeamChainFinding[] = [];
  const exploits: ValidatedExploit[] = [];

  const candidates = crawl.forms.filter((f) => f.method === 'POST' && f.fields.length > 0).slice(0, MAX_FORMS);
  const readUrls = uniq([
    ...candidates.map((f) => f.pageUrl),
    ...candidates.map((f) => f.action),
    ...crawl.pages.map((p) => p.url),
  ]).slice(0, 6);

  for (const form of candidates) {
    const marker = `seclayer_stored_${crypto.randomBytes(4).toString('hex')}`;
    const payload = `<script>${marker}</script>`;
    const bodyText = form.fields.map((name) => `${encodeURIComponent(name)}=${encodeURIComponent(payload)}`).join('&');
    const writeHeaders = { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' };

    await fetchText(form.action, { method: 'POST', headers: writeHeaders, body: bodyText }, doFetch);

    // Read back: is the marker rendered unencoded anywhere?
    let evidenceUrl = '';
    let evidenceBody = '';
    for (const readUrl of readUrls) {
      const r = await fetchText(readUrl, { method: 'GET', headers }, doFetch);
      if (isStoredReflection(marker, r.body)) {
        evidenceUrl = readUrl;
        evidenceBody = r.body;
        break;
      }
    }
    if (!evidenceUrl) continue;

    // Re-confirm persistence with a second read.
    const reread = await fetchText(evidenceUrl, { method: 'GET', headers }, doFetch);
    const attempts: PocAttempt[] = [
      { ok: true, status: 200, matched: true },
      { ok: reread.status > 0, status: reread.status, matched: isStoredReflection(marker, reread.body) },
    ];

    const req: PocRequest = {
      method: 'POST',
      url: form.action,
      headers: writeHeaders,
      bodyText,
      payload,
    };
    const exploit = buildPoc({
      vector: 'Stored Cross-Site Scripting (XSS)',
      severity: 'critical',
      endpoint: form.action,
      request: req,
      signal: `Marker written via POST rendered unencoded on GET ${evidenceUrl}`,
      controlAbsent: true,
      responseBody: `GET ${evidenceUrl}\n\n${evidenceBody}`,
      attempts,
    });
    const art = renderPocArtifact(exploit);
    findings.push({
      testName: 'Stored Cross-Site Scripting (XSS)',
      payload,
      severity: 'critical',
      description: `A payload submitted to "${form.action}" was persisted and later rendered unencoded when reading "${evidenceUrl}". Any visitor of that page executes attacker-controlled script in their session — a stored XSS that affects every viewer, not just the attacker.`,
      fix: 'Context-aware output-encode all user-supplied content on render, and apply a strict Content-Security-Policy. Never store-then-echo raw HTML.',
      rawRequest: art.rawRequest,
      rawResponse: art.rawResponse,
      validated: exploit.validationStatus === 'validated',
    });
    exploits.push(exploit);
  }

  return { findings, exploits };
}

/** Walk discovered object references and confirm cross-object (IDOR) access. */
export async function detectIdor(
  crawl: CrawlResult,
  headers: Record<string, string>,
  fetchImpl?: FetchLike,
): Promise<{ findings: ApiChainFinding[]; exploits: ValidatedExploit[] }> {
  const doFetch = fetchImpl ?? (fetch as unknown as FetchLike);
  const findings: ApiChainFinding[] = [];
  const exploits: ValidatedExploit[] = [];

  const refs = crawl.idRefs.slice(0, MAX_REFS);
  for (const ref of refs) {
    const siblingValue = ref.value === 1 ? 2 : ref.value + 1;
    const siblingUrl = withId(ref, siblingValue);
    const notFoundUrl = withId(ref, ref.value + 99991);

    const own = await fetchText(ref.url, { method: 'GET', headers }, doFetch);
    const sibling = await fetchText(siblingUrl, { method: 'GET', headers }, doFetch);
    const notFound = await fetchText(notFoundUrl, { method: 'GET', headers }, doFetch);

    if (!isIdorEvidence(own, sibling, notFound)) continue;

    // Re-confirm the neighbouring object is still readable and distinct.
    const reread = await fetchText(siblingUrl, { method: 'GET', headers }, doFetch);
    const attempts: PocAttempt[] = [
      { ok: true, status: 200, matched: true },
      { ok: reread.status > 0, status: reread.status, matched: isIdorEvidence(own, reread, notFound) },
    ];

    const req: PocRequest = {
      method: 'GET',
      url: siblingUrl,
      headers,
      payload: `Access object id=${siblingValue} while authenticated as the owner of id=${ref.value}`,
    };
    const exploit = buildPoc({
      vector: 'Insecure Direct Object Reference (IDOR)',
      severity: 'critical',
      endpoint: siblingUrl,
      request: req,
      signal: `Object id=${siblingValue} returned a distinct record to a caller scoped to id=${ref.value}`,
      controlAbsent: true,
      responseBody: sibling.body,
      attempts,
    });
    const art = renderPocArtifact(exploit);
    findings.push({
      testName: 'Insecure Direct Object Reference (IDOR)',
      severity: 'critical',
      description: `The endpoint exposes object "${ref.value}" to its owner but also returns a different record for "${siblingValue}" to the same caller, with no authorization boundary. An attacker can enumerate ids to read other users' objects (a horizontal-privilege IDOR chain).`,
      fix: 'Enforce per-object ownership checks on every read: verify the authenticated principal is authorized for the requested object id before returning it.',
      endpoint: siblingUrl,
      rawRequest: art.rawRequest,
      rawResponse: art.rawResponse,
      validated: exploit.validationStatus === 'validated',
    });
    exploits.push(exploit);
  }

  return { findings, exploits };
}

function uniq(arr: string[]): string[] {
  return [...new Set(arr)];
}
