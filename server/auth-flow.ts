import type { CrawlResult, DiscoveredForm } from './crawler.js';

/**
 * Form-based login automation.
 *
 * Bearer-token auth requires the operator to extract a token by hand. Most real
 * apps log in through an HTML form and a session cookie. This module finds the
 * login form during the crawl, submits supplied credentials, captures the
 * session cookie, and hands back a `Cookie` header so the rest of the scan
 * (crawl, chain detectors, parameter fuzzing) runs authenticated.
 *
 * Bounded: a single login POST, short timeout. Pure helpers are unit-tested; the
 * network step takes an injectable fetch.
 */

type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal },
) => Promise<{
  status: number;
  headers: { get(name: string): string | null; getSetCookie?: () => string[] };
  text: () => Promise<string>;
}>;

export interface Credentials {
  username: string;
  password: string;
}

export interface LoginForm {
  form: DiscoveredForm;
  userField: string;
  passField: string;
}

const USER_FIELD = /(user|email|login|name|account)/i;
const PASS_FIELD = /(pass|pwd|secret)/i;

/** Locate a POST login form: one with a password-like field and a username-like field. */
export function findLoginForm(crawl: CrawlResult): LoginForm | null {
  for (const form of crawl.forms) {
    if (form.method !== 'POST') continue;
    const passField = form.fields.find((f) => PASS_FIELD.test(f));
    if (!passField) continue;
    const userField = form.fields.find((f) => USER_FIELD.test(f) && f !== passField) ?? form.fields.find((f) => f !== passField);
    if (!userField) continue;
    return { form, userField, passField };
  }
  return null;
}

/** Extract the first `name=value` session cookie pair from a Set-Cookie header value. */
export function parseSessionCookie(setCookie: string | null | undefined): string | null {
  if (!setCookie) return null;
  // Take the first cookie's name=value (before attributes / before the next cookie).
  const firstCookie = setCookie.split(/,(?=[^;]+=[^;]+)/)[0]; // split combined cookies, keep the first
  const pair = firstCookie.split(';')[0].trim();
  if (!/^[^=\s]+=.+$/.test(pair)) return null;
  return pair;
}

/** Read the session cookie from a response, tolerating combined / array Set-Cookie. */
function readSetCookie(res: { headers: { get(name: string): string | null; getSetCookie?: () => string[] } }): string | null {
  const arr = res.headers.getSetCookie?.();
  if (arr && arr.length > 0) return parseSessionCookie(arr.join(', '));
  return parseSessionCookie(res.headers.get('set-cookie'));
}

/**
 * Submit credentials to a discovered login form and return a `Cookie` header
 * value for the established session, or null if no cookie was issued.
 */
export async function establishSession(
  login: LoginForm,
  creds: Credentials,
  headers: Record<string, string>,
  fetchImpl?: FetchLike,
  timeoutMs = 5000,
): Promise<string | null> {
  const doFetch = fetchImpl ?? (fetch as unknown as FetchLike);
  const body = new URLSearchParams({
    [login.userField]: creds.username,
    [login.passField]: creds.password,
  }).toString();

  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await doFetch(login.form.action, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: controller.signal,
    });
    return readSetCookie(res);
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

/** Merge a session cookie into request headers, preserving any existing Cookie. */
export function withCookie(headers: Record<string, string>, cookie: string): Record<string, string> {
  const existing = headers.Cookie || headers.cookie;
  return { ...headers, Cookie: existing ? `${existing}; ${cookie}` : cookie };
}
