import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import type { AddressInfo } from 'net';
import { runCrawl } from '../../server/crawler.js';

// A small fixture site exercised by the crawler. It links several same-origin
// pages, an insecure-looking login form, a CSRF-less POST form, a page with
// numeric object-reference URLs, and an off-site link that must NOT be crawled.
const PAGES: Record<string, string> = {
  '/': `<html><head><title>Home</title></head><body>
    <a href="/login">Login</a>
    <a href="/account?id=42">Your account</a>
    <a href="/orders/108">Order 108</a>
    <a href="/about">About</a>
    <a href="https://evil.example.com/x">offsite</a>
    <img src="logo.png">
  </body></html>`,
  '/login': `<html><head><title>Login</title></head><body>
    <form action="/session" method="post">
      <input name="email" type="text">
      <input name="password" type="password">
    </form>
  </body></html>`,
  '/about': `<html><head><title>About</title></head><body>
    <form action="/subscribe" method="post">
      <input name="email" type="text">
    </form>
    <a href="/account?id=7">acct</a>
  </body></html>`,
  '/account': `<html><head><title>Account</title></head><body>ok</body></html>`,
  '/orders/108': `<html><head><title>Order</title></head><body>order</body></html>`,
};

let server: http.Server;
let base: string;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const path = (req.url || '/').split('#')[0];
    const key = path.split('?')[0];
    const body = PAGES[key];
    if (body == null) { res.statusCode = 404; res.end('nope'); return; }
    res.setHeader('content-type', 'text/html');
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe('runCrawl', () => {
  it('maps multiple same-origin pages and stays on-origin', async () => {
    const { result } = await runCrawl(base, { allowPrivateHosts: true });
    expect(result.pagesCrawled).toBeGreaterThan(1);
    // every crawled page is same-origin — no evil.example.com
    expect(result.pages.every(p => p.url.startsWith(base))).toBe(true);
  });

  it('extracts forms with their fields and method', async () => {
    const { result } = await runCrawl(base, { allowPrivateHosts: true });
    const loginForm = result.forms.find(f => f.action.endsWith('/session'));
    expect(loginForm).toBeDefined();
    expect(loginForm!.method).toBe('POST');
    expect(loginForm!.hasPassword).toBe(true);
    expect(loginForm!.inputs).toContain('password');
  });

  it('derives a CSRF finding for the token-less POST forms', async () => {
    const { findings } = await runCrawl(base, { allowPrivateHosts: true });
    const csrf = findings.find(f => f.title.includes('Anti-CSRF'));
    expect(csrf).toBeDefined();
    expect(csrf!.severity).toBe('high');
  });

  it('flags numeric object references as possible IDOR', async () => {
    const { findings } = await runCrawl(base, { allowPrivateHosts: true });
    const idor = findings.find(f => f.title.includes('IDOR'));
    expect(idor).toBeDefined();
    expect(idor!.category).toBe('API_SEC');
  });

  it('respects maxPages bound', async () => {
    const { result } = await runCrawl(base, { allowPrivateHosts: true, maxPages: 2 });
    expect(result.pagesCrawled).toBeLessThanOrEqual(2);
  });

  it('returns an empty result for an unreachable host without throwing', async () => {
    const { result, findings } = await runCrawl('http://127.0.0.1:1', { allowPrivateHosts: true, budgetMs: 3000 });
    expect(result.pagesCrawled).toBeLessThanOrEqual(1);
    expect(Array.isArray(findings)).toBe(true);
  });
});
