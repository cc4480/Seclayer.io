import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import type { AddressInfo } from 'net';
import { recheckFinding } from '../../server/recheck.js';
import type { Finding } from '../../src/types.js';

// Root page exposes a CSRF-less POST form, so the deep crawl re-detects the
// "Form Missing Anti-CSRF Protection" finding on every re-test.
const ROOT = `<html><head><title>App</title></head><body>
  <form action="/save" method="post">
    <input name="data" type="text">
  </form>
</body></html>`;

let server: http.Server;
let base: string;

beforeAll(async () => {
  server = http.createServer((_req, res) => {
    res.setHeader('content-type', 'text/html');
    res.end(ROOT);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe('recheckFinding', () => {
  it('reports still present when the issue is re-detected', async () => {
    const finding: Finding = {
      id: 'f1', title: 'Form Missing Anti-CSRF Protection', description: 'POST form without CSRF token',
      severity: 'high', fix: 'Add CSRF token', category: 'DAST',
    };
    const result = await recheckFinding(base, finding);
    expect(result.stillPresent).toBe(true);
    expect(result.checkedAt).toBeDefined();
  }, 30000);

  it('reports resolved when no fresh finding matches', async () => {
    const finding: Finding = {
      id: 'f2', title: 'Outdated jQuery 1.2 Library With Known CVEs', description: 'vulnerable dependency',
      severity: 'medium', fix: 'Upgrade jQuery', category: 'SCA',
    };
    const result = await recheckFinding(base, finding);
    expect(result.stillPresent).toBe(false);
    expect(result.detail).toContain('no longer detects');
  }, 30000);
});
