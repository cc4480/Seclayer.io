import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertScanTargetSafe, isBlockedIp, looksLikeHtml, compileStaticFindings } from './scanner.js';

function baseDiag(overrides: any = {}): any {
  return {
    url: 'https://x.test', scannedAt: '', responseStatus: 200, sslSecure: true,
    headers: {}, missingHeaders: [], techLeaked: [], probedPaths: [], cookieIssues: [],
    sastFindings: [], scaLibraries: [], easmPerimeter: { subdomains: [], ip: '', nameserver: '', protocol: '' },
    dastInputs: [], redTeamFindings: [], apiSecFindings: [], ...overrides,
  };
}

test('isBlockedIp blocks internal/reserved ranges', () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254', '172.16.0.1', '100.64.0.1', '::1', 'fe80::1', 'fc00::1']) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
  for (const ip of ['8.8.8.8', '93.184.216.34', '1.1.1.1']) {
    assert.equal(isBlockedIp(ip), false, `${ip} should be allowed`);
  }
});

test('assertScanTargetSafe rejects internal hosts and non-http schemes', async () => {
  for (const t of ['localhost', 'http://127.0.0.1', 'http://169.254.169.254/', 'ftp://example.com', 'file:///etc/passwd', 'admin.internal', 'http://[::1]/']) {
    await assert.rejects(assertScanTargetSafe(t), `${t} should be rejected`);
  }
});

test('assertScanTargetSafe allows a public literal IP', async () => {
  await assert.doesNotReject(assertScanTargetSafe('https://93.184.216.34'));
});

test('looksLikeHtml separates a SPA shell from a raw config file', () => {
  assert.equal(looksLikeHtml('<!doctype html><html><head>'), true);
  assert.equal(looksLikeHtml('DB_PASSWORD=secret\nAPI_KEY=abc'), false);
});

test('a clean target produces no findings and a full score (no SPA .env false positive)', () => {
  const diag = baseDiag({ probedPaths: [{ path: '/.env', status: 200, exposed: false }] });
  const r = compileStaticFindings(diag);
  assert.equal(r.findings.length, 0);
  assert.equal(r.score, 100);
});

test('a confirmed exposed .env yields a critical finding', () => {
  const diag = baseDiag({ probedPaths: [{ path: '/.env', status: 200, exposed: true }] });
  const r = compileStaticFindings(diag);
  assert.equal(r.severity, 'critical');
  assert.ok(r.findings.some((f) => /env/i.test(f.title)));
});

test('missing CSP is reported as high severity', () => {
  const diag = baseDiag({ missingHeaders: ['content-security-policy'] });
  const r = compileStaticFindings(diag);
  assert.ok(r.findings.some((f) => /content-security-policy/i.test(f.title) && f.severity === 'high'));
});
