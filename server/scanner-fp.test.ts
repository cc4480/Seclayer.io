import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeCookies } from './scanner/cookies.js';
import { analyzeResponse } from './scanner/analysis.js';

function baseResult(headers: Record<string, string> = {}): any {
  return {
    url: 'https://x.test', headers, missingHeaders: [], techLeaked: [],
    cookieIssues: [], sastFindings: [], scaLibraries: [],
  };
}

test('analyzeCookies ignores analytics/CDN cookies, flags session cookies', () => {
  // Benign cookies must never produce findings.
  assert.deepEqual(analyzeCookies(['_ga=GA1.2.3; Path=/', '__cf_bm=abc; Path=/'], true), []);
  // A session cookie with no flags is flagged on all three.
  const issues = analyzeCookies(['sessionid=xyz; Path=/'], true);
  assert.ok(issues.includes('Session cookie lacks HttpOnly flag'));
  assert.ok(issues.includes('Session cookie lacks Secure directive'));
  assert.ok(issues.includes('Session cookie lacks SameSite policy'));
});

test('analyzeCookies respects flags and __Host- prefix', () => {
  const issues = analyzeCookies(['__Host-session=xyz; Path=/; HttpOnly; SameSite=Lax'], true);
  assert.deepEqual(issues, []); // __Host- implies Secure; other flags present
});

test('meta CSP suppresses the missing-CSP false positive', () => {
  const result = baseResult({});
  analyzeResponse(result, '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">', 'https://x.test');
  assert.ok(!result.missingHeaders.includes('content-security-policy'));
});

test('CSP frame-ancestors suppresses missing X-Frame-Options', () => {
  const result = baseResult({ 'content-security-policy': "frame-ancestors 'none'" });
  analyzeResponse(result, '', 'https://x.test');
  assert.ok(!result.missingHeaders.includes('x-frame-options'));
});

test('HSTS is not flagged on plain-HTTP targets', () => {
  const result = baseResult({});
  analyzeResponse(result, '', 'http://x.test');
  assert.ok(!result.missingHeaders.includes('strict-transport-security'));
});

test('unversioned Server banner is not a tech-leak; versioned one is', () => {
  const bare = baseResult({ server: 'nginx' });
  analyzeResponse(bare, '', 'https://x.test');
  assert.equal(bare.techLeaked.length, 0);

  const versioned = baseResult({ server: 'nginx/1.18.0' });
  analyzeResponse(versioned, '', 'https://x.test');
  assert.ok(versioned.techLeaked.some((t: string) => /nginx\/1\.18\.0/.test(t)));
});
