import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeCookies } from './scanner/cookies.js';
import { analyzeResponse } from './scanner/analysis.js';
import { detectVulnerableLibraries } from './scanner/sca.js';
import { compileStaticFindings } from './scanner.js';

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

test('SCA only fires on a real asset reference, not incidental body text', () => {
  // A version string in visible copy must not trigger a finding.
  assert.deepEqual(detectVulnerableLibraries('<p>We migrated from jquery-1.12.4 last year.</p>'), []);
  // A real <script src> reference is detected.
  const hit = detectVulnerableLibraries('<script src="/assets/jquery-1.12.4.min.js"></script>');
  assert.equal(hit.length, 1);
  assert.equal(hit[0].name, 'jQuery');
  assert.equal(hit[0].version, '1.12.4');
});

test('cookie issues collapse into a single consolidated finding', () => {
  const diag: any = {
    url: 'https://x.test', scannedAt: '', responseStatus: 200, sslSecure: true,
    headers: {}, missingHeaders: [], techLeaked: [], probedPaths: [],
    cookieIssues: ['Session cookie lacks HttpOnly flag', 'Session cookie lacks Secure directive', 'Session cookie lacks SameSite policy'],
    sastFindings: [], scaLibraries: [], easmPerimeter: { subdomains: [], ip: '', nameserver: '', protocol: '' },
    dastInputs: [], redTeamFindings: [], apiSecFindings: [],
  };
  const r = compileStaticFindings(diag);
  const cookieFindings = r.findings.filter((f) => /cookie/i.test(f.title));
  assert.equal(cookieFindings.length, 1);
  assert.match(cookieFindings[0].description, /HttpOnly/);
  assert.match(cookieFindings[0].description, /SameSite/);
});
