import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileStaticFindings, summarizeDiagnostics, type DiagnosticResult } from '../server/scanner.ts';

function baseDiagnostics(overrides: Partial<DiagnosticResult> = {}): DiagnosticResult {
  return {
    url: 'https://example.test',
    scannedAt: new Date().toISOString(),
    responseStatus: 200,
    sslSecure: true,
    headers: {},
    missingHeaders: [],
    techLeaked: [],
    probedPaths: [],
    cookieIssues: [],
    sastFindings: [],
    scaLibraries: [],
    easmPerimeter: { subdomains: [], ip: '1.2.3.4', nameserver: 'ns', protocol: 'TLS 1.3 / HTTPS' },
    dastInputs: [],
    redTeamFindings: [],
    apiSecFindings: [],
    ...overrides,
  };
}

test('clean target yields a perfect score and low severity', () => {
  const { score, severity, findings } = compileStaticFindings(baseDiagnostics());
  assert.equal(score, 100);
  assert.equal(severity, 'low');
  assert.equal(findings.length, 0);
});

test('insecure HTTP is reported as a high-severity EASM finding', () => {
  const result = compileStaticFindings(baseDiagnostics({ sslSecure: false }));
  const finding = result.findings.find((f) => f.category === 'EASM' && /HTTP/i.test(f.title));
  assert.ok(finding, 'expected an HTTP finding');
  assert.equal(finding!.severity, 'high');
  assert.ok(result.score < 100);
});

test('exposed .env file is escalated to critical and floors the score', () => {
  const result = compileStaticFindings(
    baseDiagnostics({ probedPaths: [{ path: '/.env', status: 200, exposed: true }] }),
  );
  assert.equal(result.severity, 'critical');
  assert.ok(result.findings.some((f) => /\.env/i.test(f.title) && f.severity === 'critical'));
});

test('score is clamped to the 12-100 range even with many findings', () => {
  const result = compileStaticFindings(
    baseDiagnostics({
      sslSecure: false,
      missingHeaders: ['content-security-policy', 'strict-transport-security', 'x-frame-options'],
      probedPaths: [
        { path: '/.env', status: 200, exposed: true },
        { path: '/.git/config', status: 200, exposed: true },
      ],
    }),
  );
  assert.ok(result.score >= 12 && result.score <= 100);
});

test('summarizeDiagnostics trims a diagnostic run down to report-renderable fields', () => {
  const diag = baseDiagnostics({
    headers: { server: 'nginx' },
    probedPaths: [{ path: '/.env', status: 200, exposed: true }],
    dastInputs: [
      { formAction: '/login', method: 'POST', csrfPresent: false, vulnerability: 'CSRF', severity: 'high', description: 'd', fix: 'f' },
    ],
    easmPerimeter: {
      subdomains: [{ domain: 'api.example.test', status: 'live', port: '443', ip: '5.6.7.8' }],
      ip: '1.2.3.4',
      nameserver: 'ns1.example.test',
      protocol: 'TLS 1.3 / HTTPS',
    },
  });

  const summary = summarizeDiagnostics(diag);

  assert.equal(summary.responseStatus, 200);
  assert.deepEqual(summary.headers, { server: 'nginx' });
  assert.deepEqual(summary.probedPaths, [{ path: '/.env', status: 200, exposed: true }]);
  assert.deepEqual(summary.dastInputs, [{ formAction: '/login', method: 'POST', csrfPresent: false }]);
  assert.equal(summary.easmPerimeter.ip, '1.2.3.4');
  assert.equal(summary.easmPerimeter.nameserver, 'ns1.example.test');
  assert.deepEqual(summary.easmPerimeter.subdomains, [{ domain: 'api.example.test', status: 'live', port: '443' }]);
});
