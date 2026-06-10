import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inferServiceFromPort, buildHadrianMatrix } from '../server/enterprise-helpers.ts';
import { type DiagnosticResult } from '../server/scanner.ts';

function baseDiagnostics(overrides: Partial<DiagnosticResult> = {}): DiagnosticResult {
  return {
    url: 'https://api.example.test',
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

test('inferServiceFromPort labels well-known ports and subdomain shapes', () => {
  assert.equal(inferServiceFromPort('1194', 'vpn.example.test'), 'OpenVPN Daemon');
  assert.equal(inferServiceFromPort('25', 'mail.example.test'), 'SMTP Mail Relay');
  assert.equal(inferServiceFromPort('443', 'api.example.test'), 'HTTPS API Endpoint');
  assert.equal(inferServiceFromPort('443', 'admin.example.test'), 'HTTPS Admin Portal');
  assert.equal(inferServiceFromPort('443', 'staging.example.test'), 'HTTPS Non-Production Environment');
  assert.equal(inferServiceFromPort('443', 'www.example.test'), 'HTTPS Web Service');
  assert.equal(inferServiceFromPort('8080', 'host.example.test'), 'Unresponsive / Filtered');
});

test('buildHadrianMatrix returns a benign placeholder row when nothing is exposed', () => {
  const matrix = buildHadrianMatrix(baseDiagnostics(), 'https://api.example.test/v1');
  assert.equal(matrix.length, 1);
  assert.equal(matrix[0].endpoint, '/v1');
  assert.equal(matrix[0].vulnerability, null);
});

test('buildHadrianMatrix surfaces exposed paths, API findings, and DAST inputs', () => {
  const diag = baseDiagnostics({
    apiSecFindings: [
      { testName: 'BOLA', endpoint: '/api/orders/1', description: 'object access', severity: 'high', payload: 'x' } as any,
    ],
    dastInputs: [
      { formAction: '/login', method: 'POST', csrfPresent: false, vulnerability: 'CSRF', severity: 'high', description: 'no token', fix: 'add token' },
    ],
    probedPaths: [{ path: '/.env', status: 200, exposed: true }],
  });

  const matrix = buildHadrianMatrix(diag, 'https://api.example.test', 'Bearer x');
  const endpoints = matrix.map((m) => m.endpoint);
  assert.ok(endpoints.includes('/api/orders/1'));
  assert.ok(endpoints.includes('/login'));
  assert.ok(endpoints.includes('/.env'));

  // The CSRF-missing DAST input is flagged; supplied credentials are marked tested.
  const loginRow = matrix.find((m) => m.endpoint === '/login')!;
  assert.ok(loginRow.vulnerability);
  assert.notEqual(loginRow.rolesResult['Supplied Credentials'].status, 'Not Tested (No Credentials Supplied)');
});
