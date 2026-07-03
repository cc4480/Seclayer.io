import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileScanMetadata } from './scanner.js';

function baseDiag(overrides: any = {}): any {
  return {
    url: 'https://x.test', scannedAt: '', responseStatus: 200, sslSecure: true,
    headers: {}, missingHeaders: [], techLeaked: [], probedPaths: [], cookieIssues: [],
    sastFindings: [], scaLibraries: [],
    easmPerimeter: { subdomains: [], ip: '', nameserver: '', protocol: 'HTTPS' },
    dastInputs: [], redTeamFindings: [], apiSecFindings: [], ...overrides,
  };
}

test('compileScanMetadata surfaces real recon (IP, nameserver, TLS, server header)', () => {
  const diag = baseDiag({
    responseStatus: 200,
    sslSecure: true,
    headers: { server: 'nginx/1.25.3' },
    techLeaked: ['Server: nginx/1.25.3'],
    easmPerimeter: { subdomains: [], ip: '93.184.216.34', nameserver: 'ns1.example.net', protocol: 'HTTPS' },
  });
  const meta = compileScanMetadata(diag);
  assert.equal(meta.responseStatus, 200);
  assert.equal(meta.ip, '93.184.216.34');
  assert.equal(meta.nameserver, 'ns1.example.net');
  assert.equal(meta.protocol, 'HTTPS');
  assert.match(meta.tls || '', /TLS/);
  assert.equal(meta.serverHeader, 'nginx/1.25.3');
  assert.deepEqual(meta.techLeaked, ['Server: nginx/1.25.3']);
});

test('compileScanMetadata keeps only live subdomains and records how many were checked', () => {
  const diag = baseDiag({
    easmPerimeter: {
      ip: '1.2.3.4', nameserver: '', protocol: 'HTTPS',
      subdomains: [
        { domain: 'api.x.test', status: 'live', port: '443' },
        { domain: 'dev.x.test', status: 'inactive', port: '0' },
        { domain: 'admin.x.test', status: 'live', port: '443' },
      ],
    },
  });
  const meta = compileScanMetadata(diag);
  assert.equal(meta.subdomainsChecked, 3);
  assert.equal(meta.liveSubdomains?.length, 2);
  assert.deepEqual(meta.liveSubdomains?.map((s) => s.domain), ['api.x.test', 'admin.x.test']);
});

test('compileScanMetadata caps stored live subdomains', () => {
  const many = Array.from({ length: 40 }, (_, i) => ({ domain: `s${i}.x.test`, status: 'live' as const, port: '443' }));
  const diag = baseDiag({ easmPerimeter: { ip: '1.2.3.4', nameserver: '', protocol: 'HTTPS', subdomains: many } });
  const meta = compileScanMetadata(diag);
  assert.equal(meta.subdomainsChecked, 40);
  assert.equal(meta.liveSubdomains?.length, 24);
});

test('compileScanMetadata reports plaintext HTTP posture and omits missing recon fields', () => {
  const diag = baseDiag({
    sslSecure: false,
    easmPerimeter: { subdomains: [], ip: '', nameserver: '', protocol: 'HTTP' },
  });
  const meta = compileScanMetadata(diag);
  assert.equal(meta.protocol, 'HTTP');
  assert.match(meta.tls || '', /Plaintext/);
  assert.equal(meta.ip, undefined);
  assert.equal(meta.nameserver, undefined);
  assert.equal(meta.serverHeader, undefined);
});

test('compileScanMetadata passes crawl surface and probed paths through', () => {
  const diag = baseDiag({
    probedPaths: [
      { path: '/.env', status: 200, exposed: true },
      { path: '/.git/config', status: 404, exposed: false },
    ],
    crawl: { pagesVisited: 5, endpointsDiscovered: 12, paramsTested: 7, sampleEndpoints: ['/search?q'] },
  });
  const meta = compileScanMetadata(diag);
  assert.equal(meta.probedPaths?.length, 2);
  assert.equal(meta.probedPaths?.[0].exposed, true);
  assert.equal(meta.crawl?.pagesVisited, 5);
  assert.equal(meta.crawl?.endpointsDiscovered, 12);
});
