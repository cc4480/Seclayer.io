import { test } from 'node:test';
import assert from 'node:assert/strict';
import { derivePentagiEvidence, buildPentagiLogs } from '../server/pentagi.ts';
import { type DiagnosticResult } from '../server/scanner.ts';

function baseDiagnostics(overrides: Partial<DiagnosticResult> = {}): DiagnosticResult {
  return {
    url: 'https://pentagi.example.test',
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
    easmPerimeter: { subdomains: [], ip: '203.0.113.7', nameserver: 'ns.example.test', protocol: 'TLS 1.3 / HTTPS' },
    dastInputs: [],
    redTeamFindings: [],
    apiSecFindings: [],
    ...overrides,
  };
}

test('derivePentagiEvidence reflects real recon and exploit signals', () => {
  const diag = baseDiagnostics({
    techLeaked: ['Server: nginx'],
    probedPaths: [{ path: '/.env', status: 200, exposed: true }],
    easmPerimeter: {
      ip: '203.0.113.7',
      nameserver: 'ns.example.test',
      protocol: 'TLS 1.3 / HTTPS',
      subdomains: [
        { domain: 'api.example.test', status: 'live', port: '443', ip: '203.0.113.8' },
        { domain: 'dead.example.test', status: 'inactive', port: '0' },
      ],
    },
    redTeamFindings: [
      { testName: 'Active Reflected XSS Probe', payload: '<script>x</script>', severity: 'high', description: 'reflected', fix: 'encode' },
    ],
  });
  const evidence = derivePentagiEvidence('https://pentagi.example.test', diag, {
    score: 45,
    severity: 'high',
    findings: [{}, {}, {}],
  });

  assert.equal(evidence.hostname, 'pentagi.example.test');
  assert.deepEqual(evidence.liveSubdomains, ['api.example.test']);
  assert.deepEqual(evidence.exposedPaths, ['/.env']);
  assert.equal(evidence.exploitFindings.length, 1);
  assert.equal(evidence.exploitFindings[0].name, 'Active Reflected XSS Probe');
  assert.equal(evidence.totalFindings, 3);
  assert.equal(evidence.score, 45);
});

test('buildPentagiLogs narrates confirmed exploits without inventing them', () => {
  const evidence = derivePentagiEvidence('https://pentagi.example.test', baseDiagnostics({
    probedPaths: [{ path: '/.env', status: 200, exposed: true }],
    redTeamFindings: [
      { testName: 'Active SQL Injection Probe', payload: "' OR 1=1--", severity: 'critical', description: 'db error reflected', fix: 'params' },
    ],
  }), { score: 20, severity: 'critical', findings: [{}, {}] });

  const logs = buildPentagiLogs(evidence);
  const agents = new Set(logs.map((l) => l.agent));
  assert.ok(agents.has('Scout Agent'));
  assert.ok(agents.has('Exploiter Agent'));
  assert.ok(agents.has('Reporter Agent'));

  // First Scout log cites the target host; Exploiter cites the real finding.
  assert.ok(logs[0].agent === 'Scout Agent' && logs[0].msg.includes('pentagi.example.test'));
  assert.ok(logs.some((l) => l.agent === 'Exploiter Agent' && /SQL Injection/i.test(l.msg)));
  assert.ok(logs.some((l) => l.agent === 'Exploiter Agent' && l.msg.includes('/.env')));
  assert.ok(logs.some((l) => l.agent === 'Reporter Agent' && l.msg.includes('20/100')));
});

test('buildPentagiLogs reports no exploitable vector when the scan is clean', () => {
  const evidence = derivePentagiEvidence('https://clean.example.test', baseDiagnostics(), {
    score: 92,
    severity: 'low',
    findings: [],
  });

  const logs = buildPentagiLogs(evidence);
  // No fabricated exploit chain — the Exploiter explicitly confirms nothing fired.
  assert.ok(logs.some((l) => l.agent === 'Exploiter Agent' && /no exploitable vector confirmed/i.test(l.msg)));
  assert.ok(logs.some((l) => l.agent === 'Reporter Agent' && /no high-severity exploit chain/i.test(l.msg)));
  assert.ok(!logs.some((l) => /exfiltrat|admin user redirected|bypassed authentication/i.test(l.msg)));

  // Timestamps increase monotonically.
  const secs = logs.map((l) => {
    const [m, s] = l.time.split(':').map(Number);
    return m * 60 + s;
  });
  for (let i = 1; i < secs.length; i++) assert.ok(secs[i] > secs[i - 1]);
});
