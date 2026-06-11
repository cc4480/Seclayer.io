import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateAiReport, generatePentagiLogs } from '../server/deepseek.ts';
import { compileStaticFindings, type DiagnosticResult } from '../server/scanner.ts';
import { derivePentagiEvidence } from '../server/pentagi.ts';

// The test environment has no DEEPSEEK_API_KEY configured, so every entry
// point should take its deterministic local-fallback path.

function baseDiagnostics(overrides: Partial<DiagnosticResult> = {}): DiagnosticResult {
  return {
    url: 'https://fallback.example.test',
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

test('generateAiReport falls back to the local summary and preserves static findings', async () => {
  const diag = baseDiagnostics({ sslSecure: false });
  const compiled = compileStaticFindings(diag);
  const report = await generateAiReport(diag.url, diag, compiled);

  assert.equal(report.score, compiled.score);
  assert.equal(report.severity, compiled.severity);
  assert.deepEqual(report.findings, compiled.findings);
  // The summary mentions the real target rather than a placeholder domain.
  assert.ok(report.aiSummary.includes(diag.url));
  assert.ok(!/example\.com/i.test(report.aiSummary));
});

test('generatePentagiLogs narrates a grounded fallback feed from real evidence', async () => {
  const diag = baseDiagnostics({
    url: 'https://staging.api.target.test',
    redTeamFindings: [
      { testName: 'Active Reflected XSS Probe', payload: '<script>x</script>', severity: 'high', description: 'reflected', fix: 'encode' },
    ],
  });
  const compiled = compileStaticFindings(diag);
  const evidence = derivePentagiEvidence('https://staging.api.target.test', diag, compiled);
  const logs = await generatePentagiLogs(evidence);

  assert.ok(Array.isArray(logs) && logs.length > 0);
  // The feed cites the supplied target in its first Scout log.
  assert.ok(logs[0].agent === 'Scout Agent' && logs[0].msg.includes('staging.api.target.test'));
  const agents = new Set(logs.map((l) => l.agent));
  assert.ok(agents.has('Scout Agent'));
  assert.ok(agents.has('Reporter Agent'));
  // The confirmed XSS finding is narrated; nothing is fabricated.
  assert.ok(logs.some((l) => l.agent === 'Exploiter Agent' && /XSS/i.test(l.msg)));
});

test('generatePentagiLogs does not claim an exploit when the scan is clean', async () => {
  const diag = baseDiagnostics({ url: 'https://clean.target.test' });
  const compiled = compileStaticFindings(diag);
  const evidence = derivePentagiEvidence('https://clean.target.test', diag, compiled);
  const logs = await generatePentagiLogs(evidence);

  assert.ok(logs.length > 0);
  assert.ok(logs.some((l) => l.agent === 'Exploiter Agent' && /no exploitable vector confirmed/i.test(l.msg)));
});
