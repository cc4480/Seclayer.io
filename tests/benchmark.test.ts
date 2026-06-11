import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Finding } from '../src/types.ts';
import { runDiagnostics, compileStaticFindings } from '../server/scanner.ts';
import { startVulnerableTarget, startCleanTarget, startAuthenticatedTarget } from '../bench/fixtures.ts';
import { scoreTarget, aggregate, ACTIVE_CHECKS, ALL_CHECK_IDS } from '../bench/scoring.ts';
import { BENCHMARK_STATS } from '../src/lib/benchmark-stats.ts';

const bola = (findings: Finding[]) => findings.some((f) => /object level authorization|bola/i.test(f.title));

function f(title: string, extra: Partial<Finding> = {}): Finding {
  return { id: 'x', title, description: '', severity: 'high', fix: '', category: 'RED_TEAM', ...extra };
}

test('scoring: detection, false positives, and aggregate metrics', () => {
  const vuln = scoreTarget(
    [f('Active SQL Injection Probe'), f('Active Reflected XSS Probe', { validated: true })],
    ALL_CHECK_IDS,
  );
  assert.deepEqual(vuln.truePositives.sort(), ['sqli', 'xss']);
  assert.equal(vuln.missed.length, ACTIVE_CHECKS.length - 2);
  assert.equal(vuln.validatedCount, 1);

  // Clean target with a finding that should not be there -> false positive.
  const clean = scoreTarget([f('Active SQL Injection Probe')], []);
  assert.deepEqual(clean.falsePositives, ['sqli']);

  const metrics = aggregate(vuln, clean);
  assert.equal(metrics.truePositives, 2);
  assert.equal(metrics.falsePositives, 1);
  assert.equal(metrics.detectionRate, 2 / ACTIVE_CHECKS.length);
});

test('benchmark: scanner achieves full detection and zero false positives on the fixtures', async () => {
  const vuln = await startVulnerableTarget();
  const clean = await startCleanTarget();
  try {
    const vulnFindings = compileStaticFindings(await runDiagnostics(vuln.url)).findings;
    const cleanFindings = compileStaticFindings(await runDiagnostics(clean.url)).findings;

    const vulnScore = scoreTarget(vulnFindings, ALL_CHECK_IDS);
    const cleanScore = scoreTarget(cleanFindings, []);
    const metrics = aggregate(vulnScore, cleanScore);

    // Every planted vulnerability is detected.
    assert.deepEqual(
      vulnScore.missed,
      [],
      `Missed checks: ${vulnScore.missed.join(', ')} (detected: ${vulnScore.detected.join(', ')})`,
    );
    assert.equal(metrics.detectionRate, 1);

    // The decoy-laden clean target produces zero active-probe false positives.
    assert.deepEqual(
      cleanScore.falsePositives,
      [],
      `Unexpected false positives: ${cleanScore.falsePositives.join(', ')}`,
    );
    assert.equal(metrics.falsePositiveRate, 0);
    assert.equal(metrics.precision, 1);

    // The active exploit probes (XSS/SQLi/cmd/SSRF/GraphQL/BOLA) are re-confirmed.
    assert.ok(
      vulnScore.validatedCount >= BENCHMARK_STATS.validatedVectors,
      `Expected >=${BENCHMARK_STATS.validatedVectors} validated findings, got ${vulnScore.validatedCount}`,
    );
  } finally {
    await vuln.close();
    await clean.close();
  }
});

test('benchmark: authenticated scanning reaches a finding an anonymous scan cannot', async () => {
  const TOKEN = 'bench-secret-token';
  const target = await startAuthenticatedTarget(TOKEN);
  try {
    const anon = compileStaticFindings(await runDiagnostics(target.url)).findings;
    const authed = compileStaticFindings(await runDiagnostics(target.url, `Bearer ${TOKEN}`)).findings;
    assert.equal(bola(anon), false, 'Anonymous scan should not reach the gated BOLA endpoint');
    assert.equal(bola(authed), true, 'Authenticated scan should reach the gated BOLA endpoint');
  } finally {
    await target.close();
  }
});

test('published landing-page stats match the live benchmark (no drift)', async () => {
  // The numbers shown on the site are CI-enforced against the real scanner.
  assert.equal(BENCHMARK_STATS.totalChecks, ACTIVE_CHECKS.length);

  const vuln = await startVulnerableTarget();
  const clean = await startCleanTarget();
  try {
    const vulnScore = scoreTarget(compileStaticFindings(await runDiagnostics(vuln.url)).findings, ALL_CHECK_IDS);
    const cleanScore = scoreTarget(compileStaticFindings(await runDiagnostics(clean.url)).findings, []);
    const metrics = aggregate(vulnScore, cleanScore);

    assert.equal(metrics.detectionRate, BENCHMARK_STATS.detectionRate, 'detection rate drifted from published stat');
    assert.equal(metrics.falsePositiveRate, BENCHMARK_STATS.falsePositiveRate, 'false-positive rate drifted from published stat');
  } finally {
    await vuln.close();
    await clean.close();
  }
});
