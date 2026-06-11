import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Finding } from '../src/types.ts';
import { runDiagnostics, compileStaticFindings } from '../server/scanner.ts';
import {
  startVulnerableTarget,
  startCleanTarget,
  startAuthenticatedTarget,
  startChainTarget,
  startCleanChainTarget,
} from '../bench/fixtures.ts';
import { scoreTarget, aggregate, ACTIVE_CHECKS, ALL_CHECK_IDS } from '../bench/scoring.ts';
import { BENCHMARK_STATS } from '../src/lib/benchmark-stats.ts';

const TOKEN = 'bench-secret-token';
const bola = (findings: Finding[]) => findings.some((f) => /object level authorization|bola/i.test(f.title));
const findingsFor = async (url: string, auth?: string) =>
  compileStaticFindings(await runDiagnostics(url, auth)).findings;

/** Combined corpus: single-page classes + the authenticated multi-page chains. */
async function scanCorpus(single: () => Promise<{ url: string; close: () => Promise<void> }>, chain: (t: string) => Promise<{ url: string; close: () => Promise<void> }>) {
  const a = await single();
  const b = await chain(TOKEN);
  try {
    return [...(await findingsFor(a.url)), ...(await findingsFor(b.url, `Bearer ${TOKEN}`))];
  } finally {
    await a.close();
    await b.close();
  }
}

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

test('benchmark: full detection (incl. stored XSS + IDOR chains) and zero false positives', async () => {
  const vulnFindings = await scanCorpus(startVulnerableTarget, startChainTarget);
  const cleanFindings = await scanCorpus(startCleanTarget, startCleanChainTarget);

  const vulnScore = scoreTarget(vulnFindings, ALL_CHECK_IDS);
  const cleanScore = scoreTarget(cleanFindings, []);
  const metrics = aggregate(vulnScore, cleanScore);

  // Every planted vulnerability — including the multi-page chains — is detected.
  assert.deepEqual(
    vulnScore.missed,
    [],
    `Missed checks: ${vulnScore.missed.join(', ')} (detected: ${vulnScore.detected.join(', ')})`,
  );
  assert.equal(metrics.detectionRate, 1);

  // The decoy-laden clean targets produce zero false positives.
  assert.deepEqual(
    cleanScore.falsePositives,
    [],
    `Unexpected false positives: ${cleanScore.falsePositives.join(', ')}`,
  );
  assert.equal(metrics.falsePositiveRate, 0);
  assert.equal(metrics.precision, 1);

  assert.ok(
    vulnScore.validatedCount >= BENCHMARK_STATS.validatedVectors,
    `Expected >=${BENCHMARK_STATS.validatedVectors} validated findings, got ${vulnScore.validatedCount}`,
  );
});

test('benchmark: authenticated scanning reaches findings an anonymous scan cannot', async () => {
  const target = await startAuthenticatedTarget(TOKEN);
  try {
    const anon = await findingsFor(target.url);
    const authed = await findingsFor(target.url, `Bearer ${TOKEN}`);
    assert.equal(bola(anon), false, 'Anonymous scan should not reach the gated BOLA endpoint');
    assert.equal(bola(authed), true, 'Authenticated scan should reach the gated BOLA endpoint');
  } finally {
    await target.close();
  }

  // The multi-page chains live behind auth too: anonymous scan finds neither.
  const chain = await startChainTarget(TOKEN);
  try {
    const anon = scoreTarget(await findingsFor(chain.url), []);
    assert.equal(anon.detected.includes('stored_xss'), false);
    assert.equal(anon.detected.includes('idor'), false);
  } finally {
    await chain.close();
  }
});

test('published landing-page stats match the live benchmark (no drift)', async () => {
  // The numbers shown on the site are CI-enforced against the real scanner.
  assert.equal(BENCHMARK_STATS.totalChecks, ACTIVE_CHECKS.length);

  const vulnScore = scoreTarget(await scanCorpus(startVulnerableTarget, startChainTarget), ALL_CHECK_IDS);
  const cleanScore = scoreTarget(await scanCorpus(startCleanTarget, startCleanChainTarget), []);
  const metrics = aggregate(vulnScore, cleanScore);

  assert.equal(metrics.detectionRate, BENCHMARK_STATS.detectionRate, 'detection rate drifted from published stat');
  assert.equal(metrics.falsePositiveRate, BENCHMARK_STATS.falsePositiveRate, 'false-positive rate drifted from published stat');
});
