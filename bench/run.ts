import fs from 'fs';
import path from 'path';
import type { Finding } from '../src/types.js';
import { runDiagnostics, compileStaticFindings } from '../server/scanner.js';
import { startVulnerableTarget, startCleanTarget, startAuthenticatedTarget } from './fixtures.js';
import { scoreTarget, aggregate, ACTIVE_CHECKS, ALL_CHECK_IDS } from './scoring.js';

/**
 * Reproducible accuracy benchmark. Spins up the labeled fixture targets, runs
 * the real scanner against each, scores the findings against the ground truth,
 * and prints (plus persists) detection rate, false-positive rate, and precision.
 *
 * Run with: npm run benchmark
 */

async function scan(url: string, authHeader?: string): Promise<Finding[]> {
  const diag = await runDiagnostics(url, authHeader);
  return compileStaticFindings(diag).findings;
}

const bolaDetected = (findings: Finding[]) =>
  findings.some((f) => /object level authorization|bola/i.test(f.title));

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

async function main() {
  const vuln = await startVulnerableTarget();
  const clean = await startCleanTarget();

  try {
    const vulnFindings = await scan(vuln.url);
    const cleanFindings = await scan(clean.url);

    const vulnScore = scoreTarget(vulnFindings, ALL_CHECK_IDS);
    const cleanScore = scoreTarget(cleanFindings, []); // nothing should fire here
    const metrics = aggregate(vulnScore, cleanScore);

    const labelOf = (id: string) => ACTIVE_CHECKS.find((c) => c.id === id)?.label ?? id;

    console.log('\n=== Seclayer Scanner Accuracy Benchmark ===\n');
    console.log(`Vulnerable target — detection (expected: all ${ACTIVE_CHECKS.length}):`);
    for (const c of ACTIVE_CHECKS) {
      const hit = vulnScore.detected.includes(c.id);
      console.log(`  ${hit ? '✓ DETECTED ' : '✗ MISSED   '} ${c.label}`);
    }
    console.log(`  Validated (re-confirmed PoC) findings: ${vulnScore.validatedCount}`);

    console.log('\nClean target — false positives (expected: none):');
    if (cleanScore.falsePositives.length === 0) {
      console.log('  ✓ No active-probe false positives (all decoys suppressed)');
    } else {
      for (const id of cleanScore.falsePositives) console.log(`  ✗ FALSE POSITIVE: ${labelOf(id)}`);
    }

    // Authenticated scanning: a token unlocks a finding an anonymous scan misses.
    const TOKEN = 'bench-secret-token';
    const authTarget = await startAuthenticatedTarget(TOKEN);
    let authProven = false;
    try {
      const anon = await scan(authTarget.url);
      const authed = await scan(authTarget.url, `Bearer ${TOKEN}`);
      authProven = !bolaDetected(anon) && bolaDetected(authed);
      console.log('\nAuthenticated scanning:');
      console.log(`  Anonymous scan detects gated BOLA: ${bolaDetected(anon) ? 'yes' : 'no'}`);
      console.log(`  Authenticated scan detects gated BOLA: ${bolaDetected(authed) ? 'yes' : 'no'}`);
      console.log(`  ${authProven ? '✓' : '✗'} Credentials reach findings an anonymous scan cannot`);
    } finally {
      await authTarget.close();
    }

    console.log('\n--- Metrics ---');
    console.log(`  Vulnerability classes:   ${ACTIVE_CHECKS.length}`);
    console.log(`  Detection rate (recall): ${pct(metrics.detectionRate)}  (${metrics.truePositives}/${metrics.truePositives + metrics.falseNegatives})`);
    console.log(`  False-positive rate:     ${pct(metrics.falsePositiveRate)}  (${metrics.falsePositives}/${ACTIVE_CHECKS.length})`);
    console.log(`  Precision:               ${pct(metrics.precision)}`);
    console.log('');

    // Optional real-world profile (e.g. a local DVWA/Juice Shop) when network is
    // available: scan it and report which classes fired. No pass/fail gate, since
    // a live app's ground truth varies. Set BENCH_REAL_TARGET=http://host:port.
    let realTarget: { url: string; detected: string[]; validatedCount: number } | null = null;
    const realUrl = process.env.BENCH_REAL_TARGET;
    if (realUrl) {
      try {
        console.log(`Real target profile: scanning ${realUrl} ...`);
        const realFindings = await scan(realUrl);
        const real = scoreTarget(realFindings, []);
        realTarget = { url: realUrl, detected: real.detected, validatedCount: real.validatedCount };
        console.log(`  Classes fired: ${real.detected.length ? real.detected.join(', ') : 'none'}`);
        console.log(`  Validated PoCs: ${real.validatedCount}\n`);
      } catch (e) {
        console.warn(`  Real target unreachable (${(e as Error).message}); skipped.\n`);
      }
    }

    const report = {
      generatedAt: new Date().toISOString(),
      checks: ACTIVE_CHECKS.map((c) => c.label),
      vulnerableTarget: vulnScore,
      cleanTarget: cleanScore,
      authenticatedScanningProven: authProven,
      realTarget,
      metrics,
    };
    const outPath = path.join(process.cwd(), 'bench', 'results.json');
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
    console.log(`Wrote ${outPath}\n`);

    // Gate: full detection, zero false positives, and proven auth scanning.
    const ok = metrics.detectionRate === 1 && metrics.falsePositives === 0 && authProven;
    if (!ok) {
      console.error('Benchmark FAILED its thresholds (100% detection, 0 FP, auth scanning proven).');
      process.exitCode = 1;
    } else {
      console.log(`Benchmark PASSED (${ACTIVE_CHECKS.length} classes, 100% detection, 0 false positives, auth scanning proven).`);
    }
  } finally {
    await vuln.close();
    await clean.close();
  }
}

main().catch((err) => {
  console.error('Benchmark error:', err);
  process.exit(1);
});
