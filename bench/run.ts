import fs from 'fs';
import path from 'path';
import type { Finding } from '../src/types.js';
import { runDiagnostics, compileStaticFindings } from '../server/scanner.js';
import { startVulnerableTarget, startCleanTarget } from './fixtures.js';
import { scoreTarget, aggregate, ACTIVE_CHECKS, ALL_CHECK_IDS } from './scoring.js';

/**
 * Reproducible accuracy benchmark. Spins up the labeled fixture targets, runs
 * the real scanner against each, scores the findings against the ground truth,
 * and prints (plus persists) detection rate, false-positive rate, and precision.
 *
 * Run with: npm run benchmark
 */

async function scan(url: string): Promise<Finding[]> {
  const diag = await runDiagnostics(url);
  return compileStaticFindings(diag).findings;
}

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
    console.log('Vulnerable target — detection (expected: all 7):');
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

    console.log('\n--- Metrics ---');
    console.log(`  Detection rate (recall): ${pct(metrics.detectionRate)}  (${metrics.truePositives}/${metrics.truePositives + metrics.falseNegatives})`);
    console.log(`  False-positive rate:     ${pct(metrics.falsePositiveRate)}  (${metrics.falsePositives}/${ACTIVE_CHECKS.length})`);
    console.log(`  Precision:               ${pct(metrics.precision)}`);
    console.log('');

    const report = {
      generatedAt: new Date().toISOString(),
      checks: ACTIVE_CHECKS.map((c) => c.label),
      vulnerableTarget: vulnScore,
      cleanTarget: cleanScore,
      metrics,
    };
    const outPath = path.join(process.cwd(), 'bench', 'results.json');
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
    console.log(`Wrote ${outPath}\n`);

    // Gate: full detection and zero false positives are required to pass.
    const ok = metrics.detectionRate === 1 && metrics.falsePositives === 0;
    if (!ok) {
      console.error('Benchmark FAILED its thresholds (detection must be 100%, FP must be 0).');
      process.exitCode = 1;
    } else {
      console.log('Benchmark PASSED (100% detection, 0 false positives).');
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
