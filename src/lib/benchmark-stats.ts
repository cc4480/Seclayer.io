/**
 * Published accuracy numbers shown as a trust signal on the landing page.
 *
 * These are NOT free-floating marketing claims: `tests/benchmark.test.ts` runs
 * the real scanner against the labeled fixtures and asserts the live result
 * matches every value here. If the scanner regresses, the test fails — so the
 * number on the site can never silently drift from what the scanner actually
 * does. Regenerate/inspect with `npm run benchmark`.
 */
export const BENCHMARK_STATS = {
  /** Distinct vulnerability classes covered by the benchmark corpus. */
  totalChecks: 14,
  /** Recall on the vulnerable fixtures: detected / planted. */
  detectionRate: 1,
  /** False positives on the decoy-laden clean fixtures. */
  falsePositiveRate: 0,
  /** Exploit vectors re-confirmed with a reproducible PoC. */
  validatedVectors: 8,
  /** Authenticated, multi-page scanning surfaces findings an anonymous scan cannot. */
  authenticatedScanning: true,
} as const;

export const BENCHMARK_DISPLAY = {
  detection: `${Math.round(BENCHMARK_STATS.detectionRate * 100)}%`,
  falsePositives: `${Math.round(BENCHMARK_STATS.falsePositiveRate * 100)}%`,
  checks: `${BENCHMARK_STATS.totalChecks}`,
  validated: `${BENCHMARK_STATS.validatedVectors}`,
} as const;
