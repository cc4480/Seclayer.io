import type { Finding } from '../src/types.js';

/**
 * Ground-truth scoring for the accuracy benchmark.
 *
 * Each "active check" is a high-signal probe whose precision is what the
 * calibration + validation work governs. Header/protocol findings are
 * deterministic facts (a plaintext-HTTP fixture really is cleartext), so they
 * are intentionally out of scope for the false-positive metric.
 */

export interface ActiveCheck {
  id: string;
  label: string;
  /** True when the scanner's findings contain this vulnerability. */
  detect: (findings: Finding[]) => boolean;
}

const has = (findings: Finding[], pred: (f: Finding) => boolean) => findings.some(pred);

export const ACTIVE_CHECKS: ActiveCheck[] = [
  { id: 'xss', label: 'Reflected XSS', detect: (f) => has(f, (x) => /reflected xss/i.test(x.title)) },
  { id: 'sqli', label: 'SQL Injection', detect: (f) => has(f, (x) => /sql injection/i.test(x.title)) },
  { id: 'cmdi', label: 'OS Command Injection', detect: (f) => has(f, (x) => /command injection/i.test(x.title)) },
  { id: 'ssrf', label: 'SSRF', detect: (f) => has(f, (x) => /server-side request forgery|ssrf/i.test(x.title)) },
  { id: 'graphql', label: 'GraphQL Introspection', detect: (f) => has(f, (x) => /graphql/i.test(x.title)) },
  { id: 'bola', label: 'Broken Object Level Authorization', detect: (f) => has(f, (x) => /object level authorization|bola/i.test(x.title)) },
  { id: 'env', label: 'Exposed .env file', detect: (f) => has(f, (x) => /exposed/i.test(x.title) && /\.env/i.test(x.title + x.description)) },
];

export interface TargetScore {
  detected: string[];
  expectedPresent: string[];
  truePositives: string[];
  falsePositives: string[];
  missed: string[];
  validatedCount: number;
}

/** Score one target's findings against the set of checks expected to be present. */
export function scoreTarget(findings: Finding[], expectedPresent: string[]): TargetScore {
  const expected = new Set(expectedPresent);
  const detected = ACTIVE_CHECKS.filter((c) => c.detect(findings)).map((c) => c.id);
  const detectedSet = new Set(detected);
  return {
    detected,
    expectedPresent,
    truePositives: detected.filter((id) => expected.has(id)),
    falsePositives: detected.filter((id) => !expected.has(id)),
    missed: expectedPresent.filter((id) => !detectedSet.has(id)),
    validatedCount: findings.filter((f) => f.validated).length,
  };
}

export interface BenchmarkMetrics {
  truePositives: number;
  falseNegatives: number;
  falsePositives: number;
  trueNegatives: number;
  detectionRate: number; // recall: TP / (TP + FN)
  falsePositiveRate: number; // FP / (FP + TN)
  precision: number; // TP / (TP + FP)
}

/**
 * Aggregate per-target scores into overall metrics. `cleanExpected` is the set
 * of checks that *should not* fire on the clean target (used to count true
 * negatives for the FP rate).
 */
export function aggregate(vulnerable: TargetScore, clean: TargetScore): BenchmarkMetrics {
  const truePositives = vulnerable.truePositives.length;
  const falseNegatives = vulnerable.missed.length;
  const falsePositives = clean.falsePositives.length;
  const trueNegatives = ACTIVE_CHECKS.length - falsePositives;

  const detectionRate = truePositives + falseNegatives === 0 ? 1 : truePositives / (truePositives + falseNegatives);
  const falsePositiveRate = falsePositives + trueNegatives === 0 ? 0 : falsePositives / (falsePositives + trueNegatives);
  const precision = truePositives + falsePositives === 0 ? 1 : truePositives / (truePositives + falsePositives);

  return {
    truePositives,
    falseNegatives,
    falsePositives,
    trueNegatives,
    detectionRate,
    falsePositiveRate,
    precision,
  };
}

/** Every active check is expected on the vulnerable target. */
export const ALL_CHECK_IDS = ACTIVE_CHECKS.map((c) => c.id);
