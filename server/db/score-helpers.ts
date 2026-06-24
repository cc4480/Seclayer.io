import { Finding, Severity } from '../../src/types.js';

export function cleanUrl(urlStr: string): string {
  try {
    return urlStr.replace(/https?:\/\//i, '').replace(/\/+$/, '').trim().toLowerCase();
  } catch {
    return String(urlStr || '').trim().toLowerCase();
  }
}

export function recalculateScore(findings: Finding[]): { score: number; severity: Severity } {
  let score = 100;
  const active = findings.filter(f => !f.isFalsePositive);

  active.forEach(f => {
    const s = f.severity?.toLowerCase();
    if (s === 'critical') score -= 35;
    else if (s === 'high') score -= 25;
    else if (s === 'medium') score -= 15;
    else if (s === 'low') score -= 5;
  });

  score = Math.max(12, Math.min(100, score));

  let severity: Severity = 'low';
  if (active.some(f => f.severity === 'critical')) severity = 'critical';
  else if (active.some(f => f.severity === 'high')) severity = 'high';
  else if (active.some(f => f.severity === 'medium')) severity = 'medium';

  return { score, severity };
}
