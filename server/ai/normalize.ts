import { Finding, Severity } from '../../src/types.js';
import { VALID_CATEGORIES } from './client.js';

export function normalizeCategory(raw: string): string {
  const cat = String(raw || '').toUpperCase().replace(/[\s-]/g, '_');
  if ((VALID_CATEGORIES as readonly string[]).includes(cat)) return cat;
  if (cat.includes('RED') || cat.includes('TEAM') || cat.includes('FUZZ') || cat.includes('EXPLOIT')) return 'RED_TEAM';
  if (cat.includes('STATIC') || cat.includes('CODE') || cat.includes('SECRET') || cat.includes('KEY')) return 'SAST';
  if (cat.includes('DEPEND') || cat.includes('LIBRAR') || cat.includes('COMPOSIT') || cat.includes('SOFTWARE')) return 'SCA';
  if (cat.includes('INTERACTIVE') || cat.includes('COOKIE') || cat.includes('SESSION')) return 'IAST';
  if (cat.includes('SURFACE') || cat.includes('DNS') || cat.includes('PORT') || cat.includes('SSL') || cat.includes('CERT')) return 'EASM';
  return 'DAST';
}

export function compileLocalSummary(url: string, sc: { score: number; severity: Severity; findings: Finding[] }): string {
  if (sc.severity === 'critical' || sc.severity === 'high') {
    return `Your app at ${url} has serious security issues that need fixing before you launch. An attacker could compromise user accounts or steal data. Fix the critical findings first.`;
  }
  if (sc.severity === 'medium') {
    return `Your app at ${url} has some security gaps worth addressing before you go live. No critical exposures were found, but the issues flagged could be exploited by a motivated attacker.`;
  }
  return `Your app at ${url} looks secure. No major vulnerabilities were found. A few minor improvements are noted below.`;
}
