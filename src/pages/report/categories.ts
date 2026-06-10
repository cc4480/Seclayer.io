import { Code, Globe, Zap, Package, Grid, Server, Terminal } from 'lucide-react';
import { Finding } from '../../types.js';

export type SecCategory = 'SAST' | 'DAST' | 'IAST' | 'SCA' | 'EASM' | 'RED_TEAM' | 'API_SEC';

export const categoryTabLabels = [
  { key: 'SAST' as const, label: 'SAST', icon: Code, term: 'Static Analysis' },
  { key: 'DAST' as const, label: 'DAST', icon: Globe, term: 'Dynamic Audit' },
  { key: 'IAST' as const, label: 'IAST', icon: Zap, term: 'Interactive Policies' },
  { key: 'SCA' as const, label: 'SCA', icon: Package, term: 'Composition Review' },
  { key: 'EASM' as const, label: 'EASM', icon: Grid, term: 'Attack Surface' },
  { key: 'API_SEC' as const, label: 'API SEC', icon: Server, term: 'API Security Testing' },
  { key: 'RED_TEAM' as const, label: 'RED TEAM', icon: Terminal, term: 'Red Team Active Probes' },
];

export function getCategoryCount(findings: Finding[], cat: SecCategory) {
  return findings.filter(f => f.category === cat).length;
}

export function getCategorySeverity(findings: Finding[], cat: SecCategory) {
  const catFindings = findings.filter(f => f.category === cat);
  if (catFindings.length === 0) return 'SECURE';
  if (catFindings.some(f => f.severity === 'critical' || f.severity === 'high')) return 'HIGH RISK';
  if (catFindings.some(f => f.severity === 'medium')) return 'MODERATE';
  return 'LOW RISK';
}

export function getCategoryColor(findings: Finding[], cat: SecCategory) {
  const status = getCategorySeverity(findings, cat);
  if (status === 'SECURE') return 'text-[#22c55e] border-[#22c55e]/20 bg-[#22c55e]/5';
  if (status === 'HIGH RISK') return 'text-red-400 border-red-500/20 bg-red-500/5';
  if (status === 'MODERATE') return 'text-amber-400 border-amber-500/20 bg-amber-500/5';
  return 'text-blue-400 border-blue-500/20 bg-blue-500/5';
}
