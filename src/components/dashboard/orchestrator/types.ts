export type SubTab = 'aspm' | 'easm' | 'apiscan' | 'iast' | 'pentagi';

export const subTabs: Array<{ id: SubTab; label: string; subtitle: string }> = [
  { id: 'aspm', label: 'ASPM Correlation', subtitle: 'DefectDojo & Fusion' },
  { id: 'easm', label: 'EASM Perimeter', subtitle: 'Amass Subdomains' },
  { id: 'apiscan', label: 'API Security Testing', subtitle: 'Hadrian Matrix' },
  { id: 'iast', label: 'Interactive Passive Testing', subtitle: 'DongTai IAST Tracer' },
  { id: 'pentagi', label: 'Autonomous Pentest AI', subtitle: 'PentAGI Cooperative Agents' },
];

export const severityColor = (s: string) =>
  s === 'critical' ? 'text-red-400 bg-red-950/30 border-red-900/40' :
  s === 'high' ? 'text-[#f87171] bg-[#f87171]/10 border-[#f87171]/20' :
  s === 'medium' ? 'text-amber-400 bg-amber-950/20 border-amber-900/30' :
  'text-[#a1a1aa] bg-black border-[#27272a]';
