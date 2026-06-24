import { Clock, Shield, FileText } from 'lucide-react';
import { Scan, Finding } from '../../types.js';
import { SecCategory, getCategoryCount, categoryTabLabels } from './reportHelpers.js';

interface ReportMetaCardProps {
  scan: Scan;
  previousScan?: Scan;
  findings: Finding[];
  activeTab: 'OVERVIEW' | SecCategory | 'compliance';
  onSetActiveTab: (tab: 'OVERVIEW' | SecCategory | 'compliance') => void;
}

/**
 * Audit meta summary card header: target host, score/findings delta vs the
 * previous scan, AppSec score, posture rating, and the segmented module
 * tab bar (Overview / per-category / Compliance). Does not render the tab
 * body content — callers compose that alongside this component.
 */
export default function ReportMetaCard({
  scan,
  previousScan,
  findings,
  activeTab,
  onSetActiveTab,
}: ReportMetaCardProps) {
  const score = scan.score || 100;
  const isMediumRisk = score >= 60 && score < 85;
  const isLowRisk = score >= 85;

  const scoreColorClass =
    isLowRisk ? 'text-[#22c55e] border-[#22c55e]/25 bg-[#22c55e]/5' :
    isMediumRisk ? 'text-amber-400 border-amber-500/20 bg-amber-500/5' :
    'text-red-400 border-red-500/20 bg-red-500/5';

  return (
    <>
      <div className="bg-black/40 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6 border-b border-[#27272a]">
        <div>
          <div className="flex items-center space-x-2.5">
            <span className="font-mono text-xs text-[#52525b] select-none">[Target Host]</span>
            <strong className="font-mono text-sm text-white tracking-wide break-all select-all">{scan.url}</strong>
          </div>
          <p className="text-[#52525b] text-xs mt-2 font-mono flex items-center space-x-4">
            <span className="flex items-center space-x-1">
              <Clock className="w-3.5 h-3.5 text-[#52525b]" />
              <span>Assessed: {new Date(scan.createdAt).toLocaleDateString()}</span>
            </span>
            <span>•</span>
            <span>Job ID: {scan.id}</span>
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 shrink-0">
          {previousScan && (
            <div className="p-4 rounded border border-zinc-800 bg-black flex items-center space-x-5 h-full">
              <div className="text-right">
                <span className="text-[9px] font-mono text-zinc-500 uppercase block tracking-wider select-none">Score Delta</span>
                <span className={`text-xl font-mono font-black block mt-1 ${scan.score > previousScan.score ? 'text-green-500' : scan.score < previousScan.score ? 'text-red-500' : 'text-zinc-500'}`}>
                  {scan.score > previousScan.score ? '+' : ''}{scan.score - previousScan.score}
                </span>
              </div>
              <div className="border-l border-zinc-800 pl-4 text-right">
                <span className="text-[9px] font-mono text-zinc-500 uppercase block tracking-wider select-none">Findings Delta</span>
                <span className={`text-xl font-mono font-black block mt-1 ${findings.length < previousScan.findings!.length ? 'text-green-500' : findings.length > previousScan.findings!.length ? 'text-amber-500' : 'text-zinc-500'}`}>
                  {findings.length > previousScan.findings!.length ? '+' : ''}{findings.length - previousScan.findings!.length}
                </span>
              </div>
            </div>
          )}
          <div className={`p-4 rounded border flex items-center space-x-5 h-full shrink-0 ${scoreColorClass}`}>
            <div className="text-right">
              <span className="text-[9px] font-mono text-[#52525b] uppercase block tracking-wider select-none">AppSec Score</span>
              <span className="text-3xl font-mono font-black leading-none">{scan.score}<span className="text-xs text-[#52525b] font-normal">/100</span></span>
            </div>
            <div className="border-l border-[#27272a] pl-4">
              <span className="text-[9px] font-mono text-[#52525b] uppercase block tracking-wider select-none">Posture Rating</span>
              <span className="text-xs font-mono font-bold uppercase tracking-wider block mt-1">{scan.severity}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Core AppSec Framework Segmented Matrix tabs */}
      <div className="flex overflow-x-auto border-b border-[#27272a] bg-black/20 select-none scrollbar-none">
        <button
          onClick={() => onSetActiveTab('OVERVIEW')}
          className={`px-5 py-4 border-b-2 text-xs font-mono uppercase tracking-wider font-semibold transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
            activeTab === 'OVERVIEW'
              ? 'border-[#22c55e] text-white bg-black/40'
              : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
          }`}
        >
          <Shield className="w-4 h-4 text-[#22c55e]" />
          <span>Executive Overview</span>
        </button>

        {categoryTabLabels.map(cat => {
          const count = getCategoryCount(findings, cat.key);
          const hasAlerts = count > 0;
          return (
            <button
              key={cat.key}
              onClick={() => onSetActiveTab(cat.key)}
              className={`px-5 py-4 border-b-2 text-xs font-mono uppercase tracking-wider transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
                activeTab === cat.key
                  ? 'border-[#22c55e] text-white bg-black/40'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              <cat.icon className={`w-4 h-4 ${activeTab === cat.key ? 'text-[#22c55e]' : 'text-[#52525b]'}`} />
              <span className="font-bold">{cat.label}</span>
              <span className={`text-[10px] px-1.5 py-0.2 ml-1 rounded font-mono ${
                hasAlerts
                  ? 'bg-red-500/10 text-red-400 border border-red-500/25'
                  : 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/25'
              }`}>
                {count}
              </span>
            </button>
          );
        })}

        <button
          onClick={() => onSetActiveTab('compliance')}
          className={`px-5 py-4 border-b-2 text-xs font-mono uppercase tracking-wider font-semibold transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
            activeTab === 'compliance'
              ? 'border-[#22c55e] text-white font-bold bg-black/40'
              : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
          }`}
        >
          <FileText className={`w-4 h-4 ${activeTab === 'compliance' ? 'text-[#22c55e]' : 'text-[#52525b]'}`} />
          <span>[+] Compliance Report</span>
        </button>
      </div>
    </>
  );
}
