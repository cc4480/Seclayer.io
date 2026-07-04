import React from 'react';
import { Shield, Check, CheckCircle2 } from 'lucide-react';
import { Finding } from '../../types.js';
import { SecCategory, categoryTabLabels, getCategorySeverity } from './categories.js';
import { SuppressionState } from './useSuppression.js';
import FindingCard from './FindingCard.js';

interface FindingsTabProps {
  activeTab: SecCategory;
  findings: Finding[];
  copiedCodeId: string | null;
  onCopyCode: (findingId: string, fixText: string) => void;
  expandedApiRows: Record<string, boolean>;
  onToggleExpand: (findingId: string) => void;
  sup: SuppressionState;
}

export default function FindingsTab({ activeTab, findings, copiedCodeId, onCopyCode, expandedApiRows, onToggleExpand, sup }: FindingsTabProps) {
  const meta = categoryTabLabels.find(c => c.key === activeTab);
  const moduleFindings = findings.filter(f => f.category === activeTab);

  return (
    <div className="space-y-6 animate-fade-in">

      {/* Module title cards */}
      <div className="flex items-center justify-between border-b border-[#27272a] pb-4">
        <div>
          <h4 className="text-white text-sm font-bold font-mono tracking-tight uppercase flex items-center space-x-2">
            {React.createElement(meta?.icon || Shield, { className: 'w-5 h-5 text-[#22c55e]' })}
            <span>{meta?.label} Module Findings</span>
          </h4>
          <span className="text-[10px] font-mono text-[#52525b] uppercase mt-1 block">
            {meta?.term}
          </span>
        </div>
        <span className="text-[10px] font-mono text-zinc-400 block uppercase font-extrabold bg-[#18181b] border border-[#27272a] px-2.5 py-1">
          Risk Assessment: {getCategorySeverity(findings, activeTab)}
        </span>
      </div>

      {/* Filtered list of findings */}
      {moduleFindings.length === 0 ? (
        <div className="text-center py-16 bg-black/40 rounded border border-dashed border-[#27272a] flex flex-col items-center">
          <CheckCircle2 className="w-10 h-10 text-[#22c55e] mb-3" />
          <span className="text-xs text-white font-bold font-mono uppercase block">Zero Vulnerabilities Outstanding</span>
          <p className="text-[11px] text-[#52525b] mt-1.5 font-mono max-w-md">
            Your current configurations satisfy standard defensive criteria in {meta?.term}.
          </p>
          <div className="mt-5 grid grid-cols-2 gap-3 max-w-sm w-full font-mono text-[9px] text-[#52525b] text-left">
            <div className="flex items-center space-x-1">
              <Check className="w-3 h-3 text-[#22c55e]" />
              <span>Hardening complete</span>
            </div>
            <div className="flex items-center space-x-1">
              <Check className="w-3 h-3 text-[#22c55e]" />
              <span>Continuous evaluation active</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {moduleFindings.map(finding => (
            <div key={finding.id}>
              <FindingCard
                finding={finding}
                copiedCodeId={copiedCodeId}
                onCopyCode={onCopyCode}
                expanded={!!expandedApiRows[finding.id]}
                onToggleExpand={() => onToggleExpand(finding.id)}
                sup={sup}
              />
            </div>
          ))}
        </div>
      )}

    </div>
  );
}
