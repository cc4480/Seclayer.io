import React from 'react';
import { Shield, Check, CheckCircle2 } from 'lucide-react';
import { Finding } from '../../types.js';
import { SecCategory, categoryTabLabels, getCategorySeverity } from './categories.js';
import FindingCard from './FindingCard.js';

interface ModuleFindingsTabProps {
  category: SecCategory;
  findings: Finding[];
  copiedCodeId: string | null;
  onCopyCode: (id: string, text: string) => void;
  expandedApiRows: Record<string, boolean>;
  onToggleExpanded: (findingId: string) => void;
  suppression: {
    suppressInputId: string | null;
    suppressReason: string;
    setSuppressReason: (value: string) => void;
    isSuppressing: boolean;
    suppressError: string | null;
    openSuppress: (findingId: string) => void;
    closeSuppress: () => void;
    saveSuppression: (finding: Finding) => void;
    removeSuppression: (findingTitle: string) => void;
  };
}

/** Findings list for one security module tab: title card, empty state, or FindingCard list. */
export default function ModuleFindingsTab({
  category,
  findings,
  copiedCodeId,
  onCopyCode,
  expandedApiRows,
  onToggleExpanded,
  suppression,
}: ModuleFindingsTabProps) {
  const catMeta = categoryTabLabels.find(c => c.key === category);
  const catFindings = findings.filter(f => f.category === category);

  return (
    <div className="space-y-6 animate-fade-in">

      {/* Module title cards */}
      <div className="flex items-center justify-between border-b border-[#27272a] pb-4">
        <div>
          <h4 className="text-white text-sm font-bold font-mono tracking-tight uppercase flex items-center space-x-2">
            {React.createElement(catMeta?.icon || Shield, { className: 'w-5 h-5 text-[#22c55e]' })}
            <span>{catMeta?.label} Module Findings</span>
          </h4>
          <span className="text-[10px] font-mono text-[#52525b] uppercase mt-1 block">
            {catMeta?.term}
          </span>
        </div>
        <span className="text-[10px] font-mono text-zinc-400 block uppercase font-extrabold bg-[#18181b] border border-[#27272a] px-2.5 py-1">
          Risk Assessment: {getCategorySeverity(findings, category)}
        </span>
      </div>

      {/* Filtered list of findings */}
      {catFindings.length === 0 ? (
        <div className="text-center py-16 bg-black/40 rounded border border-dashed border-[#27272a] flex flex-col items-center">
          <CheckCircle2 className="w-10 h-10 text-[#22c55e] mb-3" />
          <span className="text-xs text-white font-bold font-mono uppercase block">Zero Vulnerabilities Outstanding</span>
          <p className="text-[11px] text-[#52525b] mt-1.5 font-mono max-w-md">
            Your current configurations satisfy standard defensive criteria in {catMeta?.term}.
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
          {catFindings.map(finding => (
            <FindingCard
              key={finding.id}
              finding={finding}
              copiedCodeId={copiedCodeId}
              onCopyCode={onCopyCode}
              expanded={!!expandedApiRows[finding.id]}
              onToggleExpanded={() => onToggleExpanded(finding.id)}
              suppressOpen={suppression.suppressInputId === finding.id}
              suppressReason={suppression.suppressReason}
              suppressError={suppression.suppressError}
              isSuppressing={suppression.isSuppressing}
              onOpenSuppress={() => suppression.openSuppress(finding.id)}
              onCloseSuppress={suppression.closeSuppress}
              onSuppressReasonChange={suppression.setSuppressReason}
              onSaveSuppression={() => suppression.saveSuppression(finding)}
              onRemoveSuppression={() => suppression.removeSuppression(finding.title)}
            />
          ))}
        </div>
      )}

    </div>
  );
}
