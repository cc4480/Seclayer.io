import React from 'react';
import { Shield, Check, CheckCircle2 } from 'lucide-react';
import { Finding } from '../../types.js';
import {
  SecCategory,
  REMEDIATION_META,
  remediationStatusOf,
  getCategorySeverity,
  categoryTabLabels,
} from './reportHelpers.js';
import FindingCard from './FindingCard.js';

interface ModuleFindingsTabProps {
  activeTab: SecCategory;
  findings: Finding[];
  moduleFindings: Finding[];
  statusFilter: 'all' | 'open' | 'in_progress' | 'fixed' | 'verified';
  onStatusFilterChange: (status: 'all' | 'open' | 'in_progress' | 'fixed' | 'verified') => void;
  copiedCodeId: string | null;
  recheckingId: string | null;
  recheckMsg: Record<string, { ok: boolean; text: string }>;
  autoFixingId: string | null;
  autoFixMsg: Record<string, { ok: boolean; text: string; prUrl?: string }>;
  suppressInputId: string | null;
  suppressReason: string;
  isSuppressing: boolean;
  suppressError: string | null;
  onSetRemediation: (finding: Finding, status: string) => void;
  onRecheck: (finding: Finding) => void;
  onAutoFix: (finding: Finding) => void;
  onSaveSuppression: (finding: Finding) => void;
  onRemoveSuppressionDirectly: (findingTitle: string) => void;
  onCopyCode: (findingId: string, fixText: string) => void;
  onOpenSuppressInput: (findingId: string) => void;
  onCloseSuppressInput: () => void;
  onSuppressReasonChange: (reason: string) => void;
}

export default function ModuleFindingsTab({
  activeTab,
  findings,
  moduleFindings,
  statusFilter,
  onStatusFilterChange,
  copiedCodeId,
  recheckingId,
  recheckMsg,
  autoFixingId,
  autoFixMsg,
  suppressInputId,
  suppressReason,
  isSuppressing,
  suppressError,
  onSetRemediation,
  onRecheck,
  onAutoFix,
  onSaveSuppression,
  onRemoveSuppressionDirectly,
  onCopyCode,
  onOpenSuppressInput,
  onCloseSuppressInput,
  onSuppressReasonChange,
}: ModuleFindingsTabProps) {
  const activeCategory = categoryTabLabels.find(c => c.key === activeTab);

  return (
    <div className="space-y-6 animate-fade-in">

      {/* Module title cards */}
      <div className="flex items-center justify-between border-b border-[#27272a] pb-4">
        <div>
          <h4 className="text-white text-sm font-bold font-mono tracking-tight uppercase flex items-center space-x-2">
            {React.createElement(activeCategory?.icon || Shield, { className: 'w-5 h-5 text-[#22c55e]' })}
            <span>{activeCategory?.label} Module Findings</span>
          </h4>
          <span className="text-[10px] font-mono text-[#52525b] uppercase mt-1 block">
            {activeCategory?.term}
          </span>
        </div>
        <span className="text-[10px] font-mono text-zinc-400 block uppercase font-extrabold bg-[#18181b] border border-[#27272a] px-2.5 py-1">
          Risk Assessment: {getCategorySeverity(findings, activeTab)}
        </span>
      </div>

      {/* Remediation status filter */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[9px] font-mono uppercase tracking-wider text-[#52525b]">Status:</span>
        {(['all', 'open', 'in_progress', 'fixed', 'verified'] as const).map(s => {
          const count = s === 'all'
            ? findings.filter(f => f.category === activeTab).length
            : findings.filter(f => f.category === activeTab && remediationStatusOf(f) === s).length;
          return (
            <button
              key={s}
              onClick={() => onStatusFilterChange(s)}
              className={`text-[9px] font-mono uppercase tracking-wider px-2.5 py-1 rounded border transition-colors cursor-pointer ${
                statusFilter === s
                  ? 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30'
                  : 'bg-black text-[#52525b] border-[#27272a] hover:text-zinc-300'
              }`}
            >
              {s === 'all' ? 'All' : REMEDIATION_META[s].label} ({count})
            </button>
          );
        })}
      </div>

      {/* Filtered list of findings */}
      {moduleFindings.length === 0 ? (
        <div className="text-center py-16 bg-black/40 rounded border border-dashed border-[#27272a] flex flex-col items-center">
          <CheckCircle2 className="w-10 h-10 text-[#22c55e] mb-3" />
          <span className="text-xs text-white font-bold font-mono uppercase block">Zero Vulnerabilities Outstanding</span>
          <p className="text-[11px] text-[#52525b] mt-1.5 font-mono max-w-md">
            Your current configurations satisfy standard defensive criteria in {activeCategory?.term}.
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
            <FindingCard
              key={finding.id}
              finding={finding}
              copiedCodeId={copiedCodeId}
              recheckingId={recheckingId}
              recheckMsg={recheckMsg}
              autoFixingId={autoFixingId}
              autoFixMsg={autoFixMsg}
              suppressInputId={suppressInputId}
              suppressReason={suppressReason}
              isSuppressing={isSuppressing}
              suppressError={suppressError}
              onSetRemediation={onSetRemediation}
              onRecheck={onRecheck}
              onAutoFix={onAutoFix}
              onSaveSuppression={onSaveSuppression}
              onRemoveSuppressionDirectly={onRemoveSuppressionDirectly}
              onCopyCode={onCopyCode}
              onOpenSuppressInput={onOpenSuppressInput}
              onCloseSuppressInput={onCloseSuppressInput}
              onSuppressReasonChange={onSuppressReasonChange}
            />
          ))}
        </div>
      )}

    </div>
  );
}
