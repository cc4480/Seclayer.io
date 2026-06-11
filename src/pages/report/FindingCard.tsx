import React from 'react';
import { Check, Clipboard, Terminal, ChevronDown, ChevronUp, Copy, ShieldCheck } from 'lucide-react';
import { Finding } from '../../types.js';
import SuppressionPanel from './SuppressionPanel.js';

interface FindingCardProps {
  // The project compiles without @types/react, so the special React `key`
  // prop must be declared explicitly for keyed-list usage to typecheck.
  key?: string;
  finding: Finding;
  copiedCodeId: string | null;
  onCopyCode: (id: string, text: string) => void;
  expanded: boolean;
  onToggleExpanded: () => void;
  suppressOpen: boolean;
  suppressReason: string;
  suppressError: string | null;
  isSuppressing: boolean;
  onOpenSuppress: () => void;
  onCloseSuppress: () => void;
  onSuppressReasonChange: (value: string) => void;
  onSaveSuppression: () => void;
  onRemoveSuppression: () => void;
}

/** One finding: severity badges, remediation fix block, raw probe drawer, and FP suppression UI. */
export default function FindingCard({
  finding,
  copiedCodeId,
  onCopyCode,
  expanded,
  onToggleExpanded,
  suppressOpen,
  suppressReason,
  suppressError,
  isSuppressing,
  onOpenSuppress,
  onCloseSuppress,
  onSuppressReasonChange,
  onSaveSuppression,
  onRemoveSuppression,
}: FindingCardProps) {
  let severityColor = 'bg-black text-[#52525b] border border-[#27272a]';
  if (finding.isFalsePositive) severityColor = 'bg-zinc-800 text-zinc-400 border border-zinc-700/60 font-medium';
  else if (finding.severity === 'critical') severityColor = 'bg-red-500/10 border border-red-500/25 text-red-400 font-bold';
  else if (finding.severity === 'high') severityColor = 'bg-red-500/10 border border-red-500/20 text-rose-400';
  else if (finding.severity === 'medium') severityColor = 'bg-amber-500/10 border border-amber-500/20 text-amber-400';
  else if (finding.severity === 'low') severityColor = 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/25';

  return (
    <div
      className={`border rounded p-5 transition-colors shadow ${
        finding.isFalsePositive
          ? 'bg-[#0f0f11]/60 border-zinc-800 border-dashed opacity-70 hover:border-zinc-750'
          : 'bg-black border-[#27272a]/90 hover:border-[#3f3f46]'
      }`}
    >

      {/* Title element */}
      <div className="flex flex-wrap items-start justify-between gap-2 mb-3">
        <div className="flex items-center space-x-2.5">
          <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded ${severityColor}`}>
            {finding.isFalsePositive ? 'SUPPRESSED (FP)' : finding.severity}
          </span>
          {finding.confidence && (
            <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded border bg-black ${
              finding.confidence === 'high' ? 'border-[#22c55e]/30 text-[#22c55e]' :
              finding.confidence === 'medium' ? 'border-amber-500/30 text-amber-500' :
              'border-zinc-500/30 text-zinc-500'
            }`}>
              Conf: {finding.confidence}
            </span>
          )}
          {finding.validated && !finding.isFalsePositive && (
            <span
              className="text-[9px] font-mono uppercase px-2 py-0.5 rounded border border-[#22c55e]/40 bg-[#22c55e]/10 text-[#22c55e] inline-flex items-center space-x-1"
              title="Re-confirmed by an active probe with a reproducible proof-of-concept"
            >
              <ShieldCheck className="w-3 h-3 shrink-0" />
              <span>Validated PoC</span>
            </span>
          )}
          <h5 className={`text-xs font-bold font-mono tracking-tight leading-snug ${finding.isFalsePositive ? 'text-zinc-500 line-through' : 'text-white'}`}>{finding.title}</h5>
        </div>
        <span className="text-[10px] text-[#52525b] font-mono tracking-wide">ID: {finding.id}</span>
      </div>

      {/* Detail summary */}
      <p className={`text-xs font-mono leading-relaxed mb-4 pl-1 ${finding.isFalsePositive ? 'text-zinc-500' : 'text-[#a1a1aa]'}`}>
        {finding.description}
      </p>

      {/* Detailed Remediation code fix payload block */}
      <div className={`p-4 rounded border ${finding.isFalsePositive ? 'bg-zinc-950/40 border-zinc-850' : 'bg-[#0c0c0e] border-[#27272a]'}`}>
        <div className="flex justify-between items-center mb-1.5">
          <span className="text-[#52525b] font-mono text-[9px] uppercase tracking-wider">Automated Remediation Fix</span>
          <button
            onClick={() => onCopyCode(finding.id, finding.fix)}
            className="text-[10px] font-mono text-[#52525b] hover:text-[#22c55e] flex items-center space-x-1 transition-colors cursor-pointer"
          >
            {copiedCodeId === finding.id ? (
              <>
                <Check className="w-3 h-3 text-[#22c55e] shrink-0" />
                <span>Copied fix</span>
              </>
            ) : (
              <>
                <Clipboard className="w-3 h-3 text-[#52525b] shrink-0" />
                <span>Copy directive</span>
              </>
            )}
          </button>
        </div>
        <div className="overflow-x-auto max-h-48 scrollbar-thin">
          <code className={`text-[11px] font-mono whitespace-pre leading-relaxed block py-1 ${finding.isFalsePositive ? 'text-zinc-600' : 'text-zinc-300'}`}>
            {finding.fix}
          </code>
        </div>
      </div>

      {/* Raw Request / Response Collapsible Drawer for API_SEC / Payload details */}
      {(finding.rawRequest || finding.rawResponse) && (
        <div className="mt-3">
          <button
            onClick={onToggleExpanded}
            className="w-full flex items-center justify-between p-3 rounded bg-zinc-950/40 hover:bg-zinc-900 border border-zinc-800/80 transition-colors cursor-pointer group"
          >
            <span className={`flex items-center space-x-2 text-[10px] font-mono uppercase tracking-wider font-bold transition-colors ${
              finding.validated ? 'text-[#22c55e] group-hover:text-[#4ade80]' : 'text-zinc-400 group-hover:text-amber-400'
            }`}>
              {finding.validated ? <ShieldCheck className="w-3.5 h-3.5 shrink-0" /> : <Terminal className="w-3.5 h-3.5 shrink-0" />}
              <span>{finding.validated ? 'Validated Exploit — Reproducible PoC (curl)' : 'Raw HTTP Probes & Response Dump'}</span>
            </span>
            {expanded ? <ChevronUp className="w-4 h-4 text-zinc-500" /> : <ChevronDown className="w-4 h-4 text-zinc-500" />}
          </button>

          {expanded && (
            <div className="mt-2 space-y-2 animate-fade-in">
              {finding.endpoint && (
                <div className="p-3 bg-black border border-zinc-800 rounded font-mono text-[10px] text-zinc-300 overflow-x-auto">
                  <span className="text-zinc-500 select-none block mb-1">Target Endpoint:</span>
                  {finding.endpoint}
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {finding.rawRequest && (
                  <div className="p-3 bg-black border border-zinc-800 rounded relative overflow-hidden group">
                    <div className="absolute top-0 left-0 w-full bg-zinc-900/80 p-1.5 border-b border-zinc-800 text-[9px] uppercase tracking-wider font-mono text-amber-500/80 flex items-center justify-between">
                      <span>Raw Request</span>
                      <button onClick={() => onCopyCode(`req-${finding.id}`, finding.rawRequest!)} className="text-zinc-500 hover:text-white cursor-pointer"><Copy className="w-3 h-3"/></button>
                    </div>
                    <div className="pt-6 overflow-x-auto max-h-64 scrollbar-thin">
                      <code className="text-[10px] font-mono whitespace-pre text-zinc-400 break-all">{finding.rawRequest}</code>
                    </div>
                  </div>
                )}
                {finding.rawResponse && (
                  <div className="p-3 bg-black border border-zinc-800 rounded relative overflow-hidden group">
                    <div className="absolute top-0 left-0 w-full bg-zinc-900/80 p-1.5 border-b border-zinc-800 text-[9px] uppercase tracking-wider font-mono text-red-400/80 flex items-center justify-between">
                      <span>Raw Response</span>
                      <button onClick={() => onCopyCode(`res-${finding.id}`, finding.rawResponse!)} className="text-zinc-500 hover:text-white cursor-pointer"><Copy className="w-3 h-3"/></button>
                    </div>
                    <div className="pt-6 overflow-x-auto max-h-64 scrollbar-thin">
                      <code className="text-[10px] font-mono whitespace-pre text-zinc-400 break-all">{finding.rawResponse}</code>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* False Positives Management UI Drawer Toggle */}
      <SuppressionPanel
        finding={finding}
        suppressOpen={suppressOpen}
        suppressReason={suppressReason}
        suppressError={suppressError}
        isSuppressing={isSuppressing}
        onOpenSuppress={onOpenSuppress}
        onCloseSuppress={onCloseSuppress}
        onSuppressReasonChange={onSuppressReasonChange}
        onSaveSuppression={onSaveSuppression}
        onRemoveSuppression={onRemoveSuppression}
      />

    </div>
  );
}
