import { Check, Clipboard, Code } from 'lucide-react';
import { Finding } from '../../types.js';
import { REMEDIATION_META, remediationStatusOf } from './reportHelpers.js';
import FindingRawDrawer from './FindingRawDrawer.js';
import FindingRemediationControls from './FindingRemediationControls.js';
import FindingSuppressionPanel from './FindingSuppressionPanel.js';

interface FindingCardProps {
  key?: string;
  finding: Finding;
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

export default function FindingCard({
  finding,
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
}: FindingCardProps) {
  let severityColor = 'bg-black text-[#52525b] border border-[#27272a]';
  if (finding.isFalsePositive) severityColor = 'bg-zinc-800 text-zinc-400 border border-zinc-700/60 font-medium';
  else if (finding.severity === 'critical') severityColor = 'bg-red-500/10 border border-red-500/25 text-red-400 font-bold';
  else if (finding.severity === 'high') severityColor = 'bg-red-500/10 border border-red-500/20 text-rose-400';
  else if (finding.severity === 'medium') severityColor = 'bg-amber-500/10 border border-amber-500/20 text-amber-400';
  else if (finding.severity === 'low') severityColor = 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/25';

  return (
    <div
      key={finding.id}
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
          <h5 className={`text-xs font-bold font-mono tracking-tight leading-snug ${finding.isFalsePositive ? 'text-zinc-500 line-through' : 'text-white'}`}>{finding.title}</h5>
          {!finding.isFalsePositive && (
            <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded border ${REMEDIATION_META[remediationStatusOf(finding)].cls}`}>
              {REMEDIATION_META[remediationStatusOf(finding)].label}
            </span>
          )}
        </div>
        <span className="text-[10px] text-[#52525b] font-mono tracking-wide">ID: {finding.id}</span>
      </div>

      {/* Detail summary */}
      <p className={`text-xs font-mono leading-relaxed mb-3 pl-1 ${finding.isFalsePositive ? 'text-zinc-500' : 'text-[#a1a1aa]'}`}>
        {finding.description}
      </p>

      {/* Plain English impact — visible to solo devs */}
      {finding.plainEnglish && (
        <div className="mb-4 pl-1 py-2.5 px-3 rounded border border-[#22c55e]/15 bg-[#22c55e]/5 flex items-start space-x-2">
          <span className="text-[#22c55e] font-mono text-[9px] uppercase tracking-wider font-bold shrink-0 mt-0.5">What this means:</span>
          <p className="text-[#a1a1aa] text-[11px] font-sans leading-relaxed">{finding.plainEnglish}</p>
        </div>
      )}

      {/* Remediation fix */}
      <div className={`p-4 rounded border ${finding.isFalsePositive ? 'bg-zinc-950/40 border-zinc-850' : 'bg-[#0c0c0e] border-[#27272a]'}`}>
        <div className="flex justify-between items-center mb-1.5">
          <span className="text-[#52525b] font-mono text-[9px] uppercase tracking-wider">Remediation Steps</span>
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

      {/* Code fix example */}
      {finding.codeFixExample && (
        <div className="mt-3 p-4 rounded border border-[#27272a] bg-black">
          <div className="flex justify-between items-center mb-2">
            <span className="text-[#22c55e] font-mono text-[9px] uppercase tracking-wider font-bold flex items-center space-x-1.5">
              <Code className="w-3 h-3" />
              <span>Code Fix Example</span>
            </span>
            <button
              onClick={() => onCopyCode(`code-${finding.id}`, finding.codeFixExample!)}
              className="text-[10px] font-mono text-[#52525b] hover:text-[#22c55e] flex items-center space-x-1 transition-colors cursor-pointer"
            >
              {copiedCodeId === `code-${finding.id}` ? (
                <><Check className="w-3 h-3 text-[#22c55e] shrink-0" /><span>Copied</span></>
              ) : (
                <><Clipboard className="w-3 h-3 shrink-0" /><span>Copy code</span></>
              )}
            </button>
          </div>
          <div className="overflow-x-auto max-h-56 scrollbar-thin">
            <code className="text-[11px] font-mono whitespace-pre leading-relaxed block py-1 text-[#22c55e]/80">
              {finding.codeFixExample}
            </code>
          </div>
        </div>
      )}

      {/* Raw Request / Response Collapsible Drawer for API_SEC / Payload details */}
      {(finding.rawRequest || finding.rawResponse) && (
        <FindingRawDrawer finding={finding} onCopyCode={onCopyCode} />
      )}

      {/* Remediation lifecycle controls */}
      {!finding.isFalsePositive && (
        <FindingRemediationControls
          finding={finding}
          recheckingId={recheckingId}
          recheckMsg={recheckMsg}
          autoFixingId={autoFixingId}
          autoFixMsg={autoFixMsg}
          onSetRemediation={onSetRemediation}
          onRecheck={onRecheck}
          onAutoFix={onAutoFix}
        />
      )}

      {/* False Positives Management UI Drawer Toggle */}
      <FindingSuppressionPanel
        finding={finding}
        suppressInputId={suppressInputId}
        suppressReason={suppressReason}
        isSuppressing={isSuppressing}
        suppressError={suppressError}
        onSaveSuppression={onSaveSuppression}
        onRemoveSuppressionDirectly={onRemoveSuppressionDirectly}
        onOpenSuppressInput={onOpenSuppressInput}
        onCloseSuppressInput={onCloseSuppressInput}
        onSuppressReasonChange={onSuppressReasonChange}
      />

    </div>
  );
}
