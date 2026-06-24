import { AlertTriangle, CheckCircle2, Zap, Package } from 'lucide-react';
import { Finding } from '../../types.js';
import { REMEDIATION_META, remediationStatusOf } from './reportHelpers.js';

interface FindingRemediationControlsProps {
  finding: Finding;
  recheckingId: string | null;
  recheckMsg: Record<string, { ok: boolean; text: string }>;
  autoFixingId: string | null;
  autoFixMsg: Record<string, { ok: boolean; text: string; prUrl?: string }>;
  onSetRemediation: (finding: Finding, status: string) => void;
  onRecheck: (finding: Finding) => void;
  onAutoFix: (finding: Finding) => void;
}

/**
 * Remediation lifecycle controls (status buttons, Auto-Fix via PR, Re-check
 * fix) plus their resulting status messages, for a single non-suppressed
 * finding.
 */
export default function FindingRemediationControls({
  finding,
  recheckingId,
  recheckMsg,
  autoFixingId,
  autoFixMsg,
  onSetRemediation,
  onRecheck,
  onAutoFix,
}: FindingRemediationControlsProps) {
  return (
    <div className="mt-4 border-t border-[#27272a]/30 pt-3 space-y-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[9px] font-mono uppercase tracking-wider text-[#52525b] mr-1">Remediation:</span>
        {(['open', 'in_progress', 'fixed'] as const).map(s => (
          <button
            key={s}
            onClick={() => onSetRemediation(finding, s)}
            className={`text-[9px] font-mono uppercase tracking-wider px-2.5 py-1 rounded border transition-colors cursor-pointer ${
              remediationStatusOf(finding) === s
                ? REMEDIATION_META[s].cls
                : 'bg-black text-[#52525b] border-[#27272a] hover:text-zinc-300'
            }`}
          >
            {REMEDIATION_META[s].label}
          </button>
        ))}
        <button
          onClick={() => onAutoFix(finding)}
          disabled={autoFixingId === finding.id}
          className="text-[9px] font-mono uppercase tracking-wider px-2.5 py-1 rounded border border-sky-500/30 bg-sky-500/5 text-sky-400 hover:bg-sky-500/15 transition-colors cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
        >
          <Package className="w-3 h-3" />
          {autoFixingId === finding.id ? 'Opening PR…' : 'Auto-Fix via PR'}
        </button>
        <button
          onClick={() => onRecheck(finding)}
          disabled={recheckingId === finding.id}
          className="ml-auto text-[9px] font-mono uppercase tracking-wider px-2.5 py-1 rounded border border-[#22c55e]/30 bg-[#22c55e]/5 text-[#22c55e] hover:bg-[#22c55e]/15 transition-colors cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
        >
          <Zap className="w-3 h-3" />
          {recheckingId === finding.id ? 'Re-testing…' : 'Re-check fix'}
        </button>
      </div>
      {recheckMsg[finding.id] && (
        <p className={`text-[10px] font-mono leading-relaxed flex items-start gap-1.5 ${recheckMsg[finding.id].ok ? 'text-[#22c55e]' : 'text-amber-400'}`}>
          {recheckMsg[finding.id].ok ? <CheckCircle2 className="w-3 h-3 shrink-0 mt-0.5" /> : <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />}
          <span>{recheckMsg[finding.id].text}</span>
        </p>
      )}
      {finding.lastVerifiedAt && !recheckMsg[finding.id] && (
        <p className="text-[9px] font-mono text-[#52525b]">
          Last re-checked {new Date(finding.lastVerifiedAt).toLocaleString()} — {finding.verificationResult === 'resolved' ? 'resolved' : 'still present'}
        </p>
      )}
      {autoFixMsg[finding.id] && (
        <p className={`text-[10px] font-mono leading-relaxed flex items-start gap-1.5 ${autoFixMsg[finding.id].ok ? 'text-sky-400' : 'text-amber-400'}`}>
          {autoFixMsg[finding.id].ok ? <CheckCircle2 className="w-3 h-3 shrink-0 mt-0.5" /> : <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />}
          <span>
            {autoFixMsg[finding.id].text}{' '}
            {autoFixMsg[finding.id].prUrl && (
              <a href={autoFixMsg[finding.id].prUrl} target="_blank" rel="noopener noreferrer" className="underline hover:text-white">
                View pull request
              </a>
            )}
          </span>
        </p>
      )}
      {finding.autoFixStatus === 'opened' && finding.autoFixPrUrl && !autoFixMsg[finding.id] && (
        <p className="text-[9px] font-mono text-[#52525b]">
          Auto-fix PR opened —{' '}
          <a href={finding.autoFixPrUrl} target="_blank" rel="noopener noreferrer" className="underline hover:text-zinc-300">
            view on GitHub
          </a>
        </p>
      )}
    </div>
  );
}
