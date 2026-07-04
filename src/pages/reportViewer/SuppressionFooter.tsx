import React from 'react';
import { AlertTriangle } from 'lucide-react';
import { Finding } from '../../types.js';
import { SuppressionState } from './useSuppression.js';

// False-positive management drawer for a single finding: the justification input
// when open, otherwise the "mark false positive" / "remove exemption" controls.
export default function SuppressionFooter({ finding, sup }: { finding: Finding; sup: SuppressionState }) {
  return (
    <div className="mt-4 border-t border-[#27272a]/30 pt-3 flex flex-col">
      {sup.suppressInputId === finding.id ? (
        <div className="bg-[#121214] border border-[#27272a]/80 p-3.5 rounded space-y-3 animate-fade-in">
          <label className="text-[10px] font-mono uppercase tracking-wider text-amber-500/90 font-bold block">
            Define Suppression Justification (Audit Trail)
          </label>
          <p className="text-[11px] text-[#52525b] font-mono">
            By declaring this finding a false positive or an excluded risk, its impact is subtracted from the final security score and rating, and the exemption will apply to future scans of this URL.
          </p>
          <input
            type="text"
            autoFocus
            placeholder="e.g. Host-level firewalls handle payload blocking / acceptable legacby boundary match."
            value={sup.suppressReason}
            onChange={(e) => sup.setSuppressReason(e.target.value)}
            className="w-full bg-black border border-[#27272a] rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-[#22c55e] placeholder-zinc-700"
          />
          {sup.suppressError && (
            <p className="text-[10px] font-mono text-red-400">{sup.suppressError}</p>
          )}
          <div className="flex justify-end space-x-2">
            <button
              onClick={() => { sup.setSuppressInputId(null); sup.setSuppressError(null); }}
              className="px-2.5 py-1.5 border border-[#27272a] text-[#a1a1aa] hover:text-white bg-zinc-900 hover:bg-zinc-800 text-[10px] font-mono uppercase rounded cursor-pointer transition-all"
            >
              Close
            </button>
            <button
              onClick={() => sup.handleSaveSuppression(finding)}
              disabled={sup.isSuppressing}
              className="px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/35 text-[10px] font-mono uppercase rounded font-bold cursor-pointer transition-all"
            >
              {sup.isSuppressing ? 'Processing...' : 'Suppress Finding'}
            </button>
          </div>
        </div>
      ) : (
        <div className="flex justify-between items-center">
          {finding.isFalsePositive ? (
            <div className="flex items-center justify-between w-full bg-zinc-900/40 border border-dashed border-zinc-800/80 px-3.5 py-2 rounded">
              <p className="text-[11px] font-mono text-zinc-500 flex items-center space-x-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-zinc-600 shrink-0" />
                <span><strong>Exempted Risk:</strong> {finding.suppressionReason || 'Declared acceptable false positive risk.'}</span>
              </p>
              <button
                disabled={sup.isSuppressing}
                onClick={() => sup.handleRemoveSuppressionDirectly(finding.title)}
                className="text-[10px] font-mono text-red-400 hover:text-red-300 underline cursor-pointer select-none transition-colors"
              >
                Remove Exemption
              </button>
            </div>
          ) : (
            <>
              <span className="text-[10px] font-mono text-[#52525b]">Is this threat checked or invalid?</span>
              <button
                onClick={() => { sup.setSuppressInputId(finding.id); sup.setSuppressReason(''); sup.setSuppressError(null); }}
                className="px-2.5 py-1 bg-zinc-900 border border-zinc-800/80 hover:border-amber-500/20 text-[#71717a] hover:text-amber-400 text-[10px] font-mono uppercase tracking-wider transition-all flex items-center space-x-1.5 cursor-pointer"
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Mark False Positive</span>
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
