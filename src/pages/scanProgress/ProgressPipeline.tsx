import React from 'react';
import { Scan } from '../../types.js';

// Renders the primary progression loader, the secondary buffer sub-task bar, and
// the QUEUED → SCANNING → ANALYZING → COMPLETE stage row.
export default function ProgressPipeline({ scan, progressPercent }: { scan: Scan | null; progressPercent: number }) {
  return (
    <div className="space-y-3">
      <div className="flex justify-between items-baseline font-mono text-xs">
        <span className="text-[#52525b]">Scan Pipeline Progression</span>
        <span className="text-[#22c55e] font-bold">{progressPercent}%</span>
      </div>
      <div className="w-full bg-black h-2.5 rounded overflow-hidden border border-[#27272a] relative after:absolute after:inset-0 after:bg-gradient-to-r after:from-transparent after:via-[#22c55e]/15 after:to-transparent after:animate-shimmer after:pointer-events-none">
        <div
          className="bg-gradient-to-r from-[#22c55e] to-emerald-400 h-full transition-all duration-700 rounded-full relative"
          style={{ width: `${progressPercent}%` }}
        >
          {/* Pulsing shadow tip emitter */}
          <span className="absolute right-0 top-0 bottom-0 w-3 bg-white/45 blur-[1.5px] rounded-full animate-pulse" />
        </div>
      </div>

      {/* Secondary Non-Animated Buffer Status Bar */}
      <div className="pt-1.5 pb-2.5 space-y-1 border-t border-[#27272a]/20 mt-1">
        <div className="flex justify-between items-center text-[10px] font-mono text-[#52525b] uppercase tracking-wider">
          <span className="flex items-center gap-1.5">
            <span className="w-1 h-1 rounded-full bg-[#22c55e] inline-block animate-pulse" />
            <span>Buffer Sub-Task: <span className="text-zinc-350 normal-case font-bold">{
              scan?.status === 'queued' ? 'Validating target & resolving DNS' :
              scan?.status === 'scanning' ? 'Headers, secrets, libraries, subdomains & path probing' :
              scan?.status === 'analyzing' ? 'Active injection/API probes & report generation' :
              scan?.status === 'complete' ? 'Report compiled & saved' :
              'Initializing target pipeline...'
            }</span></span>
          </span>
          <span className="text-zinc-400 font-bold">{
            scan?.status === 'queued' ? '40%' :
            scan?.status === 'scanning' ? '70%' :
            scan?.status === 'analyzing' ? '92%' :
            scan?.status === 'complete' ? '100%' :
            '0%'
          }</span>
        </div>
        <div className="w-full bg-black h-1 rounded overflow-hidden border border-[#27272a]/60">
          <div
            className="bg-[#22c55e]/60 h-full transition-all duration-500 rounded-full"
            style={{
              width: scan?.status === 'queued' ? '40%' :
                     scan?.status === 'scanning' ? '70%' :
                     scan?.status === 'analyzing' ? '92%' :
                     scan?.status === 'complete' ? '100%' :
                     '0%'
            }}
          />
        </div>
      </div>

      <div className="flex justify-between items-center text-[10px] font-mono text-[#52525b] uppercase mt-1">
        <span className={scan?.status === 'queued' ? 'text-[#22c55e] font-bold' : ''}>QUEUED</span>
        <span className="text-[#27272a]">→</span>
        <span className={scan?.status === 'scanning' ? 'text-purple-400 font-bold' : ''}>SCANNING</span>
        <span className="text-[#27272a]">→</span>
        <span className={scan?.status === 'analyzing' ? 'text-amber-400 font-bold' : ''}>ANALYZING AI</span>
        <span className="text-[#27272a]">→</span>
        <span className={scan?.status === 'complete' ? 'text-[#22c55e] font-bold' : ''}>COMPLETE</span>
      </div>
    </div>
  );
}
