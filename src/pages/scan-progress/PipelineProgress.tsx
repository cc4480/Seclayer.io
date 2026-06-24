import { Scan } from '../../types.js';

interface PipelineProgressProps {
  progressPercent: number;
  status: Scan['status'] | undefined;
}

export default function PipelineProgress({ progressPercent, status }: PipelineProgressProps) {
  return (
    <div className="space-y-3">
      <div className="flex justify-between items-baseline font-mono text-xs">
        <span className="text-[#52525b]">Scan Pipeline Progression</span>
        <span className="text-[#22c55e] font-bold">{progressPercent}%</span>
      </div>
      <div className="w-full bg-black h-2.5 rounded overflow-hidden border border-[#27272a]">
        <div
          className="bg-gradient-to-r from-[#22c55e] to-emerald-400 h-full transition-all duration-700 rounded-full relative"
          style={{ width: `${progressPercent}%` }}
        >
          <span className="absolute right-0 top-0 bottom-0 w-3 bg-white/45 blur-[1.5px] rounded-full animate-pulse" />
        </div>
      </div>

      <div className="pt-1.5 pb-2.5 space-y-1 border-t border-[#27272a]/20 mt-1">
        <div className="flex justify-between items-center text-[10px] font-mono text-[#52525b] uppercase tracking-wider">
          <span className="flex items-center gap-1.5">
            <span className="w-1 h-1 rounded-full bg-[#22c55e] inline-block animate-pulse" />
            <span>Sub-Task: <span className="text-zinc-350 normal-case font-bold">{
              status === 'queued' ? 'Pre-execution checklist & infrastructure provisioning' :
              status === 'scanning' ? 'DAST probing / dynamic payload injection' :
              status === 'analyzing' ? 'AI analysis & severity scoring' :
              status === 'complete' ? 'Report compiled / database sync' :
              'Initializing target pipeline...'
            }</span></span>
          </span>
          <span className="text-zinc-400 font-bold">{
            status === 'queued' ? '40%' :
            status === 'scanning' ? '70%' :
            status === 'analyzing' ? '92%' :
            status === 'complete' ? '100%' : '0%'
          }</span>
        </div>
        <div className="w-full bg-black h-1 rounded overflow-hidden border border-[#27272a]/60">
          <div
            className="bg-[#22c55e]/60 h-full transition-all duration-500 rounded-full"
            style={{
              width: status === 'queued' ? '40%' :
                     status === 'scanning' ? '70%' :
                     status === 'analyzing' ? '92%' :
                     status === 'complete' ? '100%' : '0%',
            }}
          />
        </div>
      </div>

      <div className="flex justify-between items-center text-[10px] font-mono text-[#52525b] uppercase mt-1">
        <span className={status === 'queued' ? 'text-[#22c55e] font-bold' : ''}>QUEUED</span>
        <span className="text-[#27272a]">→</span>
        <span className={status === 'scanning' ? 'text-purple-400 font-bold' : ''}>SCANNING</span>
        <span className="text-[#27272a]">→</span>
        <span className={status === 'analyzing' ? 'text-amber-400 font-bold' : ''}>ANALYZING AI</span>
        <span className="text-[#27272a]">→</span>
        <span className={status === 'complete' ? 'text-[#22c55e] font-bold' : ''}>COMPLETE</span>
      </div>
    </div>
  );
}
