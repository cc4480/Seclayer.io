import React from 'react';
import { Play, RefreshCw, AlertTriangle } from 'lucide-react';

interface IastPanelProps {
  key?: string;
  iastRunning: boolean;
  iastResult: any | null;
  iastError: string | null;
  runIastTrace: () => void;
}

export default function IastPanel({
  iastRunning, iastResult, iastError, runIastTrace,
}: IastPanelProps) {
  return (
    <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
      <div>
        <h3 className="text-sm font-bold text-white mb-1 uppercase tracking-tight flex items-center gap-1.5">
          <span>4. Runtime Passive Instrumentation (IAST)</span>
          <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2">DongTai IAST Agent</span>
        </h3>
        <p className="text-[#a1a1aa] text-[11px] mb-4">
          IAST places hooks directly into server bytecode (JVM/Python VM) to intercept internal methods in real-time, analyzing taint flows from user-provided input to critical sinks like SQL or shell execution.
        </p>
      </div>

      <button
        onClick={runIastTrace}
        disabled={iastRunning}
        className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center space-x-2 cursor-pointer"
      >
        {iastRunning ? (
          <><RefreshCw className="w-4 h-4 animate-spin text-black" /><span>Checking agent status...</span></>
        ) : (
          <><Play className="w-3.5 h-3.5 fill-black text-black" /><span>Check IAST Agent Status</span></>
        )}
      </button>

      {iastError && (
        <div className="flex items-center gap-2 text-[#f87171] bg-[#f87171]/5 border border-[#f87171]/20 rounded p-3 text-[11px]">
          <AlertTriangle className="w-4 h-4 shrink-0" />{iastError}
        </div>
      )}

      {iastResult && (
        <div className="space-y-4 pt-2">
          <div className="p-4 bg-amber-950/10 border border-amber-900/30 rounded space-y-3">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span className="text-amber-400 font-bold text-xs uppercase">{iastResult.feature}</span>
            </div>
            <p className="text-[#a1a1aa] text-[11px] leading-relaxed">{iastResult.message}</p>
          </div>

          <div>
            <h4 className="text-[10px] font-bold text-white uppercase tracking-wider mb-3">Setup Steps Required</h4>
            <div className="space-y-2">
              {iastResult.setupRequired?.map((step: string, i: number) => (
                <div key={i} className="flex items-start gap-3 p-3 bg-black border border-[#27272a] rounded">
                  <span className="w-5 h-5 rounded-full bg-zinc-900 border border-zinc-700/60 flex items-center justify-center text-[10px] text-[#22c55e] font-black shrink-0 mt-0.5">
                    {i + 1}
                  </span>
                  <span className="text-[#a1a1aa] text-[11px] leading-relaxed">{step}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
