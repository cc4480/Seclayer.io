import React from 'react';
import { Globe, Play, RefreshCw } from 'lucide-react';
import { OrchestratorState } from '../useOrchestrator.js';

/** ASPM Correlation sub-module: fuses SAST/DAST signals via the Fusion engine. */
export default function AspmPanel({ orch }: { orch: OrchestratorState }) {
  const { aspmUrl, setAspmUrl, aspmRunning, aspmOutput, runAspmCorrelation } = orch;

  return (
    <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
      <div>
        <h3 className="text-sm font-bold text-white mb-1 uppercase font-mono tracking-tight flex items-center gap-1.5">
          <span>1. Application Security Posture Management (ASPM)</span>
          <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2 font-mono">DefectDojo & Fusion Engine</span>
        </h3>
        <p className="text-[#a1a1aa] text-[11px] mb-4">
          ASPM acts as a single pane of glass by consolidating Static (SAST) and Dynamic (DAST) findings. When SAST signals a vulnerability, the Fusion Correlation engine dispatches a targeted dynamic query to test exploit viability. If the dynamic exploit probe is successful, score priority is raised to CRITICAL.
        </p>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
          <Globe className="w-4 h-4 text-[#52525b] mx-2" />
          <input
            type="text"
            className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
            placeholder="staging.api.vulnerable-shop.io"
            value={aspmUrl}
            onChange={(e) => setAspmUrl(e.target.value)}
          />
        </div>
        <button
          onClick={runAspmCorrelation}
          disabled={aspmRunning || !aspmUrl.trim()}
          className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 shrink-0 cursor-pointer"
        >
          {aspmRunning ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin text-black" />
              <span>Correlating...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-black text-black" />
              <span>Trigger Core Fusion Match</span>
            </>
          )}
        </button>
      </div>

      {aspmOutput && (
        <div className="space-y-3 pt-2">
          <div className="p-3 bg-zinc-900/30 border border-zinc-800 rounded flex items-center justify-between text-zinc-300">
            <span>Orchestrated by: <strong className="text-white">{aspmOutput.orchestrator}</strong></span>
            <span className="text-emerald-400 font-bold bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-900/40 text-[10px]">CORRELATION VERIFIED</span>
          </div>

          <div className="space-y-2">
            {aspmOutput.steps.map((st: any, i: number) => (
              <div key={i} className="bg-black border border-[#27272a] rounded p-3.5">
                <div className="flex items-center justify-between border-b border-[#27272a]/40 pb-2 mb-2">
                  <span className="font-bold text-[#22c55e]">Step {i + 1}: {st.phase}</span>
                  <span className={`text-[9px] uppercase font-bold px-1.5 py-0.25 rounded ${
                    st.status === 'escalated' ? 'bg-red-950/50 text-red-400 border border-red-900/40 text-[9px]' : 'bg-zinc-900 text-zinc-400'
                  }`}>{st.status}</span>
                </div>
                <pre className="text-[11px] text-[#a1a1aa] whitespace-pre-wrap leading-relaxed select-all">
                  {st.logs}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
