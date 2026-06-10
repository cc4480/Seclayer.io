import React from 'react';
import { Globe, Play, RefreshCw } from 'lucide-react';
import { OrchestratorState } from '../useOrchestrator.js';

/** IAST sub-module: runtime taint-trace timeline from passive instrumentation. */
export default function IastPanel({ orch }: { orch: OrchestratorState }) {
  const {
    iastUrl, setIastUrl,
    iastPayload, setIastPayload,
    iastRunning, iastResult, runIastTrace,
  } = orch;

  return (
    <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
      <div>
        <h3 className="text-sm font-bold text-white mb-1 uppercase font-mono tracking-tight flex items-center gap-1.5">
          <span>4. Runtime Passive Instrumentation (IAST)</span>
          <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2 font-mono">DongTai IAST Agent</span>
        </h3>
        <p className="text-[#a1a1aa] text-[11px] mb-4">
          IAST places hooks directly into Server Bytecode (JVM/Python VM) to intercept internal methods in real-time. We can analyze taint traces and watch how user-provided strings navigate routing frameworks, sanitizers, and ORM abstractions to hit critical SQL database or Shell sinks.
        </p>
      </div>

      <div className="flex flex-col gap-3">
        <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
          <Globe className="w-4 h-4 text-[#52525b] mx-2" />
          <input
            type="text"
            className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
            placeholder="staging.api.vulnerable-shop.io"
            value={iastUrl}
            onChange={(e) => setIastUrl(e.target.value)}
          />
        </div>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
            <span className="text-[#52525b] px-2 whitespace-nowrap">Input Payload:</span>
            <input
              type="text"
              className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
              placeholder="1' UNION SELECT credit_card_number FROM customers"
              value={iastPayload}
              onChange={(e) => setIastPayload(e.target.value)}
            />
          </div>
          <button
            onClick={runIastTrace}
            disabled={iastRunning || !iastUrl.trim() || !iastPayload.trim()}
            className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 shrink-0 cursor-pointer"
          >
            {iastRunning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-black" />
                <span>Hooking Bytecode...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-black text-black" />
                <span>Instrument Bytecode Passive Hooks</span>
              </>
            )}
          </button>
        </div>
      </div>

      {iastResult && (
        <div className="space-y-4 pt-2">
          <div className={`flex justify-between items-center text-[#a1a1aa] p-3 rounded border ${
            iastResult.status === 'Sink Triggered Malicious Flow Alert'
              ? 'bg-red-950/10 border-red-900/30'
              : 'bg-[#22c55e]/5 border-[#22c55e]/30'
          }`}>
            <span>Agent Target: <code className="text-white font-bold">{iastResult.runtime}</code></span>
            {iastResult.status === 'Sink Triggered Malicious Flow Alert' ? (
              <span className="font-bold text-[#f87171] animate-pulse">SINK CRITICAL TAINT INTERCEPT</span>
            ) : (
              <span className="font-bold text-[#22c55e]">NO TAINT SINK TRIGGERED</span>
            )}
          </div>

          <div className="space-y-3 relative before:absolute before:left-[17px] before:top-4 before:bottom-4 before:w-0.5 before:bg-[#27272a]">
            {iastResult.traces.map((tr: any) => (
              <div key={tr.step} className="pl-9 relative">
                <div className="absolute left-1 top-1.5 w-6 h-6 rounded-full bg-zinc-900 border border-zinc-700/60 flex items-center justify-center text-[10px] text-[#22c55e] font-black font-mono">
                  {tr.step}
                </div>
                <div className="bg-black hover:border-zinc-700/60 border border-[#27272a] rounded p-3.5 space-y-2">
                  <div className="flex items-center justify-between text-[11px] border-b border-[#27272a]/30 pb-1.5">
                    <span className="font-mono text-zinc-300 font-bold truncate">Class: {tr.clazz}</span>
                    <span className="font-mono text-[#22c55e] shrink-0 font-bold">Method: {tr.method} • Line {tr.line}</span>
                  </div>
                  <p className="text-[#a1a1aa] text-[11px] leading-relaxed select-all">
                    {tr.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
