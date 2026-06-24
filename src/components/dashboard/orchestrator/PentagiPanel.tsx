import React from 'react';
import { Globe, Play, RefreshCw, AlertTriangle } from 'lucide-react';

interface PentagiPanelProps {
  key?: string;
  pentagiUrl: string;
  setPentagiUrl: (v: string) => void;
  pentagiRunning: boolean;
  pentagiLogs: any[];
  pentagiError: string | null;
  runPentagiExploitation: () => void;
}

export default function PentagiPanel({
  pentagiUrl, setPentagiUrl, pentagiRunning, pentagiLogs, pentagiError, runPentagiExploitation,
}: PentagiPanelProps) {
  return (
    <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
      <div>
        <h3 className="text-sm font-bold text-white mb-1 uppercase tracking-tight flex items-center gap-1.5">
          <span>5. Multi-Stage Automated Pentesting (PentAGI)</span>
          <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2">AI-Assisted Executor</span>
        </h3>
        <p className="text-[#a1a1aa] text-[11px] mb-4">
          A real multi-stage black-box exploitation run against the target. The Scout stage maps the surface (DNS, ports, TLS, subdomains), the Exploiter stage fires live injection, auth-bypass and misconfiguration probes, and the Reporter stage uses AI to synthesize confirmed findings into a strategic remediation plan. Events stream live as each stage executes.
        </p>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
          <Globe className="w-4 h-4 text-[#52525b] mx-2" />
          <input
            type="text"
            className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
            placeholder="https://target.example.com"
            value={pentagiUrl}
            onChange={(e) => setPentagiUrl(e.target.value)}
          />
        </div>
        <button
          onClick={runPentagiExploitation}
          disabled={pentagiRunning}
          className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 cursor-pointer shrink-0"
        >
          {pentagiRunning ? (
            <><RefreshCw className="w-4 h-4 animate-spin text-black" /><span>AI Agents Investigating...</span></>
          ) : (
            <><Play className="w-3.5 h-3.5 fill-black text-black" /><span>Spawn AI Pentest Agents</span></>
          )}
        </button>
      </div>

      {pentagiError && (
        <div className="flex items-center gap-2 text-[#f87171] bg-[#f87171]/5 border border-[#f87171]/20 rounded p-3 text-[11px]">
          <AlertTriangle className="w-4 h-4 shrink-0" />{pentagiError}
        </div>
      )}

      {pentagiLogs.length > 0 && (
        <div className="space-y-2">
          <div className="border border-zinc-800 rounded bg-[#09090b] p-3 text-[10px] text-zinc-500 font-mono flex items-center justify-between">
            <span>Executing: {pentagiRunning ? 'EXPLOITATION RUN LIVE' : 'PENTEST SESSION COMPLETE'}</span>
            <span className="text-[#22c55e] font-bold">{pentagiLogs.length} agent event{pentagiLogs.length !== 1 ? 's' : ''} streamed</span>
          </div>
          <div className="bg-black border border-zinc-800 rounded p-4 font-mono text-[11px] leading-relaxed overflow-y-auto max-h-[350px] space-y-2.5 text-zinc-300">
            {pentagiLogs.map((log: any, i: number) => (
              <div key={i} className="flex space-x-2 hover:bg-zinc-950 p-1.5 rounded transition-colors border-l-2 border-[#22c55e]">
                <span className="text-[#22c55e] shrink-0 font-bold">[{log.time}]</span>
                <span className="text-zinc-400 font-bold shrink-0">{log.agent}:</span>
                <span className="text-[#a1a1aa] select-all font-mono whitespace-pre-wrap">{log.msg}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
