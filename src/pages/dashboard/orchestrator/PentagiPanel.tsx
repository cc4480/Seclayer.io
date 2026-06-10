import React from 'react';
import { Play, RefreshCw } from 'lucide-react';
import { OrchestratorState } from '../useOrchestrator.js';

/** PentAGI sub-module: spawns the autonomous agent swarm and streams its logs. */
export default function PentagiPanel({ orch }: { orch: OrchestratorState }) {
  const { pentagiRunning, pentagiLogs, runPentagiExploitation } = orch;

  return (
    <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
      <div>
        <h3 className="text-sm font-bold text-white mb-1 uppercase font-mono tracking-tight flex items-center gap-1.5">
          <span>5. Multi-Agent Autonomous Pentesting (PentAGI)</span>
          <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2 font-mono">AutoPentest-AI Executor</span>
        </h3>
        <p className="text-[#a1a1aa] text-[11px] mb-4">
          Leverage LLM-driven cooperative agents running inside sandboxed containers. Scout runs background asset spidering, Exploiter crafts multi-stage bypass attacks (e.g., bypassing CSRF through cookie harvesting), and Reporter maps vulnerability entities within a secure Graph layout for exploitation.
        </p>
      </div>

      <div className="flex justify-between items-center">
        <span className="text-zinc-500 text-[10px]">Coordinates Neo4j Knowledge Entities automatically</span>
        <button
          onClick={runPentagiExploitation}
          disabled={pentagiRunning}
          className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 cursor-pointer"
        >
          {pentagiRunning ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin text-black" />
              <span>AI Agents Investigating...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-black text-black" />
              <span>Spawn Sandbox AI Penetration Agents</span>
            </>
          )}
        </button>
      </div>

      {pentagiLogs.length > 0 && (
        <div className="space-y-2">
          <div className="border border-zinc-800 rounded bg-[#09090b] p-3 text-[10px] text-zinc-500 font-mono flex items-center justify-between">
            <span>Executing: {pentagiRunning ? 'COOPERATION RUNNING' : 'PENTEST SESSION COMPLETE'}</span>
            <span className="text-[#22c55e] font-bold">Neo4j Entities: 8 nodes mapped</span>
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
