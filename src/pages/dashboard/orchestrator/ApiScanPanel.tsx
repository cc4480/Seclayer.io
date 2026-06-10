import React from 'react';
import { Globe, Play, RefreshCw, AlertTriangle } from 'lucide-react';
import { OrchestratorState } from '../useOrchestrator.js';

/** API Security Testing sub-module: Hadrian role-mutation matrix output. */
export default function ApiScanPanel({ orch }: { orch: OrchestratorState }) {
  const {
    apiScanUrl, setApiScanUrl,
    apiSpecTitle, setApiSpecTitle,
    apiScanRunning, apiMatrix, runHadrianScan,
  } = orch;

  return (
    <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
      <div>
        <h3 className="text-sm font-bold text-white mb-1 uppercase font-mono tracking-tight flex items-center gap-1.5">
          <span>3. API Security & Role Authorization Mutators</span>
          <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2 font-mono">Hadrian & APISCAN</span>
        </h3>
        <p className="text-[#a1a1aa] text-[11px] mb-4">
          Replicate Hadrian's dynamic mutation mechanics. Upload Swagger specifications and define role boundary configuration files. APISCAN constructs fuzzing requests, while Hadrian automatically rotates authorization headers for Admin, User, and Guest to isolate BOLA/IDOR access discrepancies.
        </p>
      </div>

      <div className="flex flex-col gap-3">
        <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
          <Globe className="w-4 h-4 text-[#52525b] mx-2" />
          <input
            type="text"
            className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
            placeholder="staging.api.vulnerable-shop.io"
            value={apiScanUrl}
            onChange={(e) => setApiScanUrl(e.target.value)}
          />
        </div>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
            <span className="text-[#52525b] px-2 whitespace-nowrap">Swagger Spec Title:</span>
            <input
              type="text"
              className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
              placeholder="Swagger User Management Core"
              value={apiSpecTitle}
              onChange={(e) => setApiSpecTitle(e.target.value)}
            />
          </div>
          <button
            onClick={runHadrianScan}
            disabled={apiScanRunning || !apiScanUrl.trim() || !apiSpecTitle.trim()}
            className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 shrink-0 cursor-pointer"
          >
            {apiScanRunning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-black" />
                <span>Fuzzing Routes...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-black text-black" />
                <span>Assemble Schema-Driven API Mutation Scans</span>
              </>
            )}
          </button>
        </div>
      </div>

      {apiMatrix && (
        <div className="space-y-4 pt-2">
          <h4 className="text-[10px] font-bold text-white uppercase tracking-wider">Hadrian Role Access Mutation Matrix Output</h4>
          <div className="space-y-3">
            {apiMatrix.matrix.map((item: any, i: number) => (
              <div key={i} className="bg-black border border-[#27272a] rounded p-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-[#27272a]/30 pb-3.5 mb-3.5 gap-2">
                  <div>
                    <span className="text-[10px] font-mono uppercase bg-zinc-900 border border-zinc-700/60 px-2 py-0.5 rounded mr-2 text-zinc-300">
                      {item.methods.join(' | ')}
                    </span>
                    <code className="text-[#22c55e] text-xs font-bold">{item.endpoint}</code>
                  </div>
                  <span className="text-[10px] text-zinc-500">Method mutations: {item.methods.length * 3} calls</span>
                </div>

                {/* Verification roles */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3.5">
                  {Object.entries(item.rolesResult).map(([role, statusObj]: any, rI) => (
                    <div key={rI} className="p-3 bg-[#0c0c0e] border border-[#27272a] rounded flex justify-between items-center text-[10px]">
                      <span className="text-[#52525b] text-[9px] uppercase font-bold">{role}</span>
                      <span className={`text-[10px] font-bold ${statusObj.color}`}>{statusObj.status}</span>
                    </div>
                  ))}
                </div>

                {item.vulnerability && (
                  <div className="p-3 bg-red-950/10 border border-red-900/20 text-[#f87171] rounded-md text-[11px] leading-relaxed flex items-start space-x-2">
                    <AlertTriangle className="w-4 h-4 text-[#f87171] shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-[#f87171] block font-bold mb-1">[⚠️ SECURITY WEAKNESS DETECTED]</strong>
                      <span>{item.vulnerability}</span>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
