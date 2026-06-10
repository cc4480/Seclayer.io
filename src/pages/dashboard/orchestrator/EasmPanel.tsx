import React from 'react';
import { Globe, Play, RefreshCw } from 'lucide-react';
import { OrchestratorState } from '../useOrchestrator.js';

/** EASM Attack Surface sub-module: subdomain enumeration and tech fingerprinting. */
export default function EasmPanel({ orch }: { orch: OrchestratorState }) {
  const { easmDomain, setEasmDomain, easmRunning, easmData, runEasmRecon } = orch;

  return (
    <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
      <div>
        <h3 className="text-sm font-bold text-white mb-1 uppercase font-mono tracking-tight flex items-center gap-1.5">
          <span>2. External Attack Surface Management (EASM)</span>
          <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2 font-mono">OWASP Amass & Wappalyzer</span>
        </h3>
        <p className="text-[#a1a1aa] text-[11px] mb-4">
          Reconcile internet-exposed assets continuously. Our EASM workspace combines passive certificate transparency scraping with active DNS zone brute-forcing and technology fingerprinting (Wappalyzer signatures) to parse headers and map targets without manual intervention.
        </p>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
          <Globe className="w-4 h-4 text-[#52525b] mx-2" />
          <input
            type="text"
            className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
            placeholder="target-enterprise.com"
            value={easmDomain}
            onChange={(e) => setEasmDomain(e.target.value)}
          />
        </div>
        <button
          onClick={runEasmRecon}
          disabled={easmRunning || !easmDomain.trim()}
          className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 shrink-0 cursor-pointer"
        >
          {easmRunning ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin text-black" />
              <span>Scanning Perimeter...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-black text-black" />
              <span>Run Continuous Attack Surface Map</span>
            </>
          )}
        </button>
      </div>

      {easmData && (
        <div className="space-y-6 pt-2">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-3 bg-black border border-[#27272a] rounded">
              <span className="text-[#52525b] text-[9px] uppercase block">Primary IP Address</span>
              <span className="text-white text-sm font-bold block mt-1">{easmData.summary.nameserverIp}</span>
            </div>
            <div className="p-3 bg-black border border-[#27272a] rounded">
              <span className="text-[#52525b] text-[9px] uppercase block">Subdomains Enumerated</span>
              <span className="text-[#22c55e] text-sm font-black block mt-1">{easmData.summary.totalSubdomains} Live</span>
            </div>
            <div className="p-3 bg-black border border-[#27272a] rounded">
              <span className="text-[#52525b] text-[9px] uppercase block">Identified Nameserver</span>
              <span className="text-white text-sm font-bold block mt-1 truncate">{easmData.summary.nameserver}</span>
            </div>
            <div className="p-3 bg-black border border-[#27272a] rounded">
              <span className="text-[#52525b] text-[9px] uppercase block">Active Entry IP Targets</span>
              <span className="text-[#a1a1aa] text-sm font-bold block mt-1">{easmData.summary.activeIps} Hosts</span>
            </div>
          </div>

          {/* Discovered Tech Fingerprints */}
          <div className="space-y-2">
            <h4 className="text-[10px] font-bold text-white uppercase tracking-wider mb-2">Wappalyzer Tech Identification</h4>
            <div className="flex flex-wrap gap-2">
              {easmData.technologies.map((t: any, i: number) => (
                <div key={i} className="p-2.5 bg-[#09090b] border border-[#27272a] rounded flex items-center space-x-2">
                  <span className="bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/25 rounded text-[10px] px-2 py-0.5">{t.type}</span>
                  <strong className="text-zinc-100">{t.name}</strong>
                  <span className="text-[#52525b] text-[10px]">Conf: {t.confidence}%</span>
                </div>
              ))}
            </div>
          </div>

          {/* Subdomains Table */}
          <div className="space-y-2">
            <h4 className="text-[10px] font-bold text-white uppercase tracking-wider mb-2">Discovered Host Subdomains Map</h4>
            <div className="overflow-x-auto border border-[#27272a] rounded">
              <table className="w-full text-left font-mono text-[11px] bg-black">
                <thead>
                  <tr className="bg-[#0c0c0e] border-b border-[#27272a] text-[#52525b] text-[9px] uppercase">
                    <th className="p-2.5">Subdomain Name</th>
                    <th className="p-2.5">Mapped IP Address</th>
                    <th className="p-2.5">Status</th>
                    <th className="p-2.5">Open TCP/UDP Ports</th>
                    <th className="p-2.5">Inferred Service</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#27272a]/40 divide-dashed">
                  {easmData.subdomains.map((sub: any, i: number) => (
                    <tr key={i} className="hover:bg-[#0c0c0e] transition-colors">
                      <td className="p-2.5 text-white font-bold">{sub.subdomain}</td>
                      <td className="p-2.5 text-[#a1a1aa]">{sub.ip}</td>
                      <td className="p-2.5">
                        <span className={`px-1.5 py-0.25 text-[8px] rounded uppercase ${
                          sub.status === 'live' ? 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/20' : 'bg-red-950/20 text-rose-400 border border-red-900/20'
                        }`}>{sub.status}</span>
                      </td>
                      <td className="p-2.5 text-[#22c55e] font-bold">{sub.ports.join(', ')}</td>
                      <td className="p-2.5 text-zinc-500">{sub.service}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
