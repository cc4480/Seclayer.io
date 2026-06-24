import React from 'react';
import { Globe, Play, RefreshCw, AlertTriangle } from 'lucide-react';

interface EasmPanelProps {
  key?: string;
  easmDomain: string;
  setEasmDomain: (v: string) => void;
  easmRunning: boolean;
  easmData: any | null;
  easmError: string | null;
  runEasmRecon: () => void;
}

export default function EasmPanel({
  easmDomain, setEasmDomain, easmRunning, easmData, easmError, runEasmRecon,
}: EasmPanelProps) {
  return (
    <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
      <div>
        <h3 className="text-sm font-bold text-white mb-1 uppercase tracking-tight flex items-center gap-1.5">
          <span>2. External Attack Surface Management (EASM)</span>
          <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2">OWASP Amass & crt.sh</span>
        </h3>
        <p className="text-[#a1a1aa] text-[11px] mb-4">
          Reconcile internet-exposed assets continuously. Combines passive certificate transparency scraping (crt.sh) with active DNS resolution to enumerate subdomains and map your attack surface.
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
            <><RefreshCw className="w-4 h-4 animate-spin text-black" /><span>Scanning Perimeter...</span></>
          ) : (
            <><Play className="w-3.5 h-3.5 fill-black text-black" /><span>Run Attack Surface Map</span></>
          )}
        </button>
      </div>

      {easmError && (
        <div className="flex items-center gap-2 text-[#f87171] bg-[#f87171]/5 border border-[#f87171]/20 rounded p-3 text-[11px]">
          <AlertTriangle className="w-4 h-4 shrink-0" />{easmError}
        </div>
      )}

      {easmData && (
        <div className="space-y-6 pt-2">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-3 bg-black border border-[#27272a] rounded">
              <span className="text-[#52525b] text-[9px] uppercase block">Primary IP</span>
              <span className="text-white text-sm font-bold block mt-1">{easmData.ip}</span>
            </div>
            <div className="p-3 bg-black border border-[#27272a] rounded">
              <span className="text-[#52525b] text-[9px] uppercase block">Subdomains Found</span>
              <span className="text-[#22c55e] text-sm font-black block mt-1">{easmData.summary.totalDiscovered}</span>
            </div>
            <div className="p-3 bg-black border border-[#27272a] rounded">
              <span className="text-[#52525b] text-[9px] uppercase block">Live Hosts</span>
              <span className="text-white text-sm font-bold block mt-1">{easmData.summary.live}</span>
            </div>
            <div className="p-3 bg-black border border-[#27272a] rounded">
              <span className="text-[#52525b] text-[9px] uppercase block">Nameservers</span>
              <span className="text-[#a1a1aa] text-xs font-bold block mt-1 truncate">{easmData.nameservers.length > 0 ? easmData.nameservers[0] : 'N/A'}</span>
            </div>
          </div>

          {easmData.mxRecords.length > 0 && (
            <div>
              <h4 className="text-[10px] font-bold text-white uppercase tracking-wider mb-2">MX Records</h4>
              <div className="flex flex-wrap gap-2">
                {easmData.mxRecords.map((mx: any, i: number) => (
                  <div key={i} className="p-2 bg-black border border-[#27272a] rounded text-[10px]">
                    <span className="text-[#22c55e] font-bold">{mx.exchange}</span>
                    <span className="text-[#52525b] ml-2">priority: {mx.priority}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {easmData.subdomains.length > 0 && (
            <div>
              <h4 className="text-[10px] font-bold text-white uppercase tracking-wider mb-2">Discovered Subdomains</h4>
              <div className="overflow-x-auto border border-[#27272a] rounded">
                <table className="w-full text-left font-mono text-[11px] bg-black">
                  <thead>
                    <tr className="bg-[#0c0c0e] border-b border-[#27272a] text-[#52525b] text-[9px] uppercase">
                      <th className="p-2.5">Subdomain</th>
                      <th className="p-2.5">IP Address</th>
                      <th className="p-2.5">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#27272a]/40">
                    {easmData.subdomains.map((sub: any, i: number) => (
                      <tr key={i} className="hover:bg-[#0c0c0e] transition-colors">
                        <td className="p-2.5 text-white font-bold">{sub.subdomain}</td>
                        <td className="p-2.5 text-[#a1a1aa]">{sub.ip}</td>
                        <td className="p-2.5">
                          <span className={`px-1.5 py-0.5 text-[8px] rounded uppercase ${
                            sub.status === 'live' ? 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/20' : 'bg-red-950/20 text-rose-400 border border-red-900/20'
                          }`}>{sub.status}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {easmData.subdomains.length === 0 && (
            <div className="text-center py-4 text-[#52525b] text-[11px]">
              No subdomains discovered via certificate transparency logs.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
