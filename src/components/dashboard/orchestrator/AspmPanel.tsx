import React from 'react';
import { Globe, Play, RefreshCw, AlertTriangle, Info } from 'lucide-react';
import { severityColor } from './types.js';

interface AspmPanelProps {
  key?: string;
  aspmUrl: string;
  setAspmUrl: (v: string) => void;
  aspmRunning: boolean;
  aspmOutput: any | null;
  aspmError: string | null;
  runAspmCorrelation: () => void;
}

export default function AspmPanel({
  aspmUrl, setAspmUrl, aspmRunning, aspmOutput, aspmError, runAspmCorrelation,
}: AspmPanelProps) {
  return (
    <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
      <div>
        <h3 className="text-sm font-bold text-white mb-1 uppercase tracking-tight flex items-center gap-1.5">
          <span>1. Application Security Posture Management (ASPM)</span>
          <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2">DefectDojo & Fusion Engine</span>
        </h3>
        <p className="text-[#a1a1aa] text-[11px] mb-4">
          Correlates findings across all your completed scans to identify recurring vulnerabilities. Filter by target URL substring to focus on a specific application or service.
        </p>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
          <Globe className="w-4 h-4 text-[#52525b] mx-2" />
          <input
            type="text"
            className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
            placeholder="Filter by URL (e.g. staging.api) — leave blank to correlate all scans"
            value={aspmUrl}
            onChange={(e) => setAspmUrl(e.target.value)}
          />
        </div>
        <button
          onClick={runAspmCorrelation}
          disabled={aspmRunning}
          className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 shrink-0 cursor-pointer"
        >
          {aspmRunning ? (
            <><RefreshCw className="w-4 h-4 animate-spin text-black" /><span>Correlating...</span></>
          ) : (
            <><Play className="w-3.5 h-3.5 fill-black text-black" /><span>Run Correlation</span></>
          )}
        </button>
      </div>

      {aspmError && (
        <div className="flex items-center gap-2 text-[#f87171] bg-[#f87171]/5 border border-[#f87171]/20 rounded p-3 text-[11px]">
          <AlertTriangle className="w-4 h-4 shrink-0" />{aspmError}
        </div>
      )}

      {aspmOutput && (
        <div className="space-y-4 pt-2">
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {[
              { label: 'Scans Analyzed', value: aspmOutput.scansAnalyzed, color: 'text-white' },
              { label: 'Total Findings', value: aspmOutput.summary.total, color: 'text-white' },
              { label: 'Critical', value: aspmOutput.summary.critical, color: 'text-red-400' },
              { label: 'High', value: aspmOutput.summary.high, color: 'text-[#f87171]' },
              { label: 'Medium', value: aspmOutput.summary.medium, color: 'text-amber-400' },
            ].map(({ label, value, color }) => (
              <div key={label} className="p-3 bg-black border border-[#27272a] rounded text-center">
                <span className="text-[#52525b] text-[9px] uppercase block mb-1">{label}</span>
                <span className={`${color} text-lg font-black block`}>{value}</span>
              </div>
            ))}
          </div>

          {aspmOutput.message && (
            <div className="p-3 bg-[#18181b] border border-[#27272a] rounded text-[#a1a1aa] text-[11px] flex items-center gap-2">
              <Info className="w-4 h-4 text-[#52525b] shrink-0" />
              <span>{aspmOutput.message}</span>
            </div>
          )}

          {aspmOutput.correlatedFindings.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-[10px] font-bold text-white uppercase tracking-wider">Correlated Findings</h4>
              {aspmOutput.correlatedFindings.map((f: any, i: number) => (
                <div key={i} className="bg-black border border-[#27272a] rounded p-3.5 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-white font-bold text-xs">{f.title}</span>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`text-[9px] uppercase px-1.5 py-0.5 rounded border font-bold ${severityColor(f.severity)}`}>{f.severity}</span>
                      <span className="text-[9px] text-[#52525b] font-bold">{f.occurrences}× across {f.seenIn.length} target{f.seenIn.length > 1 ? 's' : ''}</span>
                    </div>
                  </div>
                  <p className="text-[#a1a1aa] text-[11px] leading-relaxed">{f.description}</p>
                  <div className="text-[10px] text-[#22c55e] font-bold">Fix: <span className="text-[#a1a1aa] font-normal">{f.fix}</span></div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
