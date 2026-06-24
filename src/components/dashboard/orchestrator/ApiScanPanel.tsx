import React from 'react';
import { Globe, Play, RefreshCw, AlertTriangle } from 'lucide-react';
import { severityColor } from './types.js';

interface ApiScanPanelProps {
  key?: string;
  apiScanUrl: string;
  setApiScanUrl: (v: string) => void;
  apiScanRunning: boolean;
  apiScanResult: any | null;
  apiScanError: string | null;
  runHadrianScan: () => void;
}

export default function ApiScanPanel({
  apiScanUrl, setApiScanUrl, apiScanRunning, apiScanResult, apiScanError, runHadrianScan,
}: ApiScanPanelProps) {
  return (
    <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
      <div>
        <h3 className="text-sm font-bold text-white mb-1 uppercase tracking-tight flex items-center gap-1.5">
          <span>3. API Security & Endpoint Discovery</span>
          <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2">Hadrian & APISCAN</span>
        </h3>
        <p className="text-[#a1a1aa] text-[11px] mb-4">
          Probes a target for OpenAPI/Swagger specifications, checks for GraphQL introspection exposure, and detects publicly-accessible debug endpoints (Spring Actuator, etc).
        </p>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
          <Globe className="w-4 h-4 text-[#52525b] mx-2" />
          <input
            type="text"
            className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
            placeholder="https://api.yourcompany.com"
            value={apiScanUrl}
            onChange={(e) => setApiScanUrl(e.target.value)}
          />
        </div>
        <button
          onClick={runHadrianScan}
          disabled={apiScanRunning || !apiScanUrl.trim()}
          className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 shrink-0 cursor-pointer"
        >
          {apiScanRunning ? (
            <><RefreshCw className="w-4 h-4 animate-spin text-black" /><span>Probing...</span></>
          ) : (
            <><Play className="w-3.5 h-3.5 fill-black text-black" /><span>Run API Scan</span></>
          )}
        </button>
      </div>

      {apiScanError && (
        <div className="flex items-center gap-2 text-[#f87171] bg-[#f87171]/5 border border-[#f87171]/20 rounded p-3 text-[11px]">
          <AlertTriangle className="w-4 h-4 shrink-0" />{apiScanError}
        </div>
      )}

      {apiScanResult && (
        <div className="space-y-4 pt-2">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="p-3 bg-black border border-[#27272a] rounded">
              <span className="text-[#52525b] text-[9px] uppercase block">OpenAPI Spec</span>
              <span className={`text-sm font-black block mt-1 ${apiScanResult.specFound ? 'text-[#22c55e]' : 'text-[#52525b]'}`}>
                {apiScanResult.specFound ? 'Found' : 'Not found'}
              </span>
            </div>
            {apiScanResult.specFound && (
              <>
                <div className="p-3 bg-black border border-[#27272a] rounded">
                  <span className="text-[#52525b] text-[9px] uppercase block">Spec Path</span>
                  <span className="text-white text-xs font-bold block mt-1 font-mono">{apiScanResult.specPath}</span>
                </div>
                <div className="p-3 bg-black border border-[#27272a] rounded">
                  <span className="text-[#52525b] text-[9px] uppercase block">Endpoints Mapped</span>
                  <span className="text-white text-sm font-black block mt-1">{apiScanResult.endpointCount}</span>
                </div>
              </>
            )}
          </div>

          {apiScanResult.specTitle && (
            <div className="p-3 bg-[#18181b] border border-[#27272a] rounded text-[11px]">
              <span className="text-[#52525b]">API Title: </span>
              <span className="text-white font-bold">{apiScanResult.specTitle}</span>
              {apiScanResult.specVersion && <span className="text-[#52525b] ml-2">v{apiScanResult.specVersion}</span>}
            </div>
          )}

          {apiScanResult.endpoints.length > 0 && (
            <div>
              <h4 className="text-[10px] font-bold text-white uppercase tracking-wider mb-2">Discovered Endpoints</h4>
              <div className="flex flex-wrap gap-1.5">
                {apiScanResult.endpoints.map((ep: string, i: number) => (
                  <code key={i} className="text-[10px] bg-black border border-[#27272a] px-2 py-0.5 rounded text-[#22c55e]">{ep}</code>
                ))}
              </div>
            </div>
          )}

          {apiScanResult.findings.length === 0 ? (
            <div className="p-3 bg-[#22c55e]/5 border border-[#22c55e]/20 rounded text-[11px] text-[#22c55e]">
              No active security issues detected on this target.
            </div>
          ) : (
            <div className="space-y-2">
              <h4 className="text-[10px] font-bold text-white uppercase tracking-wider">Security Findings</h4>
              {apiScanResult.findings.map((f: any, i: number) => (
                <div key={i} className="bg-black border border-[#27272a] rounded p-3.5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-white font-bold">{f.issue}</span>
                    <span className={`text-[9px] uppercase px-1.5 py-0.5 rounded border font-bold ${severityColor(f.severity)}`}>{f.severity}</span>
                  </div>
                  <code className="text-[10px] text-[#22c55e] block">{f.endpoint}</code>
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
