import React, { useState } from 'react';
import { Shield, Globe, Play, RefreshCw, AlertTriangle, Info } from 'lucide-react';
import { apiFetch } from '../../lib/api.js';

type SubTab = 'aspm' | 'easm' | 'apiscan' | 'iast' | 'pentagi';

export default function OrchestratorTab() {
  const [orchSubTab, setOrchSubTab] = useState<SubTab>('pentagi');

  // ASPM
  const [aspmUrl, setAspmUrl] = useState('');
  const [aspmRunning, setAspmRunning] = useState(false);
  const [aspmOutput, setAspmOutput] = useState<any | null>(null);
  const [aspmError, setAspmError] = useState<string | null>(null);

  // EASM
  const [easmDomain, setEasmDomain] = useState('');
  const [easmRunning, setEasmRunning] = useState(false);
  const [easmData, setEasmData] = useState<any | null>(null);
  const [easmError, setEasmError] = useState<string | null>(null);

  // API Scan / Hadrian
  const [apiScanUrl, setApiScanUrl] = useState('');
  const [apiScanRunning, setApiScanRunning] = useState(false);
  const [apiScanResult, setApiScanResult] = useState<any | null>(null);
  const [apiScanError, setApiScanError] = useState<string | null>(null);

  // IAST
  const [iastRunning, setIastRunning] = useState(false);
  const [iastResult, setIastResult] = useState<any | null>(null);
  const [iastError, setIastError] = useState<string | null>(null);

  // PentAGI
  const [pentagiUrl, setPentagiUrl] = useState('');
  const [pentagiRunning, setPentagiRunning] = useState(false);
  const [pentagiLogs, setPentagiLogs] = useState<any[]>([]);
  const [pentagiError, setPentagiError] = useState<string | null>(null);

  const runAspmCorrelation = async () => {
    setAspmRunning(true);
    setAspmOutput(null);
    setAspmError(null);
    try {
      const res = await apiFetch('/api/enterprise/aspm/correlate', {
        method: 'POST',
        body: JSON.stringify({ url: aspmUrl || undefined }),
      });
      const data = await res.json();
      if (res.ok) setAspmOutput(data);
      else setAspmError(data.error || 'Correlation failed.');
    } catch (err: any) {
      setAspmError(err.message || 'Network error.');
    } finally {
      setAspmRunning(false);
    }
  };

  const runEasmRecon = async () => {
    setEasmRunning(true);
    setEasmData(null);
    setEasmError(null);
    try {
      const res = await apiFetch('/api/enterprise/easm/recon', {
        method: 'POST',
        body: JSON.stringify({ domain: easmDomain }),
      });
      const data = await res.json();
      if (res.ok) setEasmData(data);
      else setEasmError(data.error || 'EASM recon failed.');
    } catch (err: any) {
      setEasmError(err.message || 'Network error.');
    } finally {
      setEasmRunning(false);
    }
  };

  const runHadrianScan = async () => {
    setApiScanRunning(true);
    setApiScanResult(null);
    setApiScanError(null);
    try {
      const res = await apiFetch('/api/enterprise/api-scan/hadrian', {
        method: 'POST',
        body: JSON.stringify({ url: apiScanUrl }),
      });
      const data = await res.json();
      if (res.ok) setApiScanResult(data);
      else setApiScanError(data.error || 'API scan failed.');
    } catch (err: any) {
      setApiScanError(err.message || 'Network error.');
    } finally {
      setApiScanRunning(false);
    }
  };

  const runIastTrace = async () => {
    setIastRunning(true);
    setIastResult(null);
    setIastError(null);
    try {
      const res = await apiFetch('/api/enterprise/iast/trace', { method: 'POST', body: JSON.stringify({}) });
      const data = await res.json();
      if (res.ok || res.status === 501) setIastResult(data);
      else setIastError(data.error || 'IAST trace failed.');
    } catch (err: any) {
      setIastError(err.message || 'Network error.');
    } finally {
      setIastRunning(false);
    }
  };

  const runPentagiExploitation = async () => {
    if (!pentagiUrl.trim()) {
      setPentagiError('Enter a target URL before running PentAGI.');
      return;
    }
    setPentagiRunning(true);
    setPentagiLogs([]);
    setPentagiError(null);
    try {
      const res = await apiFetch(`/api/enterprise/pentagi/logs?url=${encodeURIComponent(pentagiUrl.trim())}`);
      if (res.ok) {
        const data = await res.json();
        let idx = 0;
        const interval = setInterval(() => {
          if (idx < data.logs.length) {
            setPentagiLogs(prev => [...prev, data.logs[idx]]);
            idx++;
          } else {
            clearInterval(interval);
            setPentagiRunning(false);
          }
        }, 750);
      } else {
        const data = await res.json();
        setPentagiError(data.error || 'PentAGI run failed.');
        setPentagiRunning(false);
      }
    } catch (err: any) {
      setPentagiError(err.message || 'Network error.');
      setPentagiRunning(false);
    }
  };

  const severityColor = (s: string) =>
    s === 'critical' ? 'text-red-400 bg-red-950/30 border-red-900/40' :
    s === 'high' ? 'text-[#f87171] bg-[#f87171]/10 border-[#f87171]/20' :
    s === 'medium' ? 'text-amber-400 bg-amber-950/20 border-amber-900/30' :
    'text-[#a1a1aa] bg-black border-[#27272a]';

  const subTabs: Array<{ id: SubTab; label: string; subtitle: string }> = [
    { id: 'aspm', label: 'ASPM Correlation', subtitle: 'DefectDojo & Fusion' },
    { id: 'easm', label: 'EASM Perimeter', subtitle: 'Amass Subdomains' },
    { id: 'apiscan', label: 'API Security Testing', subtitle: 'Hadrian Matrix' },
    { id: 'iast', label: 'Interactive Passive Testing', subtitle: 'DongTai IAST Tracer' },
    { id: 'pentagi', label: 'Autonomous Pentest AI', subtitle: 'PentAGI Cooperative Agents' },
  ];

  return (
    <div className="space-y-6 text-xs font-mono">
      <div className="bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5">
        <Shield className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5 animate-pulse" />
        <div className="space-y-1">
          <h4 className="text-white text-xs uppercase font-bold">Autonomous PentAGI & Microservices</h4>
          <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
            Trigger our autonomous AI ethical hacker agents, or utilize standalone security engines to de-duplicate, verify, and trace live exploitable postures.
          </p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 border-b border-[#27272a]/40 pb-3">
        {subTabs.map(sub => (
          <button
            key={sub.id}
            onClick={() => setOrchSubTab(sub.id)}
            className={`flex-1 min-w-[150px] p-3 rounded border text-left cursor-pointer transition-all ${
              orchSubTab === sub.id
                ? 'bg-[#22c55e]/5 border-[#22c55e] text-white'
                : 'bg-black border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa]'
            }`}
          >
            <span className="text-[10px] uppercase font-bold text-[#22c55e] block mb-0.5">{sub.label}</span>
            <span className="text-[9px] text-[#52525b] block">{sub.subtitle}</span>
          </button>
        ))}
      </div>

      {/* ASPM */}
      {orchSubTab === 'aspm' && (
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
      )}

      {/* EASM */}
      {orchSubTab === 'easm' && (
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
      )}

      {/* API Security Scan */}
      {orchSubTab === 'apiscan' && (
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
      )}

      {/* IAST */}
      {orchSubTab === 'iast' && (
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
      )}

      {/* PentAGI */}
      {orchSubTab === 'pentagi' && (
        <div className="space-y-4 bg-black/40 border border-[#27272a] rounded p-6">
          <div>
            <h3 className="text-sm font-bold text-white mb-1 uppercase tracking-tight flex items-center gap-1.5">
              <span>5. Multi-Agent Autonomous Pentesting (PentAGI)</span>
              <span className="bg-[#18181b] text-[#52525b] text-[9px] px-2 py-0.5 rounded ml-2">AutoPentest-AI Executor</span>
            </h3>
            <p className="text-[#a1a1aa] text-[11px] mb-4">
              LLM-driven cooperative agents running inside sandboxed containers. Scout spiders the target, Exploiter crafts multi-stage bypass attacks, and Reporter maps vulnerability entities into a structured exploitation graph.
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
      )}
    </div>
  );
}
