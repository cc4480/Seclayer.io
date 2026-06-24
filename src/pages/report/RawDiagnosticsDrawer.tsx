import { useState } from 'react';
import { Terminal, ChevronDown, ChevronUp } from 'lucide-react';
import { Scan, Finding } from '../../types.js';

interface RawDiagnosticsDrawerProps {
  scan: Scan;
  findings: Finding[];
}

/**
 * Collapsible "Diagnostic Raw Headers & Outputs" drawer shown at the bottom
 * of the report, dumping the raw scan diagnostics (request/response headers,
 * DNS/attack-surface info, probed paths, security headers, red-team probes).
 */
export default function RawDiagnosticsDrawer({ scan, findings }: RawDiagnosticsDrawerProps) {
  const [showRaw, setShowRaw] = useState(false);

  return (
    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
      <button
        onClick={() => setShowRaw(!showRaw)}
        className="w-full flex items-center justify-between text-[#a1a1aa] hover:text-white font-mono text-xs uppercase tracking-wider cursor-pointer"
      >
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-[#22c55e]" />
          <span>Diagnostic Raw Headers & Outputs</span>
        </div>
        {showRaw ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
      </button>

      {showRaw && (
        <div className="mt-5 space-y-4 pt-4 border-t border-[#27272a] animate-fade-in">
          <p className="text-[#52525b] text-[11px] leading-relaxed font-mono">
            Captured directly from the live scan of {scan.url}. These are the actual request, DNS, path-probe, and response values observed by the scanner.
          </p>

          {!scan.diagnostics ? (
            <div className="bg-black p-4 rounded font-mono text-[11px] text-[#52525b] border border-[#27272a]">
              Raw diagnostics are not available for this scan. Re-run the scan to capture live trace data.
            </div>
          ) : (
            <div className="bg-black p-4 rounded font-mono text-[10px] text-zinc-400 space-y-2 border border-[#27272a] max-h-96 overflow-y-auto">
              <span className="text-[#52525b] text-[9px] uppercase font-bold block mb-1">Outbound request</span>
              <p className="text-zinc-200">GET {(() => { try { return new URL(scan.url.startsWith('http') ? scan.url : `https://${scan.url}`).pathname || '/'; } catch { return '/'; } })()} HTTP/1.1</p>
              <p className="text-zinc-200">Host: {scan.url.replace(/https?:\/\//i, '').replace(/\/.*$/, '')}</p>
              {Object.entries(scan.diagnostics.requestHeaders).map(([k, v]) => (
                <p key={k} className="text-[#52525b]">{k}: {v}</p>
              ))}

              <p className="text-[#22c55e] font-bold mt-3">{'[EASM — DNS & ATTACK SURFACE]'}</p>
              <p className="text-zinc-400">Target host: {scan.url}</p>
              <p className="text-zinc-400">Resolved IP: {scan.diagnostics.ip}</p>
              <p className="text-zinc-400">Nameserver: {scan.diagnostics.nameserver}</p>
              <p className="text-zinc-400">Transport: {scan.diagnostics.protocol}</p>
              <p className="text-zinc-400">Live subdomains discovered: {scan.diagnostics.liveSubdomains}</p>
              {scan.diagnostics.techLeaked.length > 0 && (
                <p className="text-amber-400">Tech signatures leaked: {scan.diagnostics.techLeaked.join(', ')}</p>
              )}

              <p className="text-[#22c55e] font-bold mt-3">{'[DAST — SENSITIVE PATH PROBES]'}</p>
              {scan.diagnostics.probedPaths.length > 0 ? (
                scan.diagnostics.probedPaths.map((p, i) => (
                  <p key={i} className="text-zinc-200">
                    Path: <span className="text-amber-400">{p.path}</span> — Status: {p.status || 'no response'}{' '}
                    <span className={p.exposed ? 'text-red-500 font-bold' : 'text-[#22c55e]'}>
                      {p.exposed ? '(EXPOSED)' : '(protected)'}
                    </span>
                  </p>
                ))
              ) : (
                <p className="text-zinc-500">No path-probe data captured.</p>
              )}

              <p className="text-[#22c55e] font-bold mt-4">{'[HTTP RESPONSE]'}</p>
              <p className="text-zinc-300">Status: {scan.diagnostics.responseStatus || 'no response'}</p>
              {Object.entries(scan.diagnostics.responseHeaders).length > 0 ? (
                Object.entries(scan.diagnostics.responseHeaders).map(([k, v]) => (
                  <p key={k} className="text-zinc-300">{k}: {v}</p>
                ))
              ) : (
                <p className="text-zinc-500">No response headers captured.</p>
              )}

              <p className="text-[#22c55e] font-bold mt-4">{'[SECURITY HEADER CONTROLS]'}</p>
              {scan.diagnostics.missingHeaders.length > 0 ? (
                scan.diagnostics.missingHeaders.map((h, i) => (
                  <p key={i} className="text-zinc-450">{h}: <span className="text-red-400">ABSENT</span></p>
                ))
              ) : (
                <p className="text-[#22c55e]">All standard security headers present.</p>
              )}

              <p className="text-red-500 font-bold mt-4">{'[RED TEAM ACTIVE PROBES]'}</p>
              {findings.filter(f => f.category === 'RED_TEAM').length > 0 ? (
                findings.filter(f => f.category === 'RED_TEAM').map((f, i) => (
                  <p key={i} className="text-zinc-300">{`${f.title} → ${f.severity.toUpperCase()}`}</p>
                ))
              ) : (
                <p className="text-zinc-300">No active exploit signatures confirmed.</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
