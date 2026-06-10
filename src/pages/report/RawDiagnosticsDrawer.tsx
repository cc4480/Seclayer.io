import React, { useState } from 'react';
import { Terminal, ChevronDown, ChevronUp } from 'lucide-react';
import { Scan, Finding } from '../../types.js';

interface RawDiagnosticsDrawerProps {
  scan: Scan;
  findings: Finding[];
}

/** Collapsible raw headers / probe-log inspection drawer at the bottom of the report. */
export default function RawDiagnosticsDrawer({ scan, findings }: RawDiagnosticsDrawerProps) {
  const [showRaw, setShowRaw] = useState(false);
  const diag = scan.diagnostics;
  const hostname = scan.url.replace(/https?:\/\//i, '').replace(/\/+$/, '');

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
            Tracelog components capture direct responses matching initial dynamic server socket scans. Use these coordinates for raw manual exploit confirmations.
          </p>

          <div className="bg-black p-4 rounded font-mono text-[10px] text-zinc-400 space-y-2 border border-[#27272a] max-h-96 overflow-y-auto">
            <span className="text-[#52525b] text-[9px] uppercase font-bold block mb-1">Raw pen-testing log sequences</span>
            <p className="text-zinc-200">{'GET / HTTP/1.1'}</p>
            <p className="text-zinc-200">Host: {hostname}</p>
            <p className="text-[#52525b]">User-Agent: Seclayer-Security-Scanner/2.0 (seclayer.io; scanner@seclayer.io)</p>
            <p className="text-[#52525b]">Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8</p>

            <p className="text-[#22c55e] font-bold mt-3">{'[EASM EDGE SCAN CHECKS]'}</p>
            <p className="text-zinc-400">Target host: {scan.url}</p>
            <p className="text-zinc-400">DNS Resolution IP: {diag && diag.easmPerimeter.ip !== 'unresolved' ? diag.easmPerimeter.ip : 'Unresolved'}</p>
            <p className="text-zinc-400">Nameservers: {diag && diag.easmPerimeter.nameserver !== 'unresolved' ? diag.easmPerimeter.nameserver : 'Unresolved'}</p>
            {diag && diag.easmPerimeter.subdomains.length > 0 ? (
              diag.easmPerimeter.subdomains.map((s, i) => (
                <p key={i} className="text-zinc-300">Subdomain: {s.domain} - {s.status.toUpperCase()} (port {s.port})</p>
              ))
            ) : (
              <p className="text-zinc-300">No live subdomains discovered.</p>
            )}

            <p className="text-[#22c55e] font-bold mt-3">{'[DAST DIRECTORY AUDIT CHECKS]'}</p>
            {diag && diag.probedPaths.length > 0 ? (
              diag.probedPaths.map((p, i) => (
                <p key={i} className="text-zinc-200">Path: <span className="text-amber-400">{p.path}</span> - Status: {p.status} ({p.exposed ? 'Exposed' : 'Protected'})</p>
              ))
            ) : (
              <p className="text-zinc-300">No directory probes recorded for this scan.</p>
            )}

            <p className="text-[#22c55e] font-bold mt-4">{'[HTTP RESPONSE HEADERS]'}</p>
            {diag ? (
              <>
                <p className="text-zinc-300">Status: {diag.responseStatus}</p>
                <p className="text-zinc-300">Server: {diag.headers['server'] || 'Not disclosed'}</p>
                <p className="text-zinc-300">Content-Type: {diag.headers['content-type'] || 'N/A'}</p>
                <p className="text-zinc-300">Date: {new Date(scan.createdAt).toUTCString()}</p>
              </>
            ) : (
              <p className="text-zinc-300">Header capture not available for this scan.</p>
            )}

            <p className="text-[#22c55e] font-bold mt-4">{'[IAST CONTROLS CHECK]'}</p>
            <p className="text-zinc-400">Content-Security-Policy header: {diag ? (diag.missingHeaders.includes('content-security-policy') ? 'ABSENT' : 'ACTIVE') : (findings.some(f => f.title.includes('CSP')) ? 'ABSENT' : 'ACTIVE')}</p>
            <p className="text-zinc-400">Strict-Transport-Security header: {diag ? (diag.missingHeaders.includes('strict-transport-security') ? 'ABSENT' : 'ACTIVE') : (findings.some(f => f.title.includes('Strict-Transport-Security')) ? 'ABSENT' : 'ACTIVE')}</p>
            <p className="text-zinc-400">X-Frame-Options header: {diag ? (diag.missingHeaders.includes('x-frame-options') ? 'ABSENT' : 'ACTIVE') : (findings.some(f => f.title.includes('Clickjacking')) ? 'ABSENT' : 'ACTIVE')}</p>

            <p className="text-red-500 font-bold mt-4">{'[RED TEAM ACTIVE FUZZING PROBES]'}</p>
            <p className="text-zinc-400">Target host: {scan.url}</p>
            {findings.filter(f => f.category === 'RED_TEAM').length > 0 ? (
              findings.filter(f => f.category === 'RED_TEAM').map((f, i) => (
                <p key={i} className="text-zinc-300">{`Phase ${i + 1}: ${f.title} -> ${f.severity.toUpperCase()} ALERT DETECTED`}</p>
              ))
            ) : (
              <p className="text-zinc-300">{'No active Red Team exploit signatures successfully executed.'}</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
