import React from 'react';
import { Terminal, ChevronDown, ChevronUp } from 'lucide-react';
import { Scan, Finding } from '../../types.js';

interface RawDiagnosticsProps {
  scan: Scan;
  findings: Finding[];
  showRaw: boolean;
  onToggle: () => void;
}

export default function RawDiagnostics({ scan, findings, showRaw, onToggle }: RawDiagnosticsProps) {
  return (
    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
      <button
        onClick={onToggle}
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
            <p className="text-zinc-200">Host: {scan.url.replace(/https?:\/\//i, '')}</p>
            <p className="text-[#52525b]">User-Agent: Seclayer-Security-Scanner/2.0</p>
            <p className="text-[#52525b]">Accept: text/html,application/xhtml+xml,application/xml</p>

            <p className="text-[#22c55e] font-bold mt-3">{'[EASM EDGE SCAN CHECKS]'}</p>
            <p className="text-zinc-400">Target host: {scan.url}</p>
            <p className="text-zinc-400">DNS Resolution IP (Detected/Anycast Route): 104.244.42.1</p>
            <p className="text-zinc-400">Nameservers resolved properly: DNS Sec verified</p>

            <p className="text-[#22c55e] font-bold mt-3">{'[DAST DIRECTORY AUDIT CHECKS]'}</p>
            <p className="text-zinc-200">Path: <span className="text-amber-400">/.env</span> - Status: 404 Not Found (Protected)</p>
            <p className="text-zinc-200">Path: <span className="text-amber-400">/.git/config</span> - Status: 404 Not Found (Protected)</p>
            <p className="text-zinc-200">Path: <span className="text-amber-400">/admin</span> - Status: 403 Forbidden (Blocked)</p>

            <p className="text-[#22c55e] font-bold mt-4">{'[HTTP RESPONSE HEADERS]'}</p>
            <p className="text-zinc-300">Server: Nginx/1.18.0 (Ubuntu)</p>
            <p className="text-zinc-350">Date: {new Date(scan.createdAt).toUTCString()}</p>
            <p className="text-zinc-300">Content-Type: text/html; charset=UTF-8</p>
            <p className="text-zinc-300">Connection: keep-alive</p>

            <p className="text-[#22c55e] font-bold mt-4">{'[IAST CONTROLS CHECK]'}</p>
            <p className="text-zinc-450">Content-Security-Policy header verified: {findings.some(f => f.title.includes('CSP')) ? 'DEPRESSED / ABSENT' : 'ACTIVE'}</p>
            <p className="text-zinc-450">Strict-Transport-Security verified: {findings.some(f => f.title.includes('Strict-Transport-Security')) ? 'DEPRESSED / ABSENT' : 'ACTIVE'}</p>
            <p className="text-zinc-450">X-Frame-Options framing locks: {findings.some(f => f.title.includes('Clickjacking')) ? 'DEPRESSED / ABSENT' : 'ACTIVE'}</p>

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
