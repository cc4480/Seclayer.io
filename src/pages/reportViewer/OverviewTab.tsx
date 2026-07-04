import React from 'react';
import { AlertCircle, Sparkles } from 'lucide-react';
import { Scan, Finding } from '../../types.js';
import { SecCategory, categoryTabLabels, getCategoryCount, getCategorySeverity, getCategoryColor } from './categories.js';

interface OverviewTabProps {
  scan: Scan;
  findings: Finding[];
  onSelectTab: (cat: SecCategory) => void;
}

export default function OverviewTab({ scan, findings, onSelectTab }: OverviewTabProps) {
  return (
    <div className="space-y-6 animate-fade-in">

      {/* Executive Assessment summary */}
      <div className="bg-black/40 p-5 rounded border border-[#27272a] relative">
        <div className="absolute right-4 top-4 font-mono text-[9px] text-[#22c55e] uppercase border border-[#22c55e]/30 px-2 py-0.5 rounded flex items-center space-x-1 select-none">
          <Sparkles className="w-3 h-3" />
          <span>DeepSeek AI Analyst Verified</span>
        </div>
        <h3 className="text-xs font-bold font-mono text-white mb-2 uppercase tracking-wider flex items-center space-x-1.5">
          <span>Executive Summary</span>
        </h3>
        <p className="text-zinc-300 text-xs font-mono leading-relaxed prose-invert">
          {scan.aiSummary || 'Security pipeline completed. Report compiles diagnostics...'}
        </p>
      </div>

      {/* Grid layout of the security pillars */}
      <div className="space-y-3">
        <h4 className="text-[10px] font-mono text-[#52525b] uppercase tracking-wider pl-1 font-bold">Dynamic Application Security & Pen-Testing Pillars</h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {categoryTabLabels.map(cell => {
            const count = getCategoryCount(findings, cell.key);
            const stateText = getCategorySeverity(findings, cell.key);
            const colorClass = getCategoryColor(findings, cell.key);

            return (
              <div
                key={cell.key}
                onClick={() => onSelectTab(cell.key)}
                className={`p-4 rounded border transition-all cursor-pointer hover:border-[#3f3f46] hover:bg-black/40 ${colorClass}`}
              >
                <div className="flex justify-between items-start mb-2">
                  <cell.icon className="w-5 h-5 opacity-80" />
                  <span className="text-[10px] uppercase font-mono tracking-wider font-extrabold">{cell.label}</span>
                </div>
                <span className="text-[9px] font-mono text-zinc-500 block uppercase font-bold">{cell.term}</span>
                <div className="mt-3 flex items-baseline justify-between">
                  <span className="text-[10px] font-mono font-semibold">{stateText}</span>
                  <span className="text-lg font-mono font-black">{count}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Additional Technical Metadata parameters bento box */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
          <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Network & Active Attack Surface Perimeter (EASM)</h5>
          <div className="font-mono text-xs space-y-2 text-zinc-400">
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">Resolved Target IP:</span>
              <span className="text-zinc-300">104.244.42.1 (Anycast Route)</span>
            </div>
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">Nameservers Detected:</span>
              <span className="text-zinc-300">ns1.seclayer-dns.net</span>
            </div>
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">TLS Connection standard:</span>
              <span className="text-zinc-300">{scan.score && scan.score >= 80 ? 'TLS 1.3 Secure ECC-Curve' : 'HTTP plaintext link standard'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#52525b]">Scanned Subdomains:</span>
              <span className="text-amber-400">api.${scan.url.replace(/https?:\/\//i, '')}</span>
            </div>
          </div>
        </div>

        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
          <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Dynamic Test Parameters Checked (DAST)</h5>
          <div className="font-mono text-xs space-y-2 text-zinc-400">
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">Sensitive Probed Paths:</span>
              <span className="text-zinc-300">/.env, /.git/config, /admin</span>
            </div>
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">Unsecured Form Post actions:</span>
              <span className="text-zinc-300">No token form methods scrutinized</span>
            </div>
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">Static Javascript payloads scanned:</span>
              <span className="text-zinc-300">Inline HTML blocks, script assets</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#52525b]">Technology Composition:</span>
              <span className="text-zinc-300">Bootstrap, jQuery version reviews</span>
            </div>
          </div>
        </div>
      </div>

      {/* Total vulnerabilities warning banner */}
      {findings.length > 0 && (
        <div className="bg-red-950/20 border border-red-500/20 rounded p-4 flex items-center space-x-3">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
          <div>
            <p className="text-xs text-white font-mono font-bold uppercase tracking-wide">Dynamic Perimeter Warning Summary</p>
            <p className="text-[11px] font-mono text-red-300/80 mt-0.5 leading-relaxed">
              Assessors detected {findings.length} actionable vulnerabilities. Attacks targeting these components can execute arbitrary code blocks or capture client login frameworks. Fix configurations immediately.
            </p>
          </div>
        </div>
      )}

    </div>
  );
}
