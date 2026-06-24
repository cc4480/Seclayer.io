import { Sparkles, Grid, AlertCircle } from 'lucide-react';
import { Scan, Finding } from '../../types.js';
import { SecCategory, getCategoryCount, getCategorySeverity, getCategoryColor, categoryTabLabels } from './reportHelpers.js';

interface OverviewTabProps {
  scan: Scan;
  findings: Finding[];
  onSelectCategory: (cat: SecCategory) => void;
}

export default function OverviewTab({ scan, findings, onSelectCategory }: OverviewTabProps) {
  return (
    <div className="space-y-6 animate-fade-in">

      {/* Executive Assessment summary */}
      <div className="bg-black/40 p-5 rounded border border-[#27272a] relative">
        <div className="absolute right-4 top-4 font-mono text-[9px] text-[#22c55e] uppercase border border-[#22c55e]/30 px-2 py-0.5 rounded flex items-center space-x-1 select-none">
          <Sparkles className="w-3 h-3" />
          <span>AI-Powered Analysis</span>
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
                onClick={() => onSelectCategory(cell.key)}
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
          <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Network & Attack Surface (EASM)</h5>
          <div className="font-mono text-xs space-y-2 text-zinc-400">
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">Target Host:</span>
              <span className="text-zinc-300 truncate max-w-[180px]">{(() => { try { return new URL(scan.url.startsWith('http') ? scan.url : `https://${scan.url}`).hostname; } catch { return scan.url; } })()}</span>
            </div>
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">Transport Security:</span>
              <span className={findings.some(f => f.category === 'EASM' && /ssl|tls|https/i.test(f.title)) ? 'text-[#f87171]' : 'text-[#22c55e]'}>
                {findings.some(f => f.category === 'EASM' && /ssl|tls|https/i.test(f.title)) ? 'Issues detected' : 'Secure (HTTPS)'}
              </span>
            </div>
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">EASM Findings:</span>
              <span className="text-zinc-300">{findings.filter(f => f.category === 'EASM').length} issue{findings.filter(f => f.category === 'EASM').length !== 1 ? 's' : ''} detected</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#52525b]">DNS / Subdomains:</span>
              <span className="text-[#52525b] italic">Run EASM tab for full recon</span>
            </div>
          </div>
        </div>

        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
          <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Dynamic Probes Executed (DAST)</h5>
          <div className="font-mono text-xs space-y-2 text-zinc-400">
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">Injection probes:</span>
              <span className="text-zinc-300">SQLi, XSS, SSTI, CRLF, LFI</span>
            </div>
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">Header analysis:</span>
              <span className="text-zinc-300">HSTS, CSP, X-Frame, CORS, Referrer</span>
            </div>
            <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
              <span className="text-[#52525b]">Redirect / CORS:</span>
              <span className="text-zinc-300">Open redirect, origin reflection</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#52525b]">DAST findings:</span>
              <span className="text-zinc-300">{findings.filter(f => f.category === 'DAST').length} issue{findings.filter(f => f.category === 'DAST').length !== 1 ? 's' : ''} detected</span>
            </div>
          </div>
        </div>
      </div>

      {/* Application Surface Map — deep crawl coverage */}
      {scan.crawl && scan.crawl.pagesCrawled > 0 && (
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold flex items-center space-x-2">
              <Grid className="w-3.5 h-3.5 text-[#22c55e]" />
              <span>Application Surface Map (Deep Crawl)</span>
            </h5>
            {scan.crawl.authenticated && (
              <span className="text-[9px] font-mono uppercase bg-[#22c55e]/10 border border-[#22c55e]/20 text-[#22c55e] px-2 py-0.5 rounded">Authenticated</span>
            )}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'Pages Crawled', value: scan.crawl.pagesCrawled },
              { label: 'Forms Found', value: scan.crawl.forms.length },
              { label: 'Parameters', value: scan.crawl.discoveredParams.length },
              { label: 'Crawl Depth', value: scan.crawl.maxDepthReached },
            ].map((stat) => (
              <div key={stat.label} className="bg-black border border-[#27272a]/60 rounded p-3 text-center">
                <div className="text-xl font-mono font-bold text-[#22c55e]">{stat.value}</div>
                <div className="text-[9px] font-mono uppercase tracking-wider text-[#52525b] mt-1">{stat.label}</div>
              </div>
            ))}
          </div>
          {scan.crawl.forms.length > 0 && (
            <div className="space-y-1.5">
              <span className="text-[9px] font-mono uppercase tracking-wider text-[#52525b]">Discovered Forms</span>
              <div className="max-h-32 overflow-y-auto scrollbar-thin space-y-1">
                {scan.crawl.forms.slice(0, 12).map((f, i) => (
                  <div key={i} className="flex items-center justify-between font-mono text-[10px] bg-black border border-[#27272a]/40 rounded px-2.5 py-1.5">
                    <span className="text-zinc-400 truncate max-w-[60%]"><span className="text-[#52525b]">{f.method}</span> {f.action}</span>
                    <span className="flex items-center gap-1.5 shrink-0">
                      {f.hasPassword && <span className="text-amber-400">password</span>}
                      {f.insecure && <span className="text-[#f87171]">http</span>}
                      {f.method === 'POST' && (f.hasCsrfToken
                        ? <span className="text-[#22c55e]">csrf✓</span>
                        : <span className="text-[#f87171]">no-csrf</span>)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <p className="text-[10px] font-mono text-[#52525b] leading-relaxed">
            Crawled {scan.crawl.pagesCrawled} same-origin page(s) in {(scan.crawl.durationMs / 1000).toFixed(1)}s. Business-logic checks (insecure credential forms, missing CSRF tokens, mixed content, object-reference / IDOR signals) run against this discovered surface and appear in the findings above.
          </p>
        </div>
      )}

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
