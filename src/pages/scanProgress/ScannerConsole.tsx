import React from 'react';
import { Terminal } from 'lucide-react';

// Scrolling terminal panel of scanner console output lines. The parent owns the
// end-anchor ref so it can auto-scroll as new lines arrive.
export default function ScannerConsole({ logs, endRef }: { logs: string[]; endRef: React.RefObject<HTMLDivElement> }) {
  return (
    <div className="bg-black border border-[#27272a] rounded p-5 overflow-hidden">
      <div className="flex items-center space-x-2 border-b border-[#27272a]/40 pb-3 mb-4">
        <Terminal className="w-4 h-4 text-[#22c55e] shrink-0" />
        <span className="text-[10px] font-mono text-[#52525b] uppercase tracking-widest">Scanner Console outputs</span>
      </div>

      <div className="space-y-1.5 max-h-48 overflow-y-auto font-mono text-[11px] leading-relaxed text-[#a1a1aa] select-all scrollbar-thin">
        {logs.map((log, index) => {
          let textClass = 'text-[#a1a1aa]';
          if (log.includes('[SYSTEM]')) textClass = 'text-[#22c55e] font-semibold';
          if (log.includes('[DAEMON]')) textClass = 'text-purple-400';
          if (log.includes('[DEEPSEEK]')) textClass = 'text-amber-400';
          if (log.includes('[FATAL]')) textClass = 'text-[#f87171] font-bold';
          return (
            <div key={index} className={textClass}>
              {log}
            </div>
          );
        })}
        <div ref={endRef} />
      </div>
    </div>
  );
}
