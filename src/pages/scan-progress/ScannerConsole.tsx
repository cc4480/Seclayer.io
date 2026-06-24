import { RefObject } from 'react';
import { Terminal } from 'lucide-react';

interface ScannerConsoleProps {
  logs: string[];
  logsEndRef: RefObject<HTMLDivElement | null>;
}

export default function ScannerConsole({ logs, logsEndRef }: ScannerConsoleProps) {
  return (
    <div className="bg-black border border-[#27272a] rounded p-5 overflow-hidden">
      <div className="flex items-center space-x-2 border-b border-[#27272a]/40 pb-3 mb-4">
        <Terminal className="w-4 h-4 text-[#22c55e] shrink-0" />
        <span className="text-[10px] font-mono text-[#52525b] uppercase tracking-widest">Scanner Console</span>
      </div>

      <div className="space-y-1.5 max-h-48 overflow-y-auto font-mono text-[11px] leading-relaxed text-[#a1a1aa] select-all scrollbar-thin">
        {logs.length === 0 ? (
          <div className="text-[#52525b] animate-pulse">Connecting to scanner daemon...</div>
        ) : (
          logs.map((log, index) => {
            let textClass = 'text-[#a1a1aa]';
            if (log.includes('[SYSTEM]') || log.includes('[COMPLETE]')) textClass = 'text-[#22c55e] font-semibold';
            if (log.includes('[SCANNER]') || log.includes('[DAST]') || log.includes('[HEADERS]') || log.includes('[EASM]')) textClass = 'text-purple-400';
            if (log.includes('[AI]')) textClass = 'text-amber-400';
            if (log.includes('[ERROR]')) textClass = 'text-[#f87171] font-bold';
            return <div key={index} className={textClass}>{log}</div>;
          })
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
}
