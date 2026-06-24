import { AlertTriangle, ArrowLeft } from 'lucide-react';
import { Scan } from '../../types.js';

interface FailedScanViewProps {
  scan: Scan;
  logs: string[];
  onCancel: () => void;
}

export default function FailedScanView({ scan, logs, onCancel }: FailedScanViewProps) {
  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-20 px-6 flex items-center justify-center">
      <div className="max-w-2xl w-full bg-[#0c0c0e] border border-[#f87171]/30 p-8 rounded shadow-2xl space-y-6">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-full bg-[#f87171]/10 border border-[#f87171]/20 flex items-center justify-center shrink-0">
            <AlertTriangle className="w-6 h-6 text-[#f87171]" />
          </div>
          <div>
            <p className="text-xs font-mono text-[#f87171] uppercase tracking-widest font-bold">Scan Failed</p>
            <h2 className="text-white font-mono font-bold text-lg truncate">{scan.url}</h2>
          </div>
        </div>

        <div className="bg-black border border-[#27272a] rounded p-4 font-mono text-sm text-[#f87171]">
          {scan.error || 'An unexpected error occurred during the scan. The target may be unreachable or blocked our probes.'}
        </div>

        {logs.length > 0 && (
          <div className="bg-black border border-[#27272a] rounded p-4 max-h-40 overflow-y-auto space-y-1 font-mono text-[11px] text-[#a1a1aa]">
            {logs.map((log, i) => <div key={i} className={log.includes('[ERROR]') ? 'text-[#f87171]' : ''}>{log}</div>)}
          </div>
        )}

        <button
          onClick={onCancel}
          className="flex items-center gap-2 text-xs font-mono text-[#52525b] hover:text-white transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to dashboard
        </button>
      </div>
    </div>
  );
}
