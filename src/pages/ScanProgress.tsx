import { RefreshCw } from 'lucide-react';
import { useScanProgress } from './scan-progress/useScanProgress.js';
import FailedScanView from './scan-progress/FailedScanView.js';
import PipelineProgress from './scan-progress/PipelineProgress.js';
import ScannerConsole from './scan-progress/ScannerConsole.js';
import ActionsPanel from './scan-progress/ActionsPanel.js';

interface ScanProgressProps {
  scanId: string;
  onScanFinished: (scanId: string) => void;
  onCancel: () => void;
}

export default function ScanProgress({ scanId, onScanFinished, onCancel }: ScanProgressProps) {
  const { scan, logs, progressPercent, logsEndRef } = useScanProgress(scanId, onScanFinished);

  if (scan?.status === 'failed') {
    return <FailedScanView scan={scan} logs={logs} onCancel={onCancel} />;
  }

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-20 px-6 flex items-center justify-center">
      <div className="max-w-2xl w-full space-y-8 bg-[#0c0c0e] border border-[#27272a] p-8 rounded shadow-2xl relative overflow-hidden">

        <div className="absolute right-0 top-0 bg-[#22c55e]/5 w-96 h-96 rounded-full blur-3xl pointer-events-none" />

        <div className="text-center space-y-4">
          <div className="relative inline-flex items-center justify-center w-20 h-20 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded-full mb-2">
            <RefreshCw className="w-8 h-8 text-[#22c55e] animate-spin" />
            <div className="absolute inset-2 border-2 border-dashed border-[#22c55e]/10 rounded-full" />
          </div>

          <div>
            <span className="text-[10px] font-mono text-[#22c55e] uppercase tracking-widest block font-bold mb-1">
              Active Black-Box Penetration Audit
            </span>
            <h1 className="text-xl font-bold font-mono text-white max-w-md mx-auto truncate select-all">
              {scan?.url || 'Awaiting connection...'}
            </h1>
          </div>
        </div>

        <PipelineProgress progressPercent={progressPercent} status={scan?.status} />

        <ScannerConsole logs={logs} logsEndRef={logsEndRef} />

        <ActionsPanel status={scan?.status} onCancel={onCancel} />

      </div>
    </div>
  );
}
