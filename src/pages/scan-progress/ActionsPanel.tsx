import { Cpu } from 'lucide-react';
import { ScanStatus } from '../../types.js';

interface ActionsPanelProps {
  status: ScanStatus | undefined;
  onCancel: () => void;
}

export default function ActionsPanel({ status, onCancel }: ActionsPanelProps) {
  return (
    <div className="border-t border-[#27272a] pt-5 font-mono text-xs text-[#52525b]">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-1.5">
          <Cpu className="w-4 h-4 text-[#22c55e] shrink-0" />
          <span>Scanning using Seclayer Daemon v2</span>
        </div>
        {status !== 'complete' && (
          <button
            onClick={onCancel}
            className="text-[#52525b] hover:text-[#f87171] transition-colors cursor-pointer"
            id="cancel-scan-btn"
          >
            Cancel scan
          </button>
        )}
      </div>
    </div>
  );
}
