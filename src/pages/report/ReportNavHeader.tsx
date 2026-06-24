import { ArrowLeft, Download, Share2, Check } from 'lucide-react';

interface ReportNavHeaderProps {
  copiedLink: boolean;
  onBack: () => void;
  onShareClick: () => void;
  onDownloadPdf: () => void;
}

/**
 * Top-of-report nav row: "back to workspace" button plus the share-link and
 * download-PDF actions.
 */
export default function ReportNavHeader({
  copiedLink,
  onBack,
  onShareClick,
  onDownloadPdf,
}: ReportNavHeaderProps) {
  return (
    <div className="flex items-center justify-between">
      <button
        onClick={onBack}
        className="flex items-center space-x-2 text-[#a1a1aa] hover:text-white font-mono text-xs uppercase tracking-wider transition-colors cursor-pointer"
        id="report-back-btn"
      >
        <ArrowLeft className="w-4 h-4 text-[#22c55e]" />
        <span>Audit Workspace</span>
      </button>

      <div className="flex items-center space-x-3">
        <button
          onClick={onShareClick}
          className="px-3.5 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa] hover:text-white text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer"
          id="report-share-btn"
        >
          {copiedLink ? <Check className="w-3.5 h-3.5 text-[#22c55e]" /> : <Share2 className="w-3.5 h-3.5 text-[#52525b]" />}
          <span>{copiedLink ? 'Copied' : 'Share Link'}</span>
        </button>
        <button
          onClick={onDownloadPdf}
          className="px-3.5 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa] hover:text-white text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer"
          id="report-download-btn"
        >
          <Download className="w-3.5 h-3.5 text-[#52525b]" />
          <span>Download PDF Report</span>
        </button>
      </div>
    </div>
  );
}
