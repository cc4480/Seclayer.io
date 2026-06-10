import React from 'react';
import { Globe, CheckCircle, ExternalLink } from 'lucide-react';
import { Scan } from '../../types.js';

interface ScanRowProps {
  // The project compiles without @types/react, so the special React `key`
  // prop must be declared explicitly for keyed-list usage to typecheck.
  key?: string;
  scan: Scan;
  onViewReport: (scanId: string) => void;
}

/** One scan-history table row with status, score, and severity badges. */
export default function ScanRow({ scan, onViewReport }: ScanRowProps) {
  // Status Badge selection
  let statusBadge = (
    <span className="bg-black text-[#52525b] font-mono text-[9px] uppercase px-2 py-0.5 rounded border border-[#27272a]">
      {scan.status}
    </span>
  );
  if (scan.status === 'complete') {
    statusBadge = (
      <span className="bg-[#22c55e]/10 border border-[#22c55e]/25 text-[#22c55e] font-mono text-[9px] uppercase px-2 py-0.5 rounded flex items-center space-x-1.5 w-fit">
        <CheckCircle className="w-3 h-3 text-[#22c55e] shrink-0" />
        <span>Complete</span>
      </span>
    );
  } else if (scan.status === 'queued') {
    statusBadge = (
      <span className="bg-blue-950/40 border border-[#27272a] text-blue-400 font-mono text-[9px] uppercase px-2 py-0.5 rounded animate-pulse">
        Queued
      </span>
    );
  } else if (scan.status === 'scanning') {
    statusBadge = (
      <span className="bg-purple-950/40 border border-[#27272a] text-purple-400 font-mono text-[9px] uppercase px-2 py-0.5 rounded animate-pulse">
        Scanning...
      </span>
    );
  } else if (scan.status === 'analyzing') {
    statusBadge = (
      <span className="bg-amber-950/40 border border-[#27272a] text-amber-400 font-mono text-[9px] uppercase px-2 py-0.5 rounded animate-pulse">
        Analyzing AI...
      </span>
    );
  } else if (scan.status === 'failed') {
    statusBadge = (
      <span className="bg-[#f87171]/10 border border-[#f87171]/25 text-[#f87171] font-mono text-[9px] uppercase px-2 py-0.5 rounded">
        Failed
      </span>
    );
  }

  // Score calculation badge
  const scoreColor =
    !scan.score ? 'text-zinc-500' :
    scan.score >= 90 ? 'text-[#22c55e]' :
    scan.score >= 70 ? 'text-amber-400' : 'text-[#f87171]';

  // Severity calculation Badge
  let severityBadge = (
    <span className="text-[#52525b] font-mono text-[10px]">—</span>
  );
  if (scan.status === 'complete' && scan.severity) {
    const colorClass =
      scan.severity === 'critical' || scan.severity === 'high' ? 'bg-[#f87171]/10 text-[#f87171] font-bold border border-[#f87171]/20' :
      scan.severity === 'medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/10' :
      'bg-black text-[#a1a1aa] border border-[#27272a]';
    severityBadge = (
      <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded ${colorClass}`}>
        {scan.severity}
      </span>
    );
  }

  return (
    <tr
      onClick={() => onViewReport(scan.id)}
      className="hover:bg-black transition-colors cursor-pointer group"
    >
      <td className="py-3.5 px-4 font-mono font-bold text-white max-w-xs truncate">
        <span className="flex items-center space-x-1.5">
          <Globe className="w-3.5 h-3.5 text-[#52525b] shrink-0" />
          <span>{scan.url}</span>
        </span>
      </td>
      <td className="py-3.5 px-4">{statusBadge}</td>
      <td className="py-3.5 px-4 font-mono font-black text-sm">
        {scan.score ? (
          <span className={scoreColor}>{scan.score}</span>
        ) : (
          <span className="text-[#52525b] font-mono text-xs font-normal">Pending</span>
        )}
      </td>
      <td className="py-3.5 px-4">{severityBadge}</td>
      <td className="py-3.5 px-4 text-right font-mono text-[11px] text-[#52525b] group-hover:text-[#22c55e] transition-colors">
        <div className="flex items-center justify-end space-x-1.5">
          <span>{new Date(scan.createdAt).toLocaleDateString()}</span>
          <ExternalLink className="w-3 h-3 text-[#27272a] group-hover:text-[#22c55e] transition-colors shrink-0" />
        </div>
      </td>
    </tr>
  );
}
