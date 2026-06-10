import React from 'react';
import { Globe } from 'lucide-react';
import { Scan } from '../../types.js';
import ScanRow from './ScanRow.js';

interface ScansTabProps {
  scans: Scan[];
  onViewReport: (scanId: string) => void;
  // Filter state is lifted to Dashboard so it survives tab switches.
  searchQuery: string;
  setSearchQuery: (value: string) => void;
  filterStatus: string;
  setFilterStatus: (value: string) => void;
  filterSeverity: string;
  setFilterSeverity: (value: string) => void;
}

/** Scan history table with URL search and status/severity filters. */
export default function ScansTab({
  scans,
  onViewReport,
  searchQuery,
  setSearchQuery,
  filterStatus,
  setFilterStatus,
  filterSeverity,
  setFilterSeverity,
}: ScansTabProps) {
  const filteredScans = scans.filter((scan) => {
    // 1. URL search
    if (searchQuery.trim() && !scan.url.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    // 2. Status filter
    if (filterStatus !== 'all') {
      if (filterStatus === 'complete' && scan.status !== 'complete') return false;
      if (filterStatus === 'failed' && scan.status !== 'failed') return false;
      if (filterStatus === 'active' && ['complete', 'failed'].includes(scan.status)) return false;
    }
    // 3. Severity filter
    if (filterSeverity !== 'all') {
      if (scan.status !== 'complete' || scan.severity !== filterSeverity) return false;
    }
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Filter controls */}
      <div className="flex flex-col md:flex-row gap-4 items-center justify-between pb-4 border-b border-[#27272a]/20">
        <div className="w-full md:max-w-xs bg-black border border-[#27272a] rounded px-3 py-1.5 flex items-center focus-within:border-[#22c55e] transition-colors">
          <Globe className="w-4 h-4 text-[#52525b] mr-2 shrink-0" />
          <input
            type="text"
            placeholder="Search target URL..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-transparent text-white text-xs font-mono focus:outline-none w-full placeholder-[#52525b]"
          />
        </div>

        <div className="flex gap-3 w-full md:w-auto flex-wrap">
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-black border border-[#27272a] rounded px-3 py-1.5 text-xs font-mono text-[#a1a1aa] focus:outline-none focus:border-[#22c55e] cursor-pointer"
          >
            <option value="all">All States</option>
            <option value="complete">Complete Only</option>
            <option value="failed">Failed Only</option>
            <option value="active">Active (Queued/Scanning/Analyzing)</option>
          </select>

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-black border border-[#27272a] rounded px-3 py-1.5 text-xs font-mono text-[#a1a1aa] focus:outline-none focus:border-[#22c55e] cursor-pointer"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="medium">Medium Only</option>
            <option value="low">Low Only</option>
            <option value="info">Info Only</option>
          </select>
        </div>
      </div>

      {filteredScans.length === 0 ? (
        <div className="text-center py-12 bg-black rounded border border-dashed border-[#27272a]">
          <span className="text-xs text-[#52525b] font-mono block mb-2">No audits matched your search criteria</span>
          <p className="text-[11px] text-[#52525b] max-w-sm mx-auto font-mono">Try adjusting your filters or URL search queries to view older audits.</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#27272a] text-[#52525b] font-mono text-[10px] uppercase tracking-wider pb-3">
                <th className="py-3 px-4">Audited Target URL</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Postures Score</th>
                <th className="py-3 px-4">Vulnerabilities</th>
                <th className="py-3 px-4 text-right">Execution Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#27272a]/20 text-xs font-mono">
              {filteredScans.map((scan) => (
                <ScanRow key={scan.id} scan={scan} onViewReport={onViewReport} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
