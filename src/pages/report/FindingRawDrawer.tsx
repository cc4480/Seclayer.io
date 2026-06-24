import { useState } from 'react';
import { Terminal, ChevronDown, ChevronUp, Copy } from 'lucide-react';
import { Finding } from '../../types.js';

interface FindingRawDrawerProps {
  finding: Finding;
  onCopyCode: (findingId: string, fixText: string) => void;
}

/**
 * Collapsible "Raw HTTP Probes & Response Dump" drawer for a single finding.
 * Only rendered when the finding has a rawRequest or rawResponse.
 */
export default function FindingRawDrawer({ finding, onCopyCode }: FindingRawDrawerProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="mt-3">
      <button
        onClick={() => setExpanded(p => !p)}
        className="w-full flex items-center justify-between p-3 rounded bg-zinc-950/40 hover:bg-zinc-900 border border-zinc-800/80 transition-colors cursor-pointer group"
      >
        <span className="flex items-center space-x-2 text-[10px] font-mono text-zinc-400 group-hover:text-amber-400 transition-colors uppercase tracking-wider font-bold">
          <Terminal className="w-3.5 h-3.5 shrink-0" />
          <span>Raw HTTP Probes & Response Dump</span>
        </span>
        {expanded ? <ChevronUp className="w-4 h-4 text-zinc-500" /> : <ChevronDown className="w-4 h-4 text-zinc-500" />}
      </button>

      {expanded && (
        <div className="mt-2 space-y-2 animate-fade-in">
          {finding.endpoint && (
            <div className="p-3 bg-black border border-zinc-800 rounded font-mono text-[10px] text-zinc-300 overflow-x-auto">
              <span className="text-zinc-500 select-none block mb-1">Target Endpoint:</span>
              {finding.endpoint}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {finding.rawRequest && (
              <div className="p-3 bg-black border border-zinc-800 rounded relative overflow-hidden group">
                <div className="absolute top-0 left-0 w-full bg-zinc-900/80 p-1.5 border-b border-zinc-800 text-[9px] uppercase tracking-wider font-mono text-amber-500/80 flex items-center justify-between">
                  <span>Raw Request</span>
                  <button onClick={() => onCopyCode(`req-${finding.id}`, finding.rawRequest!)} className="text-zinc-500 hover:text-white cursor-pointer"><Copy className="w-3 h-3"/></button>
                </div>
                <div className="pt-6 overflow-x-auto max-h-64 scrollbar-thin">
                  <code className="text-[10px] font-mono whitespace-pre text-zinc-400 break-all">{finding.rawRequest}</code>
                </div>
              </div>
            )}
            {finding.rawResponse && (
              <div className="p-3 bg-black border border-zinc-800 rounded relative overflow-hidden group">
                <div className="absolute top-0 left-0 w-full bg-zinc-900/80 p-1.5 border-b border-zinc-800 text-[9px] uppercase tracking-wider font-mono text-red-400/80 flex items-center justify-between">
                  <span>Raw Response</span>
                  <button onClick={() => onCopyCode(`res-${finding.id}`, finding.rawResponse!)} className="text-zinc-500 hover:text-white cursor-pointer"><Copy className="w-3 h-3"/></button>
                </div>
                <div className="pt-6 overflow-x-auto max-h-64 scrollbar-thin">
                  <code className="text-[10px] font-mono whitespace-pre text-zinc-400 break-all">{finding.rawResponse}</code>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
