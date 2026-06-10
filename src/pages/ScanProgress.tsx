import React, { useEffect, useRef } from 'react';
import { Terminal, RefreshCw, Cpu } from 'lucide-react';
import { useScanPolling } from '../hooks/useScanPolling.js';

interface ScanProgressProps {
  scanId: string;
  onScanFinished: (scanId: string) => void;
  onCancel: () => void;
}

export default function ScanProgress({ scanId, onScanFinished, onCancel }: ScanProgressProps) {
  const { scan, logs, progressPercent, activeEvents } = useScanPolling(scanId, onScanFinished);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-20 px-6 flex items-center justify-center">
      <div className="max-w-2xl w-full space-y-8 bg-[#0c0c0e] border border-[#27272a] p-8 rounded shadow-2xl relative overflow-hidden">

        {/* Background visual highlight */}
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

        {/* Dynamic progression loader */}
        <div className="space-y-3">
          <div className="flex justify-between items-baseline font-mono text-xs">
            <span className="text-[#52525b]">Scan Pipeline Progression</span>
            <span className="text-[#22c55e] font-bold">{progressPercent}%</span>
          </div>
          <div className="w-full bg-black h-2.5 rounded overflow-hidden border border-[#27272a] relative after:absolute after:inset-0 after:bg-gradient-to-r after:from-transparent after:via-[#22c55e]/15 after:to-transparent after:animate-shimmer after:pointer-events-none">
            <div
              className="bg-gradient-to-r from-[#22c55e] to-emerald-400 h-full transition-all duration-700 rounded-full relative"
              style={{ width: `${progressPercent}%` }}
            >
              {/* Pulsing shadow tip emitter */}
              <span className="absolute right-0 top-0 bottom-0 w-3 bg-white/45 blur-[1.5px] rounded-full animate-pulse" />
            </div>
          </div>

          {/* Secondary Non-Animated Buffer Status Bar */}
          <div className="pt-1.5 pb-2.5 space-y-1 border-t border-[#27272a]/20 mt-1">
            <div className="flex justify-between items-center text-[10px] font-mono text-[#52525b] uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-[#22c55e] inline-block animate-pulse" />
                <span>Buffer Sub-Task: <span className="text-zinc-350 normal-case font-bold">{
                  scan?.status === 'queued' ? 'Pre-execution checklist & Docker orchestration' :
                  scan?.status === 'scanning' ? 'DAST probing / Dynamic multi-stage payload injection' :
                  scan?.status === 'analyzing' ? 'ASPM analyzing & DongTai IAST trace correlation' :
                  scan?.status === 'complete' ? 'Report compiled / Synchronizing database findings' :
                  'Initializing target pipeline...'
                }</span></span>
              </span>
              <span className="text-zinc-400 font-bold">{
                scan?.status === 'queued' ? '40%' :
                scan?.status === 'scanning' ? '70%' :
                scan?.status === 'analyzing' ? '92%' :
                scan?.status === 'complete' ? '100%' :
                '0%'
              }</span>
            </div>
            <div className="w-full bg-black h-1 rounded overflow-hidden border border-[#27272a]/60">
              <div
                className="bg-[#22c55e]/60 h-full transition-all duration-500 rounded-full"
                style={{
                  width: scan?.status === 'queued' ? '40%' :
                         scan?.status === 'scanning' ? '70%' :
                         scan?.status === 'analyzing' ? '92%' :
                         scan?.status === 'complete' ? '100%' :
                         '0%'
                }}
              />
            </div>
          </div>

          <div className="flex justify-between items-center text-[10px] font-mono text-[#52525b] uppercase mt-1">
            <span className={scan?.status === 'queued' ? 'text-[#22c55e] font-bold' : ''}>QUEUED</span>
            <span className="text-[#27272a]">→</span>
            <span className={scan?.status === 'scanning' ? 'text-purple-400 font-bold' : ''}>SCANNING</span>
            <span className="text-[#27272a]">→</span>
            <span className={scan?.status === 'analyzing' ? 'text-amber-400 font-bold' : ''}>ANALYZING AI</span>
            <span className="text-[#27272a]">→</span>
            <span className={scan?.status === 'complete' ? 'text-[#22c55e] font-bold' : ''}>COMPLETE</span>
          </div>
        </div>

        {/* Terminal logs component */}
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
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* Actions panel */}
        <div
          id="cancel-scan-btn-container"
          className="border-t border-[#27272a] pt-5 space-y-4 font-mono text-xs text-[#52525b]"
        >
          {/* Micro-Event Telemetry Activity Feed */}
          <div className="space-y-2">
            <div className="flex items-center justify-between border-b border-[#27272a]/20 pb-1.5">
              <span className="text-[10px] font-mono text-[#22c55e] uppercase tracking-widest flex items-center gap-1.5 font-bold">
                <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] inline-block animate-ping" />
                <span>Live Pipeline Microcheck Activity</span>
              </span>
              <span className="text-[9px] text-[#52525b] font-bold">REAL-TIME FEED</span>
            </div>

            <div className="bg-black/80 border border-[#27272a]/60 rounded p-3 h-28 overflow-y-auto space-y-1.5 scrollbar-thin select-all">
              {activeEvents.length === 0 ? (
                <div className="text-[#52525b] text-[10px] animate-pulse">Establishing pipeline trace stream...</div>
              ) : (
                activeEvents.map((ev, idx) => (
                  <div key={idx} className="flex gap-2 text-[10px] items-start transition-opacity duration-300">
                    <span className="text-zinc-500 shrink-0 font-bold">[{ev.time}]</span>
                    <span className="text-[#22c55e] shrink-0 font-bold select-none">●</span>
                    <span className="text-zinc-300 leading-tight">{ev.msg}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-1.5">
              <Cpu className="w-4 h-4 text-[#22c55e] shrink-0" />
              <span>Scanning using Seclayer Daemon v2</span>
            </div>
            {scan?.status !== 'complete' && (
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

      </div>
    </div>
  );
}
