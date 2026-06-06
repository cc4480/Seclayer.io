import React, { useEffect, useState, useRef } from 'react';
import { Terminal, RefreshCw, Cpu } from 'lucide-react';
import { Scan } from '../types.js';
import { apiFetch } from '../lib/api.js';

interface ScanProgressProps {
  scanId: string;
  onScanFinished: (scanId: string) => void;
  onCancel: () => void;
}

export default function ScanProgress({ scanId, onScanFinished, onCancel }: ScanProgressProps) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [progressPercent, setProgressPercent] = useState(10);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Micro-event activity feed
  const microEventsConfig: Record<string, string[]> = {
    initial: [
      'Establishing system control loop metrics...',
      'Validating credential token authorization...',
      'Provisioning safe worker environments...',
    ],
    queued: [
      'Querying target perimeter socket state...',
      'Resolving public Domain & DNS records structure...',
      'Pre-fetching certificate transparency logs ledger...',
    ],
    scanning: [
      'Checking SSL protocol schemas on host connection...',
      'Evaluating Strict-Transport-Security policy headers...',
      'Probing common sensitive paths for exposures...',
    ],
    analyzing: [
      'Forwarding diagnostics to DeepSeek AI...',
      'Calculating posture weights and severity metrics...',
      'Compiling developer-readable remediation guidance...',
    ],
    complete: [
      'All diagnostic endpoints cleared...',
      'Vulnerability signatures archived.',
      'Report compiled successfully.',
    ],
  };

  const [activeEvents, setActiveEvents] = useState<{ time: string; msg: string }[]>([]);

  useEffect(() => {
    const t = new Date().toLocaleTimeString();
    const currentStatus = scan?.status || 'initial';
    const firstEvent = microEventsConfig[currentStatus]?.[0] || 'Provisioning security pipeline...';
    setActiveEvents([{ time: t, msg: firstEvent }]);

    let idx = 1;
    const interval = setInterval(() => {
      const statusGroup = scan?.status || 'initial';
      const list = microEventsConfig[statusGroup] || [];
      if (list.length > 0) {
        const tNow = new Date().toLocaleTimeString();
        setActiveEvents(prev => [{ time: tNow, msg: list[idx % list.length] }, ...prev.slice(0, 4)]);
        idx++;
      }
    }, 1800);

    return () => clearInterval(interval);
  }, [scan?.status]);

  // Poll scan status
  useEffect(() => {
    let active = true;
    let pollTimer: NodeJS.Timeout;

    const fetchStatus = async () => {
      try {
        const res = await apiFetch(`/api/scans/${scanId}`);
        const data = await res.json();
        if (!active) return;

        if (data.scan) {
          const currentScan = data.scan as Scan;
          setScan(currentScan);

          if (currentScan.status === 'complete') {
            setProgressPercent(100);
            setTimeout(() => { if (active) onScanFinished(scanId); }, 1000);
            return;
          }
          if (currentScan.status === 'failed') {
            setProgressPercent(100);
            return;
          }

          setProgressPercent(
            currentScan.status === 'queued' ? 20 :
            currentScan.status === 'scanning' ? 50 :
            currentScan.status === 'analyzing' ? 80 : 10
          );
        }
      } catch (err) {
        console.error('Error polling scan status:', err);
      }
    };

    fetchStatus();
    pollTimer = setInterval(fetchStatus, 3000);
    return () => { active = false; clearInterval(pollTimer); };
  }, [scanId]);

  // Poll real logs from backend
  useEffect(() => {
    let active = true;
    let logTimer: NodeJS.Timeout;

    const fetchLogs = async () => {
      try {
        const res = await apiFetch(`/api/scans/${scanId}/logs`);
        if (res.ok) {
          const data = await res.json();
          if (active && data.logs?.length > 0) {
            setLogs(data.logs);
          }
        }
      } catch (err) {
        console.error('Error polling scan logs:', err);
      }
    };

    fetchLogs();
    logTimer = setInterval(fetchLogs, 2000);
    return () => { active = false; clearInterval(logTimer); };
  }, [scanId]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

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

        {/* Progression bar */}
        <div className="space-y-3">
          <div className="flex justify-between items-baseline font-mono text-xs">
            <span className="text-[#52525b]">Scan Pipeline Progression</span>
            <span className="text-[#22c55e] font-bold">{progressPercent}%</span>
          </div>
          <div className="w-full bg-black h-2.5 rounded overflow-hidden border border-[#27272a]">
            <div
              className="bg-gradient-to-r from-[#22c55e] to-emerald-400 h-full transition-all duration-700 rounded-full relative"
              style={{ width: `${progressPercent}%` }}
            >
              <span className="absolute right-0 top-0 bottom-0 w-3 bg-white/45 blur-[1.5px] rounded-full animate-pulse" />
            </div>
          </div>

          <div className="pt-1.5 pb-2.5 space-y-1 border-t border-[#27272a]/20 mt-1">
            <div className="flex justify-between items-center text-[10px] font-mono text-[#52525b] uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-[#22c55e] inline-block animate-pulse" />
                <span>Sub-Task: <span className="text-zinc-350 normal-case font-bold">{
                  scan?.status === 'queued' ? 'Pre-execution checklist & infrastructure provisioning' :
                  scan?.status === 'scanning' ? 'DAST probing / dynamic payload injection' :
                  scan?.status === 'analyzing' ? 'AI analysis & severity scoring' :
                  scan?.status === 'complete' ? 'Report compiled / database sync' :
                  'Initializing target pipeline...'
                }</span></span>
              </span>
              <span className="text-zinc-400 font-bold">{
                scan?.status === 'queued' ? '40%' :
                scan?.status === 'scanning' ? '70%' :
                scan?.status === 'analyzing' ? '92%' :
                scan?.status === 'complete' ? '100%' : '0%'
              }</span>
            </div>
            <div className="w-full bg-black h-1 rounded overflow-hidden border border-[#27272a]/60">
              <div
                className="bg-[#22c55e]/60 h-full transition-all duration-500 rounded-full"
                style={{
                  width: scan?.status === 'queued' ? '40%' :
                         scan?.status === 'scanning' ? '70%' :
                         scan?.status === 'analyzing' ? '92%' :
                         scan?.status === 'complete' ? '100%' : '0%',
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

        {/* Terminal logs — real events from backend */}
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

        {/* Actions panel with micro-event activity feed */}
        <div className="border-t border-[#27272a] pt-5 space-y-4 font-mono text-xs text-[#52525b]">
          <div className="space-y-2">
            <div className="flex items-center justify-between border-b border-[#27272a]/20 pb-1.5">
              <span className="text-[10px] font-mono text-[#22c55e] uppercase tracking-widest flex items-center gap-1.5 font-bold">
                <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] inline-block animate-ping" />
                <span>Live Pipeline Activity</span>
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
