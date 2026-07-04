import React, { useEffect, useState, useRef } from 'react';
import { RefreshCw, Cpu } from 'lucide-react';
import { Scan } from '../types.js';
import { microEventsConfig } from './scanProgress/microEvents.js';
import { buildStageLogs } from './scanProgress/stageLogs.js';
import ProgressPipeline from './scanProgress/ProgressPipeline.js';
import ScannerConsole from './scanProgress/ScannerConsole.js';
import TelemetryFeed from './scanProgress/TelemetryFeed.js';

interface ScanProgressProps {
  scanId: string;
  onScanFinished: (scanId: string) => void;
  onCancel: () => void;
}

export default function ScanProgress({ scanId, onScanFinished, onCancel }: ScanProgressProps) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [pollCount, setPollCount] = useState(0);
  const [progressPercent, setProgressPercent] = useState(10);
  const logsEndRef = useRef<HTMLDivElement>(null);

  const [activeEvents, setActiveEvents] = useState<{ time: string; msg: string }[]>([]);

  // Ticker for micro-events real-time feed
  useEffect(() => {
    const t = new Date().toLocaleTimeString();
    const currentStatus = scan?.status || 'initial';
    const firstEvent = microEventsConfig[currentStatus]?.[0] || 'Provisioning security pipeline daemon...';
    setActiveEvents([{ time: t, msg: firstEvent }]);

    let idx = 1;
    const interval = setInterval(() => {
      const statusGroup = scan?.status || 'initial';
      const list = microEventsConfig[statusGroup] || [];
      if (list.length > 0) {
        const tNow = new Date().toLocaleTimeString();
        const eventText = list[idx % list.length];
        setActiveEvents(prev => [
          { time: tNow, msg: eventText },
          ...prev.slice(0, 4)
        ]);
        idx++;
      }
    }, 1800);

    return () => clearInterval(interval);
  }, [scan?.status]);

  // Poll for scan status
  useEffect(() => {
    let active = true;
    let pollTimer: NodeJS.Timeout;

    const fetchStatus = async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}`);
        const data = await res.json();

        if (!active) return;

        if (data.scan) {
          const currentScan = data.scan as Scan;
          setScan(currentScan);

          // Complete route
          if (currentScan.status === 'complete') {
            setProgressPercent(100);
            addLog(`[SYSTEM] Executive scan complete. Security score compiled: ${currentScan.score || 'N/A'}/100.`);
            addLog(`[SYSTEM] Report ready for review.`);

            // Auto-trigger completion after brief delay
            setTimeout(() => {
              if (active) onScanFinished(scanId);
            }, 1000);
            return;
          }

          if (currentScan.status === 'failed') {
            setProgressPercent(100);
            addLog(`[FATAL] Scanner terminated unexpectedly: ${currentScan.error || 'Connection Timeout'}`);
            return;
          }

          // Advance progression bar corresponding to state
          if (currentScan.status === 'queued') {
            setProgressPercent(20);
          } else if (currentScan.status === 'scanning') {
            setProgressPercent(50);
          } else if (currentScan.status === 'analyzing') {
            setProgressPercent(80);
          }
        }
      } catch (err) {
        console.error('Error polling scan status:', err);
      }

      setPollCount(p => p + 1);
    };

    fetchStatus();
    pollTimer = setInterval(fetchStatus, 3000);

    return () => {
      active = false;
      clearInterval(pollTimer);
    };
  }, [scanId, pollCount]);

  // Handle UI scrolling logs to visualize scanning mechanics relative to progression
  useEffect(() => {
    if (!scan) return;
    setLogs(buildStageLogs(scan));
  }, [scan?.status]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const addLog = (msg: string) => {
    setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

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
        <ProgressPipeline scan={scan} progressPercent={progressPercent} />

        {/* Terminal logs component */}
        <ScannerConsole logs={logs} endRef={logsEndRef} />

        {/* Actions panel */}
        <div
          id="cancel-scan-btn-container"
          className="border-t border-[#27272a] pt-5 space-y-4 font-mono text-xs text-[#52525b]"
        >
          {/* Micro-Event Telemetry Activity Feed */}
          <TelemetryFeed activeEvents={activeEvents} />

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
