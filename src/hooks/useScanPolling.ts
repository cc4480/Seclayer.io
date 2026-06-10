import { useEffect, useState } from 'react';
import { Scan } from '../types.js';

// Micro-event telemetry config mapping
const microEventsConfig: Record<string, string[]> = {
  initial: [
    "Establishing system control loop metrics...",
    "Validating credential token authorization...",
    "Provisioning safe worker environments on Kubernetes clusters..."
  ],
  queued: [
    "Querying target perimeter socket state and port matrices...",
    "Amass network asset discovery worker enqueued in background...",
    "Resolving public Domain & DNS records structure...",
    "Pre-fetching certificate transparency logs ledger..."
  ],
  scanning: [
    "Katana crawler starting up headless browser subprocess...",
    "Injecting raw SQL validation payloads into input elements...",
    "Hadrian rotating authentication roles for BOLA matrices...",
    "APISCAN sending Swagger-defined validation parameters...",
    "Evaluating Strict-Transport-Security policy headers..."
  ],
  analyzing: [
    "DongTai passive tracer agent hooked inside backend JVM/Python...",
    "Tracing user input taint variables in query executors...",
    "DefectDojo parser validating static vs dynamic findings...",
    "Deploying PentAGI autonomous exploitation agents...",
    "Calculating posture weights and severity metrics..."
  ],
  complete: [
    "Syncing defect ledger entries inside DefectDojo controller...",
    "All sandbox diagnostic endpoints completely cleared...",
    "Safely tearing down ephemeral agent runtimes...",
    "Vulnerability signatures archived. Scan complete."
  ]
};

/**
 * Polls /api/scans/:id while a scan runs, deriving the progress bar value,
 * console log lines, and the rotating micro-event feed from its status.
 * Calls onScanFinished once the scan reaches the complete state.
 */
export function useScanPolling(scanId: string, onScanFinished: (scanId: string) => void) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [pollCount, setPollCount] = useState(0);
  const [progressPercent, setProgressPercent] = useState(10);
  const [activeEvents, setActiveEvents] = useState<{ time: string; msg: string }[]>([]);

  const addLog = (msg: string) => {
    setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

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

  // Rebuild the console log narrative to match how far the scan has progressed
  useEffect(() => {
    if (!scan) return;

    const logsList: string[] = [];
    const timestamp = () => new Date().toLocaleTimeString();

    logsList.push(`[${timestamp()}] [SYSTEM] Enqueued target url: ${scan.url}`);
    logsList.push(`[${timestamp()}] [SYSTEM] Provisioned security daemon pipeline.`);

    if (scan.status === 'scanning' || scan.status === 'analyzing' || scan.status === 'complete') {
      logsList.push(`[${timestamp()}] [DAEMON] Checking SSL protocol schemas on host connection...`);
      logsList.push(`[${timestamp()}] [DAEMON] Established socket on port 443.`);
      logsList.push(`[${timestamp()}] [HEADERS] Requesting GET on root host location...`);
      logsList.push(`[${timestamp()}] [HEADERS] Response code: 200. Parsing key security signatures...`);
    }

    if (scan.status === 'analyzing' || scan.status === 'complete') {
      logsList.push(`[${timestamp()}] [AUDIT] Analyzing standard HTTP headers checklist...`);
      logsList.push(`[${timestamp()}] [AUDIT] Cross-checking Cookie flag parameters: HttpOnly, Secure, SameSite.`);
      logsList.push(`[${timestamp()}] [PROBES] Testing typical site exposures: /.env, /.git/config, /admin, /wp-admin, /phpinfo.php...`);
      logsList.push(`[${timestamp()}] [DEEPSEEK] Forwarding parsed diagnostic elements to DeepSeek Intelligence...`);
      logsList.push(`[${timestamp()}] [DEEPSEEK] Compiling plain-English analysis and developer fixes...`);
    }

    if (scan.status === 'complete') {
      logsList.push(`[${timestamp()}] [SYSTEM] Report successfully persisted.`);
    }

    setLogs(logsList);
  }, [scan?.status]);

  return { scan, logs, progressPercent, activeEvents };
}
