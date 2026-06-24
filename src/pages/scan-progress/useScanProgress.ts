import { useEffect, useState, useRef } from 'react';
import { Scan } from '../../types.js';
import { apiFetch } from '../../lib/api.js';

export function useScanProgress(scanId: string, onScanFinished: (scanId: string) => void) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [progressPercent, setProgressPercent] = useState(10);
  const logsEndRef = useRef<HTMLDivElement>(null);

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

  return { scan, logs, progressPercent, logsEndRef };
}
