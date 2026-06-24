import { useState } from 'react';
import { apiFetch } from '../../../lib/api.js';
import { SubTab } from './types.js';

export function useOrchestratorState() {
  const [orchSubTab, setOrchSubTab] = useState<SubTab>('pentagi');

  // ASPM
  const [aspmUrl, setAspmUrl] = useState('');
  const [aspmRunning, setAspmRunning] = useState(false);
  const [aspmOutput, setAspmOutput] = useState<any | null>(null);
  const [aspmError, setAspmError] = useState<string | null>(null);

  // EASM
  const [easmDomain, setEasmDomain] = useState('');
  const [easmRunning, setEasmRunning] = useState(false);
  const [easmData, setEasmData] = useState<any | null>(null);
  const [easmError, setEasmError] = useState<string | null>(null);

  // API Scan / Hadrian
  const [apiScanUrl, setApiScanUrl] = useState('');
  const [apiScanRunning, setApiScanRunning] = useState(false);
  const [apiScanResult, setApiScanResult] = useState<any | null>(null);
  const [apiScanError, setApiScanError] = useState<string | null>(null);

  // IAST
  const [iastRunning, setIastRunning] = useState(false);
  const [iastResult, setIastResult] = useState<any | null>(null);
  const [iastError, setIastError] = useState<string | null>(null);

  // PentAGI
  const [pentagiUrl, setPentagiUrl] = useState('');
  const [pentagiRunning, setPentagiRunning] = useState(false);
  const [pentagiLogs, setPentagiLogs] = useState<any[]>([]);
  const [pentagiError, setPentagiError] = useState<string | null>(null);

  const runAspmCorrelation = async () => {
    setAspmRunning(true);
    setAspmOutput(null);
    setAspmError(null);
    try {
      const res = await apiFetch('/api/enterprise/aspm/correlate', {
        method: 'POST',
        body: JSON.stringify({ url: aspmUrl || undefined }),
      });
      const data = await res.json();
      if (res.ok) setAspmOutput(data);
      else setAspmError(data.error || 'Correlation failed.');
    } catch (err: any) {
      setAspmError(err.message || 'Network error.');
    } finally {
      setAspmRunning(false);
    }
  };

  const runEasmRecon = async () => {
    setEasmRunning(true);
    setEasmData(null);
    setEasmError(null);
    try {
      const res = await apiFetch('/api/enterprise/easm/recon', {
        method: 'POST',
        body: JSON.stringify({ domain: easmDomain }),
      });
      const data = await res.json();
      if (res.ok) setEasmData(data);
      else setEasmError(data.error || 'EASM recon failed.');
    } catch (err: any) {
      setEasmError(err.message || 'Network error.');
    } finally {
      setEasmRunning(false);
    }
  };

  const runHadrianScan = async () => {
    setApiScanRunning(true);
    setApiScanResult(null);
    setApiScanError(null);
    try {
      const res = await apiFetch('/api/enterprise/api-scan/hadrian', {
        method: 'POST',
        body: JSON.stringify({ url: apiScanUrl }),
      });
      const data = await res.json();
      if (res.ok) setApiScanResult(data);
      else setApiScanError(data.error || 'API scan failed.');
    } catch (err: any) {
      setApiScanError(err.message || 'Network error.');
    } finally {
      setApiScanRunning(false);
    }
  };

  const runIastTrace = async () => {
    setIastRunning(true);
    setIastResult(null);
    setIastError(null);
    try {
      const res = await apiFetch('/api/enterprise/iast/trace', { method: 'POST', body: JSON.stringify({}) });
      const data = await res.json();
      if (res.ok || res.status === 501) setIastResult(data);
      else setIastError(data.error || 'IAST trace failed.');
    } catch (err: any) {
      setIastError(err.message || 'Network error.');
    } finally {
      setIastRunning(false);
    }
  };

  const runPentagiExploitation = async () => {
    if (!pentagiUrl.trim()) {
      setPentagiError('Enter a target URL before running PentAGI.');
      return;
    }
    setPentagiRunning(true);
    setPentagiLogs([]);
    setPentagiError(null);
    try {
      const res = await apiFetch(`/api/enterprise/pentagi/logs?url=${encodeURIComponent(pentagiUrl.trim())}`);
      if (!res.ok || !res.body) {
        const data = await res.json().catch(() => ({}));
        setPentagiError(data.error || 'PentAGI run failed.');
        return;
      }

      // Read the live newline-delimited JSON stream — each agent event is
      // rendered the moment the backend produces it during the real run.
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let nl: number;
        while ((nl = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, nl).trim();
          buffer = buffer.slice(nl + 1);
          if (!line) continue;
          let event: any;
          try { event = JSON.parse(line); } catch { continue; }
          if (event.type === 'log' && event.entry) {
            setPentagiLogs(prev => [...prev, event.entry]);
          } else if (event.type === 'error') {
            setPentagiError(event.error || 'PentAGI run failed.');
          }
        }
      }
    } catch (err: any) {
      setPentagiError(err.message || 'Network error.');
    } finally {
      setPentagiRunning(false);
    }
  };

  return {
    orchSubTab, setOrchSubTab,
    aspmUrl, setAspmUrl, aspmRunning, aspmOutput, aspmError, runAspmCorrelation,
    easmDomain, setEasmDomain, easmRunning, easmData, easmError, runEasmRecon,
    apiScanUrl, setApiScanUrl, apiScanRunning, apiScanResult, apiScanError, runHadrianScan,
    iastRunning, iastResult, iastError, runIastTrace,
    pentagiUrl, setPentagiUrl, pentagiRunning, pentagiLogs, pentagiError, runPentagiExploitation,
  };
}
