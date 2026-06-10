import { useState } from 'react';
import { useApiAction, Notify } from './useApiAction.js';

/**
 * State for the five enterprise orchestrator sub-panels. Lives at the
 * Dashboard level (not inside the tab components) so inputs and results
 * survive switching between tabs, exactly as before the split.
 */
export function useOrchestrator(notify: Notify, scanUrl: string) {
  // 1. ASPM state
  const [aspmUrl, setAspmUrl] = useState('staging.api.vulnerable-shop.io');
  const aspm = useApiAction(notify);
  const runAspmCorrelation = () =>
    aspm.run('/api/enterprise/aspm/correlate', { url: aspmUrl }, 'ASPM correlation failed.');

  // 2. EASM state
  const [easmDomain, setEasmDomain] = useState('example-enterprise.com');
  const easm = useApiAction(notify);
  const runEasmRecon = () =>
    easm.run('/api/enterprise/easm/recon', { domain: easmDomain }, 'EASM recon failed.');

  // 3. Hadrian/APISCAN API Security state
  const [apiScanUrl, setApiScanUrl] = useState('staging.api.vulnerable-shop.io');
  const [apiSpecTitle, setApiSpecTitle] = useState('Swagger User Management Core');
  const hadrian = useApiAction(notify);
  const runHadrianScan = () =>
    hadrian.run('/api/enterprise/api-scan/hadrian', { url: apiScanUrl, schemaTitle: apiSpecTitle }, 'API security probe failed.');

  // 4. IAST state
  const [iastUrl, setIastUrl] = useState('staging.api.vulnerable-shop.io');
  const [iastPayload, setIastPayload] = useState("1' UNION SELECT credit_card_number FROM customers");
  const iast = useApiAction(notify);
  const runIastTrace = () =>
    iast.run('/api/enterprise/iast/trace', { url: iastUrl, inputPayload: iastPayload }, 'IAST trace failed.');

  // 5. PentAGI Agentic Pentest state
  const [pentagiRunning, setPentagiRunning] = useState(false);
  const [pentagiLogs, setPentagiLogs] = useState<any[]>([]);

  const runPentagiExploitation = async () => {
    setPentagiRunning(true);
    setPentagiLogs([]);
    try {
      const targetUrl = scanUrl || 'staging.api.vulnerable.org';
      const res = await fetch(`/api/enterprise/pentagi/logs?url=${encodeURIComponent(targetUrl)}`);
      if (res.ok) {
        const data = await res.json();
        // Stagger logs typewriter loading effect
        let idx = 0;
        const interval = setInterval(() => {
          if (idx < data.logs.length) {
            setPentagiLogs(prev => [...prev, data.logs[idx]]);
            idx++;
          } else {
            clearInterval(interval);
            setPentagiRunning(false);
          }
        }, 750);
      }
    } catch (err) {
      console.error(err);
      setPentagiRunning(false);
    }
  };

  return {
    aspmUrl, setAspmUrl, aspmRunning: aspm.running, aspmOutput: aspm.result, runAspmCorrelation,
    easmDomain, setEasmDomain, easmRunning: easm.running, easmData: easm.result, runEasmRecon,
    apiScanUrl, setApiScanUrl, apiSpecTitle, setApiSpecTitle,
    apiScanRunning: hadrian.running, apiMatrix: hadrian.result, runHadrianScan,
    iastUrl, setIastUrl, iastPayload, setIastPayload,
    iastRunning: iast.running, iastResult: iast.result, runIastTrace,
    pentagiRunning, pentagiLogs, runPentagiExploitation,
  };
}

export type OrchestratorState = ReturnType<typeof useOrchestrator>;
