import React from 'react';
import { Shield } from 'lucide-react';
import { subTabs } from './orchestrator/types.js';
import { useOrchestratorState } from './orchestrator/useOrchestratorState.js';
import AspmPanel from './orchestrator/AspmPanel.js';
import EasmPanel from './orchestrator/EasmPanel.js';
import ApiScanPanel from './orchestrator/ApiScanPanel.js';
import IastPanel from './orchestrator/IastPanel.js';
import PentagiPanel from './orchestrator/PentagiPanel.js';

export default function OrchestratorTab() {
  const {
    orchSubTab, setOrchSubTab,
    aspmUrl, setAspmUrl, aspmRunning, aspmOutput, aspmError, runAspmCorrelation,
    easmDomain, setEasmDomain, easmRunning, easmData, easmError, runEasmRecon,
    apiScanUrl, setApiScanUrl, apiScanRunning, apiScanResult, apiScanError, runHadrianScan,
    iastRunning, iastResult, iastError, runIastTrace,
    pentagiUrl, setPentagiUrl, pentagiRunning, pentagiLogs, pentagiError, runPentagiExploitation,
  } = useOrchestratorState();

  return (
    <div className="space-y-6 text-xs font-mono">
      <div className="bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5">
        <Shield className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5 animate-pulse" />
        <div className="space-y-1">
          <h4 className="text-white text-xs uppercase font-bold">Autonomous PentAGI & Microservices</h4>
          <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
            Trigger our autonomous AI ethical hacker agents, or utilize standalone security engines to de-duplicate, verify, and trace live exploitable postures.
          </p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 border-b border-[#27272a]/40 pb-3">
        {subTabs.map(sub => (
          <button
            key={sub.id}
            onClick={() => setOrchSubTab(sub.id)}
            className={`flex-1 min-w-[150px] p-3 rounded border text-left cursor-pointer transition-all ${
              orchSubTab === sub.id
                ? 'bg-[#22c55e]/5 border-[#22c55e] text-white'
                : 'bg-black border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa]'
            }`}
          >
            <span className="text-[10px] uppercase font-bold text-[#22c55e] block mb-0.5">{sub.label}</span>
            <span className="text-[9px] text-[#52525b] block">{sub.subtitle}</span>
          </button>
        ))}
      </div>

      {orchSubTab === 'aspm' && (
        <AspmPanel
          aspmUrl={aspmUrl}
          setAspmUrl={setAspmUrl}
          aspmRunning={aspmRunning}
          aspmOutput={aspmOutput}
          aspmError={aspmError}
          runAspmCorrelation={runAspmCorrelation}
        />
      )}

      {orchSubTab === 'easm' && (
        <EasmPanel
          easmDomain={easmDomain}
          setEasmDomain={setEasmDomain}
          easmRunning={easmRunning}
          easmData={easmData}
          easmError={easmError}
          runEasmRecon={runEasmRecon}
        />
      )}

      {orchSubTab === 'apiscan' && (
        <ApiScanPanel
          apiScanUrl={apiScanUrl}
          setApiScanUrl={setApiScanUrl}
          apiScanRunning={apiScanRunning}
          apiScanResult={apiScanResult}
          apiScanError={apiScanError}
          runHadrianScan={runHadrianScan}
        />
      )}

      {orchSubTab === 'iast' && (
        <IastPanel
          iastRunning={iastRunning}
          iastResult={iastResult}
          iastError={iastError}
          runIastTrace={runIastTrace}
        />
      )}

      {orchSubTab === 'pentagi' && (
        <PentagiPanel
          pentagiUrl={pentagiUrl}
          setPentagiUrl={setPentagiUrl}
          pentagiRunning={pentagiRunning}
          pentagiLogs={pentagiLogs}
          pentagiError={pentagiError}
          runPentagiExploitation={runPentagiExploitation}
        />
      )}
    </div>
  );
}
