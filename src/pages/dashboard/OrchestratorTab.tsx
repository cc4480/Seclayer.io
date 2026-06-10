import React from 'react';
import { Shield } from 'lucide-react';
import { OrchestratorState } from './useOrchestrator.js';
import AspmPanel from './orchestrator/AspmPanel.js';
import EasmPanel from './orchestrator/EasmPanel.js';
import ApiScanPanel from './orchestrator/ApiScanPanel.js';
import IastPanel from './orchestrator/IastPanel.js';
import PentagiPanel from './orchestrator/PentagiPanel.js';

export type OrchSubTab = 'aspm' | 'easm' | 'apiscan' | 'iast' | 'pentagi';

interface OrchestratorTabProps {
  orchSubTab: OrchSubTab;
  onSelectSubTab: (sub: OrchSubTab) => void;
  orch: OrchestratorState;
}

/** Enterprise orchestrator tab: sub-tab switcher over the five microservice panels. */
export default function OrchestratorTab({ orchSubTab, onSelectSubTab, orch }: OrchestratorTabProps) {
  return (
    <div className="space-y-6 animate-fade-in text-xs font-mono">
      <div className="bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5">
        <Shield className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5 animate-pulse" />
        <div className="space-y-1">
          <h4 className="text-white text-xs uppercase font-bold">Autonomous PentAGI & Microservices</h4>
          <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
            Trigger our autonomous AI ethical hacker agents, or utilize established standalone security engines to de-duplicate, verify, and trace live exploitable postures.
          </p>
        </div>
      </div>

      {/* Sub tabs */}
      <div className="flex flex-wrap gap-2 border-b border-[#27272a]/40 pb-3">
        {[
          { id: 'aspm' as const, label: 'ASPM Correlation', subtitle: 'DefectDojo & Fusion' },
          { id: 'easm' as const, label: 'EASM Perimeter', subtitle: 'Amass Subdomains & Wappalyzer' },
          { id: 'apiscan' as const, label: 'API Security Testing', subtitle: 'APISCAN & Hadrian Matrix' },
          { id: 'iast' as const, label: 'Interactive Passive Testing', subtitle: 'DongTai IAST Tracer' },
          { id: 'pentagi' as const, label: 'Autonomous Pentest AI', subtitle: 'PentAGI Cooperative Agents' }
        ].map(sub => (
          <button
            key={sub.id}
            onClick={() => onSelectSubTab(sub.id)}
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

      {orchSubTab === 'aspm' && <AspmPanel orch={orch} />}
      {orchSubTab === 'easm' && <EasmPanel orch={orch} />}
      {orchSubTab === 'apiscan' && <ApiScanPanel orch={orch} />}
      {orchSubTab === 'iast' && <IastPanel orch={orch} />}
      {orchSubTab === 'pentagi' && <PentagiPanel orch={orch} />}
    </div>
  );
}
