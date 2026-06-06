import React, { useState } from 'react';
import { Terminal, ArrowRight } from 'lucide-react';
import { Scan, ApiKey, User } from '../types.js';
import ScanLauncher from '../components/dashboard/ScanLauncher.js';
import ApiKeyPanel from '../components/dashboard/ApiKeyPanel.js';
import ScansTab from '../components/dashboard/ScansTab.js';
import MonitoringTab from '../components/dashboard/MonitoringTab.js';
import OrchestratorTab from '../components/dashboard/OrchestratorTab.js';
import ExclusionsTab from '../components/dashboard/ExclusionsTab.js';
import ApiDocsTab from '../components/dashboard/ApiDocsTab.js';

interface DashboardProps {
  user: User;
  scans: Scan[];
  apiKeys: ApiKey[];
  onInitiateScan: (url: string, authHeader?: string) => void;
  onGenerateKey: () => void;
  onRevokeKey: (keyId: string) => void;
  onViewReport: (scanId: string) => void;
  isPerformingAction: boolean;
}

type ActiveTab = 'scans' | 'orchestrator' | 'monitoring' | 'exclusions' | 'api-docs';

export default function Dashboard({
  user,
  scans,
  apiKeys,
  onInitiateScan,
  onGenerateKey,
  onRevokeKey,
  onViewReport,
  isPerformingAction,
}: DashboardProps) {
  const [activeTab, setActiveTab] = useState<ActiveTab>('orchestrator');

  const tabs: Array<{ id: ActiveTab; label: string }> = [
    { id: 'scans', label: `[+] Vulnerability Scans History (${scans.length})` },
    { id: 'orchestrator', label: '[+] Autonomous AI Attacks' },
    { id: 'monitoring', label: '[+] Continuous Monitoring' },
    { id: 'exclusions', label: '[+] Risk Exclusions & FP Rules' },
    { id: 'api-docs', label: '[+] API Documentation' },
  ];

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-12 px-6">
      <div className="max-w-7xl mx-auto space-y-10">

        {/* Header / Status banner */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-[#0c0c0e] p-6 rounded border border-[#27272a] relative overflow-hidden">
          <div className="absolute top-0 right-0 w-80 h-80 bg-[#22c55e]/5 rounded-full blur-[80px] pointer-events-none" />

          <div className="relative z-10 w-full md:w-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div>
              <h1 className="text-2xl font-mono font-bold tracking-tighter text-white mb-1">Developer Console</h1>
              <p className="text-[#a1a1aa] text-xs font-mono">
                Account context: <span className="text-white">{user.email}</span>
              </p>
            </div>
          </div>

          <div className="flex flex-col md:flex-row items-center relative z-10 w-full md:w-auto">
            <button
              onClick={() => setActiveTab('orchestrator')}
              className="w-full md:w-auto relative group overflow-hidden bg-black border border-[#22c55e]/40 rounded hover:border-[#22c55e] transition-colors p-3 flex items-center space-x-3 cursor-pointer"
            >
              <div className="absolute inset-0 bg-[#22c55e]/10 translate-y-full group-hover:translate-y-0 transition-transform duration-300 ease-out" />
              <div className="relative flex items-center justify-center bg-[#09090b] border border-[#27272a] rounded p-1.5 w-10 h-10 shrink-0">
                <Terminal className="w-5 h-5 text-[#22c55e] animate-pulse" />
              </div>
              <div className="relative text-left pr-2">
                <span className="block text-xs font-bold text-white uppercase tracking-wider">PentAGI Audit</span>
                <span className="block text-[10px] text-[#22c55e] font-mono mt-0.5">Autonomous AI Agents</span>
              </div>
              <ArrowRight className="w-4 h-4 text-[#52525b] group-hover:text-[#22c55e] transition-colors absolute right-4 opacity-0 group-hover:opacity-100 hidden sm:block" />
            </button>
          </div>
        </div>

        {/* Scan launcher + API keys grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <div className="lg:col-span-7">
            <ScanLauncher onInitiateScan={onInitiateScan} isPerformingAction={isPerformingAction} />
          </div>
          <div className="lg:col-span-5">
            <ApiKeyPanel apiKeys={apiKeys} onGenerateKey={onGenerateKey} onRevokeKey={onRevokeKey} />
          </div>
        </div>

        {/* Tabbed content panel */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
          <div className="flex flex-wrap gap-1.5 border-b border-[#27272a]/80 mb-6">
            {tabs.map(tab => (
              <button
                key={tab.id}
                id={tab.id === 'orchestrator' ? 'orchestrator-tab' : undefined}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2 font-mono text-xs uppercase tracking-widest border-b-2 transition-all pb-3 cursor-pointer ${
                  activeTab === tab.id
                    ? 'border-[#22c55e] text-white font-bold'
                    : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {activeTab === 'scans' && (
            <ScansTab scans={scans} onViewReport={onViewReport} />
          )}
          {activeTab === 'orchestrator' && (
            <OrchestratorTab />
          )}
          {activeTab === 'monitoring' && (
            <MonitoringTab userId={user.id} />
          )}
          {activeTab === 'exclusions' && (
            <ExclusionsTab userId={user.id} scanCount={scans.length} />
          )}
          {activeTab === 'api-docs' && (
            <ApiDocsTab apiKeys={apiKeys} />
          )}
        </div>

      </div>
    </div>
  );
}
