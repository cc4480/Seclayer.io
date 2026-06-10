import React, { useState, useEffect } from 'react';
import { CheckCircle, AlertTriangle } from 'lucide-react';
import { Scan, ApiKey, User } from '../types.js';
import DashboardHeader from './dashboard/DashboardHeader.js';
import ScanLauncher from './dashboard/ScanLauncher.js';
import CreditsPurchasePanel from './dashboard/CreditsPurchasePanel.js';
import ApiKeysPanel from './dashboard/ApiKeysPanel.js';
import ScansTab from './dashboard/ScansTab.js';
import MonitoringTab from './dashboard/MonitoringTab.js';
import ExclusionsTab from './dashboard/ExclusionsTab.js';
import BillingTab from './dashboard/BillingTab.js';
import ApiDocsTab from './dashboard/ApiDocsTab.js';
import OrchestratorTab, { OrchSubTab } from './dashboard/OrchestratorTab.js';
import { useOrchestrator } from './dashboard/useOrchestrator.js';
import { useDashboardLists } from './dashboard/useDashboardLists.js';
import { useMonitorForm } from './dashboard/useMonitorForm.js';

interface DashboardProps {
  user: User;
  scans: Scan[];
  apiKeys: ApiKey[];
  credits: number;
  transactions: any[];
  onInitiateScan: (url: string, authHeader?: string) => void;
  onGenerateKey: () => void;
  onRevokeKey: (keyId: string) => void;
  onPurchaseCredits: (packName: 'single' | 'pack5' | 'pack20') => void;
  onViewReport: (scanId: string) => void;
  isPerformingAction: boolean;
}

export default function Dashboard({
  user,
  scans,
  apiKeys,
  credits,
  transactions,
  onInitiateScan,
  onGenerateKey,
  onRevokeKey,
  onPurchaseCredits,
  onViewReport,
  isPerformingAction
}: DashboardProps) {
  // scanUrl lives here because both the launcher form and the PentAGI panel use it.
  const [scanUrl, setScanUrl] = useState('');
  const [activeTab, setActiveTab] = useState<'scans' | 'billing' | 'exclusions' | 'orchestrator' | 'monitoring' | 'api-docs'>('orchestrator');
  const [orchSubTab, setOrchSubTab] = useState<OrchSubTab>('pentagi');

  // Scan history filters, lifted so they survive tab switches.
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');

  const [prevCredits, setPrevCredits] = useState(credits);
  const [showToast, setShowToast] = useState(false);
  const [toastMsg, setToastMsg] = useState('');
  const [toastVariant, setToastVariant] = useState<'success' | 'error'>('success');

  const notify = (msg: string, variant: 'success' | 'error' = 'success') => {
    setToastMsg(msg);
    setToastVariant(variant);
    setShowToast(true);
    setTimeout(() => setShowToast(false), variant === 'error' ? 5000 : 3000);
  };

  const orch = useOrchestrator(notify, scanUrl);
  const { suppressRules, fetchSuppressRules, monitoredTargets, fetchMonitoredTargets } = useDashboardLists(user.id, scans);
  const monitorForm = useMonitorForm(user.id, fetchMonitoredTargets);

  // Toast notifier for balance changes
  useEffect(() => {
    if (credits > prevCredits) {
      notify(`Sandbox Top-up Successful! Added ${credits - prevCredits} scan credits.`);
    }
    setPrevCredits(credits);
  }, [credits, prevCredits]);

  const tabs: Array<{ id: typeof activeTab; label: string; domId?: string }> = [
    { id: 'scans', label: `[+] Vulnerability Scans History (${scans.length})` },
    { id: 'orchestrator', label: '[+] Autonomous AI Attacks', domId: 'orchestrator-tab' },
    { id: 'monitoring', label: '[+] Continuous Monitoring' },
    { id: 'exclusions', label: `[+] Risk Exclusions & FP Rules (${suppressRules.length})` },
    { id: 'billing', label: `[+] Billing & Receipts Log (${transactions.length})` },
    { id: 'api-docs', label: '[+] API Documentation' },
  ];

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-12 px-6">
      <div className="max-w-7xl mx-auto space-y-10">

        {/* Row 1: Header / Status banner */}
        <DashboardHeader
          user={user}
          credits={credits}
          onOpenPentagi={() => {
            setActiveTab('orchestrator');
            setOrchSubTab('pentagi');
            document.getElementById('orchestrator-tab')?.scrollIntoView({ behavior: 'smooth' });
          }}
        />

        {/* Bento Grid Layer */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">

          {/* Left Block: quick scan launcher & pricing booster (col span 7) */}
          <div className="lg:col-span-7 space-y-8">
            <ScanLauncher
              scanUrl={scanUrl}
              setScanUrl={setScanUrl}
              credits={credits}
              isPerformingAction={isPerformingAction}
              onInitiateScan={onInitiateScan}
            />
            <CreditsPurchasePanel
              isPerformingAction={isPerformingAction}
              onPurchaseCredits={onPurchaseCredits}
            />
          </div>

          {/* Right Block: API Keys (MCP client setup) (col span 5) */}
          <div className="lg:col-span-5 space-y-8">
            <ApiKeysPanel apiKeys={apiKeys} onGenerateKey={onGenerateKey} onRevokeKey={onRevokeKey} />
          </div>

        </div>

        {/* Row 3: Scans Queue, Histories list and Billing history */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6 relative">

          {/* Tabs header */}
          <div className="flex flex-wrap gap-1.5 border-b border-[#27272a]/80 mb-6">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                id={tab.domId}
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
            <ScansTab
              scans={scans}
              onViewReport={onViewReport}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              filterStatus={filterStatus}
              setFilterStatus={setFilterStatus}
              filterSeverity={filterSeverity}
              setFilterSeverity={setFilterSeverity}
            />
          )}

          {activeTab === 'monitoring' && (
            <MonitoringTab monitoredTargets={monitoredTargets} form={monitorForm} />
          )}

          {activeTab === 'orchestrator' && (
            <OrchestratorTab orchSubTab={orchSubTab} onSelectSubTab={setOrchSubTab} orch={orch} />
          )}

          {activeTab === 'exclusions' && (
            <ExclusionsTab userId={user.id} suppressRules={suppressRules} onRefresh={fetchSuppressRules} />
          )}

          {activeTab === 'billing' && <BillingTab transactions={transactions} />}

          {activeTab === 'api-docs' && <ApiDocsTab notify={notify} />}

        </div>

      </div>

      {/* Floating Status Toast Notifier */}
      {showToast && (
        <div className={`fixed bottom-6 right-6 z-50 bg-[#0c0c0e] px-4 py-3 rounded shadow-2xl font-mono text-xs flex items-center space-x-2 animate-bounce border ${
          toastVariant === 'error'
            ? 'border-red-500 text-red-400 shadow-red-950/20'
            : 'border-[#22c55e] text-[#22c55e] shadow-green-950/20'
        }`}>
          {toastVariant === 'error' ? (
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 animate-pulse" />
          ) : (
            <CheckCircle className="w-4 h-4 text-[#22c55e] shrink-0 animate-pulse" />
          )}
          <span>{toastMsg}</span>
        </div>
      )}

    </div>
  );
}
