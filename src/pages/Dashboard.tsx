import React, { useState, useEffect } from 'react';
import { Coins, CheckCircle } from 'lucide-react';
import { Scan, ApiKey, User } from '../types.js';
import { useDashboardData } from './dashboard/useDashboardData.js';
import ScanLauncher from './dashboard/ScanLauncher.js';
import ApiKeysPanel from './dashboard/ApiKeysPanel.js';
import DashboardTabs, { DashboardTab } from './dashboard/DashboardTabs.js';
import ScansTab from './dashboard/ScansTab.js';
import MonitoringTab from './dashboard/MonitoringTab.js';
import ExclusionsTab from './dashboard/ExclusionsTab.js';
import BillingTab from './dashboard/BillingTab.js';
import ApiDocsTab from './dashboard/ApiDocsTab.js';

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
  const [activeTab, setActiveTab] = useState<DashboardTab>('scans');
  const [prevCredits, setPrevCredits] = useState(credits);
  const [showToast, setShowToast] = useState(false);
  const [toastMsg, setToastMsg] = useState('');

  const data = useDashboardData(user, scans);

  const notify = (msg: string) => {
    setToastMsg(msg);
    setShowToast(true);
    setTimeout(() => setShowToast(false), 3000);
  };

  // Toast notifier for balance changes
  useEffect(() => {
    if (credits > prevCredits) {
      setToastMsg(`Sandbox Top-up Successful! Added ${credits - prevCredits} scan credits.`);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 4000);
    }
    setPrevCredits(credits);
  }, [credits, prevCredits]);

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-12 px-6">
      <div className="max-w-7xl mx-auto space-y-10">

        {/* Row 1: Header / Status banner */}
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

          <div className="flex flex-col md:flex-row items-center space-y-4 md:space-y-0 md:space-x-6 relative z-10 w-full md:w-auto">
            <div className="text-right flex items-center justify-between w-full md:w-auto md:block pt-4 border-t border-[#27272a]/40 md:pt-0 md:border-0">
              <span className="text-[10px] font-mono text-[#52525b] uppercase block md:mb-0.5">Available Balance</span>
              <span className="text-2xl font-mono font-black text-[#22c55e] flex items-center space-x-2">
                <Coins className="w-5 h-5 text-[#22c55e] shrink-0" />
                <span>{credits} <span className="text-xs font-normal text-[#52525b] font-mono">scans</span></span>
              </span>
            </div>
          </div>
        </div>

        {/* Bento Grid Layer */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <ScanLauncher
            credits={credits}
            isPerformingAction={isPerformingAction}
            onInitiateScan={onInitiateScan}
            onPurchaseCredits={onPurchaseCredits}
          />
          <ApiKeysPanel apiKeys={apiKeys} onGenerateKey={onGenerateKey} onRevokeKey={onRevokeKey} />
        </div>

        {/* Row 3: Scans Queue, Histories list and Billing history */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6 relative">
          <DashboardTabs
            activeTab={activeTab}
            onSelect={setActiveTab}
            scansCount={scans.length}
            suppressCount={data.suppressRules.length}
            txCount={transactions.length}
          />

          {activeTab === 'scans' && <ScansTab scans={scans} onViewReport={onViewReport} />}
          {activeTab === 'monitoring' && <MonitoringTab data={data} />}
          {activeTab === 'exclusions' && <ExclusionsTab data={data} />}
          {activeTab === 'billing' && <BillingTab transactions={transactions} />}
          {activeTab === 'api-docs' && <ApiDocsTab onNotify={notify} />}
        </div>

      </div>

      {/* Floating Status Toast Notifier */}
      {showToast && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0c0c0e] border border-[#22c55e] text-[#22c55e] px-4 py-3 rounded shadow-2xl shadow-green-950/20 font-mono text-xs flex items-center space-x-2 animate-bounce">
          <CheckCircle className="w-4 h-4 text-[#22c55e] shrink-0 animate-pulse" />
          <span>{toastMsg}</span>
        </div>
      )}

    </div>
  );
}
