import React from 'react';

export type DashboardTab = 'scans' | 'billing' | 'exclusions' | 'monitoring' | 'api-docs';

interface DashboardTabsProps {
  activeTab: DashboardTab;
  onSelect: (tab: DashboardTab) => void;
  scansCount: number;
  suppressCount: number;
  txCount: number;
}

export default function DashboardTabs({ activeTab, onSelect, scansCount, suppressCount, txCount }: DashboardTabsProps) {
  const tabClass = (tab: DashboardTab) =>
    `px-4 py-2 font-mono text-xs uppercase tracking-widest border-b-2 transition-all pb-3 cursor-pointer ${
      activeTab === tab
        ? 'border-[#22c55e] text-white font-bold'
        : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
    }`;

  return (
    <div className="flex flex-wrap gap-1.5 border-b border-[#27272a]/80 mb-6">
      <button onClick={() => onSelect('scans')} className={tabClass('scans')}>
        [+] Vulnerability Scans History ({scansCount})
      </button>
      <button onClick={() => onSelect('monitoring')} className={tabClass('monitoring')}>
        [+] Continuous Monitoring
      </button>
      <button onClick={() => onSelect('exclusions')} className={tabClass('exclusions')}>
        [+] Risk Exclusions & FP Rules ({suppressCount})
      </button>
      <button onClick={() => onSelect('billing')} className={tabClass('billing')}>
        [+] Billing & Receipts Log ({txCount})
      </button>
      <button onClick={() => onSelect('api-docs')} className={tabClass('api-docs')}>
        [+] API Documentation
      </button>
    </div>
  );
}
