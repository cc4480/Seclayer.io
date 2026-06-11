import React, { useState } from 'react';
import { Shield, ArrowLeft, Download, Share2, Check, ShieldCheck } from 'lucide-react';
import { Scan } from '../types.js';
import { generateAuditPdf } from '../lib/pdf-report.js';
import { SecCategory, categoryTabLabels, getCategoryCount } from './report/categories.js';
import { useSuppression } from './report/useSuppression.js';
import ScanMetaHeader from './report/ScanMetaHeader.js';
import OverviewTab from './report/OverviewTab.js';
import ModuleFindingsTab from './report/ModuleFindingsTab.js';
import RawDiagnosticsDrawer from './report/RawDiagnosticsDrawer.js';

interface ReportViewerProps {
  scan: Scan;
  previousScan?: Scan;
  onBack: () => void;
  onRefreshScans?: () => void;
}

export default function ReportViewer({ scan, previousScan, onBack, onRefreshScans }: ReportViewerProps) {
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | SecCategory>('OVERVIEW');
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);
  const [expandedApiRows, setExpandedApiRows] = useState<Record<string, boolean>>({});
  const [validatedOnly, setValidatedOnly] = useState(false);

  const suppression = useSuppression(scan, onRefreshScans);
  const findings = scan.findings || [];
  const validatedCount = findings.filter(f => f.validated && !f.isFalsePositive).length;

  const handleShareClick = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const handleCopyCode = (findingId: string, fixText: string) => {
    navigator.clipboard.writeText(fixText);
    setCopiedCodeId(findingId);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-12 px-6">
      <div className="max-w-5xl mx-auto space-y-8 animate-fade-in">

        {/* Navigation Action Header */}
        <div className="flex items-center justify-between">
          <button
            onClick={onBack}
            className="flex items-center space-x-2 text-[#a1a1aa] hover:text-white font-mono text-xs uppercase tracking-wider transition-colors cursor-pointer"
            id="report-back-btn"
          >
            <ArrowLeft className="w-4 h-4 text-[#22c55e]" />
            <span>Audit Workspace</span>
          </button>

          <div className="flex items-center space-x-3">
            <button
              onClick={handleShareClick}
              className="px-3.5 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa] hover:text-white text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer"
              id="report-share-btn"
            >
              {copiedLink ? <Check className="w-3.5 h-3.5 text-[#22c55e]" /> : <Share2 className="w-3.5 h-3.5 text-[#52525b]" />}
              <span>{copiedLink ? 'Copied' : 'Share Link'}</span>
            </button>
            <button
              onClick={() => generateAuditPdf(scan, findings)}
              className="px-3.5 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa] hover:text-white text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer"
              id="report-download-btn"
            >
              <Download className="w-3.5 h-3.5 text-[#52525b]" />
              <span>Export Audit Findings</span>
            </button>
          </div>
        </div>

        {/* Audit Meta Summary Card */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded overflow-hidden shadow-2xl">
          <ScanMetaHeader scan={scan} previousScan={previousScan} findings={findings} />

          {/* Validated-only filter: surface re-confirmed exploit proofs */}
          {validatedCount > 0 && (
            <div className="flex items-center justify-between px-5 py-3 border-b border-[#27272a] bg-[#22c55e]/[0.03]">
              <span className="flex items-center space-x-2 text-[10px] font-mono uppercase tracking-wider text-[#22c55e]">
                <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                <span>{validatedCount} validated exploit{validatedCount === 1 ? '' : 's'} with reproducible PoC</span>
              </span>
              <button
                onClick={() => setValidatedOnly(v => !v)}
                className={`px-3 py-1 rounded border text-[10px] font-mono uppercase tracking-wider transition-colors cursor-pointer flex items-center space-x-1.5 ${
                  validatedOnly
                    ? 'border-[#22c55e]/50 bg-[#22c55e]/10 text-[#22c55e]'
                    : 'border-[#27272a] text-[#52525b] hover:text-[#a1a1aa] hover:border-[#3f3f46]'
                }`}
                id="report-validated-filter"
              >
                {validatedOnly && <Check className="w-3 h-3 shrink-0" />}
                <span>Validated only</span>
              </button>
            </div>
          )}

          {/* Core AppSec Framework Segmented Matrix tabs */}
          <div className="flex overflow-x-auto border-b border-[#27272a] bg-black/20 select-none scrollbar-none">
            <button
              onClick={() => setActiveTab('OVERVIEW')}
              className={`px-5 py-4 border-b-2 text-xs font-mono uppercase tracking-wider font-semibold transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
                activeTab === 'OVERVIEW'
                  ? 'border-[#22c55e] text-white bg-black/40'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              <Shield className="w-4 h-4 text-[#22c55e]" />
              <span>Executive Overview</span>
            </button>

            {categoryTabLabels.map(cat => {
              const count = getCategoryCount(findings, cat.key);
              const hasAlerts = count > 0;
              return (
                <button
                  key={cat.key}
                  onClick={() => setActiveTab(cat.key)}
                  className={`px-5 py-4 border-b-2 text-xs font-mono uppercase tracking-wider transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
                    activeTab === cat.key
                      ? 'border-[#22c55e] text-white bg-black/40'
                      : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
                  }`}
                >
                  <cat.icon className={`w-4 h-4 ${activeTab === cat.key ? 'text-[#22c55e]' : 'text-[#52525b]'}`} />
                  <span className="font-bold">{cat.label}</span>
                  <span className={`text-[10px] px-1.5 py-0.2 ml-1 rounded font-mono ${
                    hasAlerts
                      ? 'bg-red-500/10 text-red-400 border border-red-500/25'
                      : 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/25'
                  }`}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          <div className="p-6">

            {/* OVERVIEW TAB RENDERER */}
            {activeTab === 'OVERVIEW' && (
              <OverviewTab scan={scan} findings={findings} onSelectCategory={setActiveTab} />
            )}

            {/* DYNAMIC PER MODULE FINDINGS RENDERER */}
            {activeTab !== 'OVERVIEW' && (
              <ModuleFindingsTab
                category={activeTab}
                findings={findings}
                validatedOnly={validatedOnly}
                copiedCodeId={copiedCodeId}
                onCopyCode={handleCopyCode}
                expandedApiRows={expandedApiRows}
                onToggleExpanded={(findingId) => setExpandedApiRows(p => ({ ...p, [findingId]: !p[findingId] }))}
                suppression={suppression}
              />
            )}

          </div>
        </div>

        {/* Raw Header Output Inspection drawer */}
        <RawDiagnosticsDrawer scan={scan} findings={findings} />

      </div>
    </div>
  );
}
