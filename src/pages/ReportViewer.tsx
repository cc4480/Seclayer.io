import React, { useState } from 'react';
import { Shield, ArrowLeft, Download, Share2, Check, Clock } from 'lucide-react';
import { Scan } from '../types.js';
import { SecCategory, categoryTabLabels, getCategoryCount, scoreColorClass } from './reportViewer/categories.js';
import { downloadAuditPdf } from './reportViewer/pdf.js';
import { useSuppression } from './reportViewer/useSuppression.js';
import OverviewTab from './reportViewer/OverviewTab.js';
import FindingsTab from './reportViewer/FindingsTab.js';
import RawDiagnostics from './reportViewer/RawDiagnostics.js';

interface ReportViewerProps {
  scan: Scan;
  previousScan?: Scan;
  onBack: () => void;
  onRefreshScans?: () => void;
}

export default function ReportViewer({ scan, previousScan, onBack, onRefreshScans }: ReportViewerProps) {
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | SecCategory>('OVERVIEW');
  const [showRaw, setShowRaw] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);
  const [expandedApiRows, setExpandedApiRows] = useState<Record<string, boolean>>({});

  const sup = useSuppression(scan, onRefreshScans);
  const findings = scan.findings || [];

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
              onClick={() => downloadAuditPdf(scan, findings)}
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
          <div className="bg-black/40 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6 border-b border-[#27272a]">
            <div>
              <div className="flex items-center space-x-2.5">
                <span className="font-mono text-xs text-[#52525b] select-none">[Target Host]</span>
                <strong className="font-mono text-sm text-white tracking-wide break-all select-all">{scan.url}</strong>
              </div>
              <p className="text-[#52525b] text-xs mt-2 font-mono flex items-center space-x-4">
                <span className="flex items-center space-x-1">
                  <Clock className="w-3.5 h-3.5 text-[#52525b]" />
                  <span>Assessed: {new Date(scan.createdAt).toLocaleDateString()}</span>
                </span>
                <span>•</span>
                <span>Job ID: {scan.id}</span>
              </p>
            </div>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 shrink-0">
              {previousScan && (
                <div className="p-4 rounded border border-zinc-800 bg-black flex items-center space-x-5 h-full">
                  <div className="text-right">
                    <span className="text-[9px] font-mono text-zinc-500 uppercase block tracking-wider select-none">Score Delta</span>
                    <span className={`text-xl font-mono font-black block mt-1 ${scan.score! > previousScan.score! ? 'text-green-500' : scan.score! < previousScan.score! ? 'text-red-500' : 'text-zinc-500'}`}>
                      {scan.score! > previousScan.score! ? '+' : ''}{scan.score! - previousScan.score!}
                    </span>
                  </div>
                  <div className="border-l border-zinc-800 pl-4 text-right">
                    <span className="text-[9px] font-mono text-zinc-500 uppercase block tracking-wider select-none">Findings Delta</span>
                    <span className={`text-xl font-mono font-black block mt-1 ${findings.length < previousScan.findings!.length ? 'text-green-500' : findings.length > previousScan.findings!.length ? 'text-amber-500' : 'text-zinc-500'}`}>
                      {findings.length > previousScan.findings!.length ? '+' : ''}{findings.length - previousScan.findings!.length}
                    </span>
                  </div>
                </div>
              )}
              <div className={`p-4 rounded border flex items-center space-x-5 h-full shrink-0 ${scoreColorClass(scan.score || 100)}`}>
                <div className="text-right">
                  <span className="text-[9px] font-mono text-[#52525b] uppercase block tracking-wider select-none">AppSec Score</span>
                  <span className="text-3xl font-mono font-black leading-none">{scan.score}<span className="text-xs text-[#52525b] font-normal">/100</span></span>
                </div>
                <div className="border-l border-[#27272a] pl-4">
                  <span className="text-[9px] font-mono text-[#52525b] uppercase block tracking-wider select-none">Posture Rating</span>
                  <span className="text-xs font-mono font-bold uppercase tracking-wider block mt-1">{scan.severity}</span>
                </div>
              </div>
            </div>
          </div>

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
            {activeTab === 'OVERVIEW' ? (
              <OverviewTab scan={scan} findings={findings} onSelectTab={setActiveTab} />
            ) : (
              <FindingsTab
                activeTab={activeTab}
                findings={findings}
                copiedCodeId={copiedCodeId}
                onCopyCode={handleCopyCode}
                expandedApiRows={expandedApiRows}
                onToggleExpand={(id) => setExpandedApiRows(p => ({ ...p, [id]: !p[id] }))}
                sup={sup}
              />
            )}
          </div>
        </div>

        {/* Raw Header Output Inspection drawer */}
        <RawDiagnostics scan={scan} findings={findings} showRaw={showRaw} onToggle={() => setShowRaw(!showRaw)} />

      </div>
    </div>
  );
}
