import { Scan } from '../types.js';
import { useReportViewerState } from './report/useReportViewerState.js';
import ReportNavHeader from './report/ReportNavHeader.js';
import ReportMetaCard from './report/ReportMetaCard.js';
import OverviewTab from './report/OverviewTab.js';
import ModuleFindingsTab from './report/ModuleFindingsTab.js';
import ComplianceTab from './report/ComplianceTab.js';
import RawDiagnosticsDrawer from './report/RawDiagnosticsDrawer.js';

interface ReportViewerProps {
  scan: Scan;
  previousScan?: Scan;
  onBack: () => void;
  onRefreshScans?: () => void;
}

export default function ReportViewer({ scan, previousScan, onBack, onRefreshScans }: ReportViewerProps) {
  const {
    activeTab, setActiveTab,
    copiedLink,
    copiedCodeId,
    suppressInputId, setSuppressInputId,
    suppressReason, setSuppressReason,
    isSuppressing,
    suppressError, setSuppressError,
    recheckingId,
    recheckMsg,
    statusFilter, setStatusFilter,
    autoFixingId,
    autoFixMsg,
    findings,
    moduleFindings,
    handleSetRemediation,
    handleRecheck,
    handleAutoFix,
    handleSaveSuppression,
    handleRemoveSuppressionDirectly,
    handleShareClick,
    handleCopyCode,
    handleDownloadPdf,
  } = useReportViewerState(scan, onRefreshScans);

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-12 px-6">
      <div className="max-w-5xl mx-auto space-y-8 animate-fade-in">

        {/* Navigation Action Header */}
        <ReportNavHeader
          copiedLink={copiedLink}
          onBack={onBack}
          onShareClick={handleShareClick}
          onDownloadPdf={handleDownloadPdf}
        />

        {/* Audit Meta Summary Card */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded overflow-hidden shadow-2xl">
          <ReportMetaCard
            scan={scan}
            previousScan={previousScan}
            findings={findings}
            activeTab={activeTab}
            onSetActiveTab={setActiveTab}
          />

          <div className="p-6">

            {/* OVERVIEW TAB RENDERER */}
            {activeTab === 'OVERVIEW' && (
              <OverviewTab scan={scan} findings={findings} onSelectCategory={setActiveTab} />
            )}

            {/* DYNAMIC PER MODULE FINDINGS RENDERER */}
            {activeTab !== 'OVERVIEW' && activeTab !== 'compliance' && (
              <ModuleFindingsTab
                activeTab={activeTab}
                findings={findings}
                moduleFindings={moduleFindings}
                statusFilter={statusFilter}
                onStatusFilterChange={setStatusFilter}
                copiedCodeId={copiedCodeId}
                recheckingId={recheckingId}
                recheckMsg={recheckMsg}
                autoFixingId={autoFixingId}
                autoFixMsg={autoFixMsg}
                suppressInputId={suppressInputId}
                suppressReason={suppressReason}
                isSuppressing={isSuppressing}
                suppressError={suppressError}
                onSetRemediation={handleSetRemediation}
                onRecheck={handleRecheck}
                onAutoFix={handleAutoFix}
                onSaveSuppression={handleSaveSuppression}
                onRemoveSuppressionDirectly={handleRemoveSuppressionDirectly}
                onCopyCode={handleCopyCode}
                onOpenSuppressInput={(id) => { setSuppressInputId(id); setSuppressReason(''); setSuppressError(null); }}
                onCloseSuppressInput={() => { setSuppressInputId(null); setSuppressError(null); }}
                onSuppressReasonChange={setSuppressReason}
              />
            )}

            {/* COMPLIANCE TAB */}
            {activeTab === 'compliance' && (
              <ComplianceTab scan={scan} findings={findings} />
            )}

          </div>
        </div>

        {/* Raw Header Output Inspection drawer */}
        <RawDiagnosticsDrawer scan={scan} findings={findings} />

      </div>
    </div>
  );
}
