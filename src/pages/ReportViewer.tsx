import { useState } from 'react';
import { Settings, Eye } from 'lucide-react';
import { Scan, Finding } from '../types.js';
import { apiFetch } from '../lib/api.js';
import { generatePdfReport } from './report/generatePdfReport.js';
import { SecCategory, remediationStatusOf } from './report/reportHelpers.js';
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
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | SecCategory | 'compliance'>('OVERVIEW');
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);

  // Suppression and False Positives States
  const [suppressInputId, setSuppressInputId] = useState<string | null>(null);
  const [suppressReason, setSuppressReason] = useState('');
  const [isSuppressing, setIsSuppressing] = useState(false);
  const [suppressError, setSuppressError] = useState<string | null>(null);

  // Remediation lifecycle states
  const [recheckingId, setRecheckingId] = useState<string | null>(null);
  const [recheckMsg, setRecheckMsg] = useState<Record<string, { ok: boolean; text: string }>>({});
  const [statusFilter, setStatusFilter] = useState<'all' | 'open' | 'in_progress' | 'fixed' | 'verified'>('all');
  const [autoFixingId, setAutoFixingId] = useState<string | null>(null);
  const [autoFixMsg, setAutoFixMsg] = useState<Record<string, { ok: boolean; text: string; prUrl?: string }>>({});

  const findings = scan.findings || [];

  const handleSetRemediation = async (finding: Finding, status: string) => {
    try {
      const res = await apiFetch(`/api/scans/${scan.id}/findings/${finding.id}/remediation`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      });
      if (res.ok && onRefreshScans) onRefreshScans();
    } catch (err) {
      console.error('Failed to update remediation status:', err);
    }
  };

  const handleRecheck = async (finding: Finding) => {
    setRecheckingId(finding.id);
    setRecheckMsg(prev => ({ ...prev, [finding.id]: { ok: true, text: 'Re-testing against live target…' } }));
    try {
      const res = await apiFetch(`/api/scans/${scan.id}/findings/${finding.id}/recheck`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setRecheckMsg(prev => ({ ...prev, [finding.id]: { ok: !data.stillPresent, text: data.detail } }));
        if (onRefreshScans) onRefreshScans();
      } else {
        setRecheckMsg(prev => ({ ...prev, [finding.id]: { ok: false, text: data.error || 'Re-check failed.' } }));
      }
    } catch (err: any) {
      setRecheckMsg(prev => ({ ...prev, [finding.id]: { ok: false, text: err.message || 'Network error during re-check.' } }));
    } finally {
      setRecheckingId(null);
    }
  };

  const handleAutoFix = async (finding: Finding) => {
    setAutoFixingId(finding.id);
    setAutoFixMsg(prev => ({ ...prev, [finding.id]: { ok: true, text: 'Generating patch and opening pull request…' } }));
    try {
      const res = await apiFetch(`/api/scans/${scan.id}/findings/${finding.id}/auto-fix`, { method: 'POST' });
      const data = await res.json();
      if (res.ok && data.status === 'ok') {
        setAutoFixMsg(prev => ({ ...prev, [finding.id]: { ok: true, text: `Pull request opened.`, prUrl: data.prUrl } }));
        if (onRefreshScans) onRefreshScans();
      } else {
        setAutoFixMsg(prev => ({ ...prev, [finding.id]: { ok: false, text: data.detail || data.error || 'Auto-fix failed.' } }));
      }
    } catch (err: any) {
      setAutoFixMsg(prev => ({ ...prev, [finding.id]: { ok: false, text: err.message || 'Network error during auto-fix.' } }));
    } finally {
      setAutoFixingId(null);
    }
  };

  const moduleFindings = findings.filter(
    f => f.category === activeTab && (statusFilter === 'all' || remediationStatusOf(f) === statusFilter),
  );

  const handleSaveSuppression = async (finding: Finding) => {
    setIsSuppressing(true);
    setSuppressError(null);
    try {
      const res = await apiFetch(`/api/scans/${scan.id}/findings/${finding.id}/suppress`, {
        method: 'POST',
        body: JSON.stringify({
          reason: suppressReason.trim() || 'Verified acceptable risk / false positive audit confirmation.'
        })
      });
      if (res.ok) {
        setSuppressInputId(null);
        setSuppressReason('');
        if (onRefreshScans) onRefreshScans();
      } else {
        const data = await res.json();
        setSuppressError(data.error || 'Failed to apply suppression rule');
      }
    } catch (err: any) {
      setSuppressError(err.message || 'Network failure applying suppression');
    } finally {
      setIsSuppressing(false);
    }
  };

  const handleRemoveSuppressionDirectly = async (findingTitle: string) => {
    setIsSuppressing(true);
    setSuppressError(null);
    try {
      const listRes = await apiFetch('/api/suppressions');
      if (!listRes.ok) throw new Error('Could not read exclusion list');
      const listData = await listRes.json();
      const cleanUrl = (u: string) => u.toLowerCase().replace(/https?:\/\//i, '').replace(/\/+$/, '');
      const matchingRule = (listData.suppressions || []).find((s: any) =>
        s.findingTitle === findingTitle && cleanUrl(s.targetUrl) === cleanUrl(scan.url)
      );
      if (!matchingRule) throw new Error('Suppression rule for this finding was not found.');

      const delRes = await apiFetch(`/api/suppressions/${matchingRule.id}`, { method: 'DELETE' });
      if (delRes.ok) {
        if (onRefreshScans) onRefreshScans();
      } else {
        const delData = await delRes.json();
        throw new Error(delData.error || 'Failed to remove exclusion rule');
      }
    } catch (err: any) {
      setSuppressError(err.message || 'Failed to restore finding status.');
    } finally {
      setIsSuppressing(false);
    }
  };

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

  const handleDownloadPdf = () => {
    generatePdfReport(scan, findings);
  };

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
