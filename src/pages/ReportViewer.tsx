import React, { useState } from 'react';
import { 
  Shield, ArrowLeft, Download, Share2, Clipboard, Globe, 
  Settings, Check, Eye, Code, Terminal, AlertTriangle, 
  ChevronDown, ChevronUp, Clock, FileText, CheckCircle2,
  Zap, Package, Grid, AlertCircle, Sparkles, Server, Copy
} from 'lucide-react';
import { Scan, Finding } from '../types.js';
import { apiFetch } from '../lib/api.js';
import { jsPDF } from "jspdf";
import autoTable from 'jspdf-autotable';

interface ReportViewerProps {
  scan: Scan;
  previousScan?: Scan;
  onBack: () => void;
  onRefreshScans?: () => void;
}

type SecCategory = 'SAST' | 'DAST' | 'IAST' | 'SCA' | 'EASM' | 'RED_TEAM' | 'API_SEC';

export default function ReportViewer({ scan, previousScan, onBack, onRefreshScans }: ReportViewerProps) {
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | SecCategory | 'compliance'>('OVERVIEW');
  const [showRaw, setShowRaw] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);

  // Suppression and False Positives States
  const [suppressInputId, setSuppressInputId] = useState<string | null>(null);
  const [suppressReason, setSuppressReason] = useState('');
  const [isSuppressing, setIsSuppressing] = useState(false);
  const [suppressError, setSuppressError] = useState<string | null>(null);
  const [expandedApiRows, setExpandedApiRows] = useState<Record<string, boolean>>({});

  const findings = scan.findings || [];

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
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 15;
    const contentWidth = pageWidth - margin * 2;
    const today = new Date().toISOString().split('T')[0];
    const score = scan.score ?? 100;

    const severityRgb = (s: string): [number, number, number] =>
      s === 'critical' ? [239, 68, 68] :
      s === 'high'     ? [249, 115, 22] :
      s === 'medium'   ? [234, 179, 8] :
                         [34, 197, 94];

    const truncate = (str: string, maxLen: number) =>
      str && str.length > maxLen ? str.slice(0, maxLen - 1) + '…' : (str || '');

    const addFooters = () => {
      const totalPages = (doc as any).internal.getNumberOfPages();
      for (let p = 1; p <= totalPages; p++) {
        doc.setPage(p);
        doc.setFontSize(7);
        doc.setFont("helvetica", "normal");
        doc.setTextColor(150, 150, 150);
        doc.text(
          `Page ${p} of ${totalPages}  —  Confidential  —  Seclayer Security Assessment  —  ${today}`,
          pageWidth / 2, pageHeight - 6, { align: 'center' }
        );
      }
    };

    const ensureSpace = (currentY: number, needed: number): number => {
      if (currentY + needed > pageHeight - 14) { doc.addPage(); return 20; }
      return currentY;
    };

    // ── PAGE 1: EXECUTIVE COVER ──────────────────────────────────────────────
    doc.setFillColor(9, 9, 11);
    doc.rect(0, 0, pageWidth, 50, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(24);
    doc.text("SECLAYER", margin, 22);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(161, 161, 170);
    doc.text("Security Assessment Report", margin, 33);
    doc.setFontSize(9);
    doc.text(today, pageWidth - margin, 22, { align: 'right' });

    let y = 65;
    doc.setFontSize(8);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(120, 120, 120);
    doc.text("TARGET ASSESSED:", margin, y);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    doc.setTextColor(30, 30, 30);
    doc.text(scan.url, margin + 36, y);
    y += 14;

    const scoreRgb: [number, number, number] =
      score >= 85 ? [34, 197, 94] : score >= 60 ? [234, 179, 8] : [239, 68, 68];
    doc.setFillColor(...scoreRgb);
    doc.rect(margin, y, 38, 22, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.text(`${score}`, margin + 19, y + 12, { align: 'center' });
    doc.setFontSize(8);
    doc.text("/100", margin + 19, y + 19, { align: 'center' });

    const verdict = score >= 85 ? "SAFE TO SHIP" : score >= 60 ? "REVIEW RECOMMENDED" : "ACTION REQUIRED";
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.setTextColor(...scoreRgb);
    doc.text(verdict, margin + 46, y + 13);
    y += 34;

    if (scan.aiSummary) {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(60, 60, 60);
      doc.text("ASSESSMENT SUMMARY", margin, y);
      y += 5;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(70, 70, 70);
      const summaryLines = doc.splitTextToSize(scan.aiSummary, contentWidth);
      doc.text(summaryLines, margin, y);
      y += summaryLines.length * 4.5 + 10;
    }

    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(60, 60, 60);
    doc.text("FINDINGS SUMMARY", margin, y);
    y += 6;

    const counts: Array<{ label: string; n: number; rgb: [number, number, number] }> = [
      { label: 'Critical', n: findings.filter(f => f.severity === 'critical').length, rgb: [239, 68, 68] },
      { label: 'High',     n: findings.filter(f => f.severity === 'high').length,     rgb: [249, 115, 22] },
      { label: 'Medium',   n: findings.filter(f => f.severity === 'medium').length,   rgb: [234, 179, 8] },
      { label: 'Low',      n: findings.filter(f => f.severity === 'low').length,      rgb: [34, 197, 94] },
    ];
    counts.forEach((c, idx) => {
      const px = margin + idx * 45;
      doc.setFillColor(c.rgb[0], c.rgb[1], c.rgb[2]);
      doc.rect(px, y, 40, 14, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.text(`${c.n}`, px + 20, y + 8, { align: 'center' });
      doc.setFontSize(6);
      doc.setFont("helvetica", "normal");
      doc.text(c.label.toUpperCase(), px + 20, y + 13, { align: 'center' });
    });

    // ── PAGE 2: PRIORITY FIXES ───────────────────────────────────────────────
    const priorityFindings = findings
      .filter(f => !f.isFalsePositive && (f.severity === 'critical' || f.severity === 'high'))
      .sort((a, b) => (a.severity === 'critical' ? 0 : 1) - (b.severity === 'critical' ? 0 : 1))
      .slice(0, 5);

    if (priorityFindings.length > 0) {
      doc.addPage();
      doc.setFillColor(9, 9, 11);
      doc.rect(0, 0, pageWidth, 16, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      doc.text("PRIORITY FIXES", margin, 11);
      let py = 28;

      priorityFindings.forEach((f, idx) => {
        const sRgb = severityRgb(f.severity);
        const bodyText = f.plainEnglish || f.description;
        const bodyLines = doc.splitTextToSize(bodyText, contentWidth);
        const codeLines = f.codeFixExample ? doc.splitTextToSize(f.codeFixExample, contentWidth - 8) : [];
        const blockH = 10 + bodyLines.length * 4.5 + 4 + (codeLines.length > 0 ? codeLines.length * 4 + 10 : 0);
        py = ensureSpace(py, blockH + 8);

        doc.setFillColor(...sRgb);
        doc.rect(margin, py, 22, 6, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFont("helvetica", "bold");
        doc.setFontSize(7);
        doc.text(f.severity.toUpperCase(), margin + 11, py + 4.2, { align: 'center' });
        doc.setFont("helvetica", "bold");
        doc.setFontSize(10);
        doc.setTextColor(20, 20, 20);
        doc.text(f.title, margin + 26, py + 4.5);
        py += 10;

        doc.setFont("helvetica", "normal");
        doc.setFontSize(9);
        doc.setTextColor(70, 70, 70);
        doc.text(bodyLines, margin, py);
        py += bodyLines.length * 4.5 + 4;

        if (codeLines.length > 0) {
          const codeBlockH = codeLines.length * 4 + 8;
          py = ensureSpace(py, codeBlockH + 4);
          doc.setFillColor(242, 242, 242);
          doc.rect(margin, py, contentWidth, codeBlockH, 'F');
          doc.setDrawColor(210, 210, 210);
          doc.rect(margin, py, contentWidth, codeBlockH, 'S');
          doc.setFont("courier", "normal");
          doc.setFontSize(7.5);
          doc.setTextColor(40, 40, 40);
          doc.text(codeLines, margin + 4, py + 5);
          py += codeBlockH + 6;
        }

        if (idx < priorityFindings.length - 1) {
          py = ensureSpace(py, 6);
          doc.setDrawColor(220, 220, 220);
          doc.line(margin, py, pageWidth - margin, py);
          py += 6;
        }
      });
    }

    // ── PAGE 3+: ALL FINDINGS TABLE ──────────────────────────────────────────
    doc.addPage();
    doc.setFillColor(9, 9, 11);
    doc.rect(0, 0, pageWidth, 16, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text("FULL FINDINGS", margin, 11);

    autoTable(doc, {
      startY: 20,
      head: [['#', 'Vulnerability', 'Severity', 'Category', 'Impact', 'Remediation']],
      body: findings.map((f, i) => [
        String(i + 1),
        f.isFalsePositive ? `${f.title} (SUPPRESSED)` : f.title,
        f.severity.toUpperCase(),
        f.category,
        truncate(f.plainEnglish || f.description, 100),
        truncate(f.fix, 100),
      ]),
      theme: 'grid',
      styles: { fontSize: 7.5, cellPadding: 2.5, overflow: 'linebreak' },
      headStyles: { fillColor: [9, 9, 11], textColor: [255, 255, 255], fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [248, 248, 248] },
      columnStyles: {
        0: { cellWidth: 8 },
        1: { cellWidth: 38 },
        2: { cellWidth: 18 },
        3: { cellWidth: 18 },
        4: { cellWidth: 52 },
        5: { cellWidth: 47 },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 2) {
          data.cell.styles.textColor = severityRgb(String(data.cell.raw).toLowerCase());
          data.cell.styles.fontStyle = 'bold';
        }
        if (data.section === 'body' && findings[data.row.index]?.isFalsePositive) {
          data.cell.styles.textColor = [160, 160, 160];
        }
      },
    });

    // ── LAST PAGE: COMPLIANCE SUMMARY ────────────────────────────────────────
    doc.addPage();
    doc.setFillColor(9, 9, 11);
    doc.rect(0, 0, pageWidth, 16, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text("COMPLIANCE SUMMARY", margin, 11);

    const activeFindings = findings.filter(f => !f.isFalsePositive);
    const checkFail = (kws: string[]) =>
      activeFindings.some(f =>
        (f.severity === 'high' || f.severity === 'critical') &&
        kws.some(kw => f.title.toLowerCase().includes(kw.toLowerCase()) || f.description.toLowerCase().includes(kw.toLowerCase()))
      );

    type CompRow = { id: string; name: string; status: 'PASS' | 'FAIL' | 'WARN' };
    const pciReqs: CompRow[] = [
      { id: 'Req 4.2.1',  name: 'Strong Cryptography',           status: checkFail(['TLS','SSL','certificate','HSTS','expired']) ? 'FAIL' : 'PASS' },
      { id: 'Req 6.2.4',  name: 'Protect Against Known Attacks', status: checkFail(['injection','XSS','cross-site','SSTI','template','traversal','command']) ? 'FAIL' : 'PASS' },
      { id: 'Req 6.3.2',  name: 'Software Component Inventory',  status: checkFail(['jQuery','Bootstrap','Lodash','outdated','library']) ? 'FAIL' : 'PASS' },
      { id: 'Req 8.2.1',  name: 'User Authentication Controls',  status: checkFail(['CORS','cookie','session','authentication','bypass']) ? 'FAIL' : 'PASS' },
      { id: 'Req 11.3.2', name: 'External Vulnerability Scans',  status: 'PASS' },
      { id: 'Req 11.4.1', name: 'Penetration Testing',           status: 'PASS' },
    ];
    const soc2Reqs: CompRow[] = [
      { id: 'CC6.1', name: 'Logical Access Controls', status: checkFail(['CORS','authentication','bypass','IDOR','access control']) ? 'FAIL' : 'PASS' },
      { id: 'CC6.6', name: 'Logical Access Threats',  status: checkFail(['injection','XSS','SSRF','traversal','command']) ? 'FAIL' : 'PASS' },
      { id: 'CC7.1', name: 'Vulnerability Detection', status: 'PASS' },
      { id: 'CC8.1', name: 'Change Management',       status: checkFail(['outdated','library','jQuery','Bootstrap','SCA']) ? 'FAIL' : 'PASS' },
      { id: 'CC9.2', name: 'Risk Monitoring',         status: score >= 70 ? 'PASS' : 'WARN' },
    ];

    const statusRgb = (s: 'PASS' | 'FAIL' | 'WARN'): [number, number, number] =>
      s === 'PASS' ? [34, 197, 94] : s === 'FAIL' ? [239, 68, 68] : [234, 179, 8];
    const compColW = (contentWidth - 8) / 2;

    const renderCompTable = (rows: CompRow[], startX: number, title: string) => {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(30, 30, 30);
      doc.text(title, startX, 24);
      autoTable(doc, {
        startY: 28,
        tableWidth: compColW,
        margin: { left: startX },
        head: [['ID', 'Requirement', 'Status']],
        body: rows.map(r => [r.id, r.name, r.status]),
        theme: 'grid',
        styles: { fontSize: 7, cellPadding: 2 },
        headStyles: { fillColor: [9, 9, 11], textColor: [255, 255, 255], fontStyle: 'bold' },
        columnStyles: {
          0: { cellWidth: 22 },
          1: { cellWidth: compColW - 40 },
          2: { cellWidth: 18, halign: 'center', fontStyle: 'bold' },
        },
        didParseCell: (data) => {
          if (data.section === 'body' && data.column.index === 2) {
            data.cell.styles.textColor = statusRgb(String(data.cell.raw) as 'PASS' | 'FAIL' | 'WARN');
            data.cell.styles.fontStyle = 'bold';
          }
        },
      });
    };

    renderCompTable(pciReqs, margin, "PCI-DSS 4.0");
    renderCompTable(soc2Reqs, margin + compColW + 8, "SOC2 Trust Service Criteria");

    addFooters();
    doc.save(`seclayer-report-${scan.url.replace(/https?:\/\//i, '').replace(/[^a-zA-Z0-9]/g, '_')}.pdf`);
  };

  // Score metrics
  const score = scan.score || 100;
  const isHighRisk = score < 60;
  const isMediumRisk = score >= 60 && score < 85;
  const isLowRisk = score >= 85;

  const scoreColorClass = 
    isLowRisk ? 'text-[#22c55e] border-[#22c55e]/25 bg-[#22c55e]/5' :
    isMediumRisk ? 'text-amber-400 border-amber-500/20 bg-amber-500/5' :
    'text-red-400 border-red-500/20 bg-red-500/5';

  const getCategoryCount = (cat: SecCategory) => {
    return findings.filter(f => f.category === cat).length;
  };

  const getCategorySeverity = (cat: SecCategory) => {
    const catFindings = findings.filter(f => f.category === cat);
    if (catFindings.length === 0) return 'SECURE';
    if (catFindings.some(f => f.severity === 'critical' || f.severity === 'high')) return 'HIGH RISK';
    if (catFindings.some(f => f.severity === 'medium')) return 'MODERATE';
    return 'LOW RISK';
  };

  const getCategoryColor = (cat: SecCategory) => {
    const status = getCategorySeverity(cat);
    if (status === 'SECURE') return 'text-[#22c55e] border-[#22c55e]/20 bg-[#22c55e]/5';
    if (status === 'HIGH RISK') return 'text-red-400 border-red-500/20 bg-red-500/5';
    if (status === 'MODERATE') return 'text-amber-400 border-amber-500/20 bg-amber-500/5';
    return 'text-blue-400 border-blue-500/20 bg-blue-500/5';
  };

  const categoryTabLabels = [
    { key: 'SAST' as const, label: 'SAST', icon: Code, term: 'Static Analysis' },
    { key: 'DAST' as const, label: 'DAST', icon: Globe, term: 'Dynamic Audit' },
    { key: 'IAST' as const, label: 'IAST', icon: Zap, term: 'Interactive Policies' },
    { key: 'SCA' as const, label: 'SCA', icon: Package, term: 'Composition Review' },
    { key: 'EASM' as const, label: 'EASM', icon: Grid, term: 'Attack Surface' },
    { key: 'API_SEC' as const, label: 'API SEC', icon: Server, term: 'API Security Testing' },
    { key: 'RED_TEAM' as const, label: 'RED TEAM', icon: Terminal, term: 'Red Team Active Probes' },
  ];

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
              onClick={handleDownloadPdf}
              className="px-3.5 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa] hover:text-white text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer"
              id="report-download-btn"
            >
              <Download className="w-3.5 h-3.5 text-[#52525b]" />
              <span>Download PDF Report</span>
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
                    <span className={`text-xl font-mono font-black block mt-1 ${scan.score > previousScan.score ? 'text-green-500' : scan.score < previousScan.score ? 'text-red-500' : 'text-zinc-500'}`}>
                      {scan.score > previousScan.score ? '+' : ''}{scan.score - previousScan.score}
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
              <div className={`p-4 rounded border flex items-center space-x-5 h-full shrink-0 ${scoreColorClass}`}>
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
              const count = getCategoryCount(cat.key);
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

            <button
              onClick={() => setActiveTab('compliance')}
              className={`px-5 py-4 border-b-2 text-xs font-mono uppercase tracking-wider font-semibold transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
                activeTab === 'compliance'
                  ? 'border-[#22c55e] text-white font-bold bg-black/40'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              <FileText className={`w-4 h-4 ${activeTab === 'compliance' ? 'text-[#22c55e]' : 'text-[#52525b]'}`} />
              <span>[+] Compliance Report</span>
            </button>
          </div>

          <div className="p-6">
            
            {/* OVERVIEW TAB RENDERER */}
            {activeTab === 'OVERVIEW' && (
              <div className="space-y-6 animate-fade-in">
                
                {/* Executive Assessment summary */}
                <div className="bg-black/40 p-5 rounded border border-[#27272a] relative">
                  <div className="absolute right-4 top-4 font-mono text-[9px] text-[#22c55e] uppercase border border-[#22c55e]/30 px-2 py-0.5 rounded flex items-center space-x-1 select-none">
                    <Sparkles className="w-3 h-3" />
                    <span>AI-Powered Analysis</span>
                  </div>
                  <h3 className="text-xs font-bold font-mono text-white mb-2 uppercase tracking-wider flex items-center space-x-1.5">
                    <span>Executive Summary</span>
                  </h3>
                  <p className="text-zinc-300 text-xs font-mono leading-relaxed prose-invert">
                    {scan.aiSummary || 'Security pipeline completed. Report compiles diagnostics...'}
                  </p>
                </div>

                {/* Grid layout of the security pillars */}
                <div className="space-y-3">
                  <h4 className="text-[10px] font-mono text-[#52525b] uppercase tracking-wider pl-1 font-bold">Dynamic Application Security & Pen-Testing Pillars</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                    {categoryTabLabels.map(cell => {
                      const count = getCategoryCount(cell.key);
                      const stateText = getCategorySeverity(cell.key);
                      const colorClass = getCategoryColor(cell.key);

                      return (
                        <div 
                          key={cell.key}
                          onClick={() => setActiveTab(cell.key)}
                          className={`p-4 rounded border transition-all cursor-pointer hover:border-[#3f3f46] hover:bg-black/40 ${colorClass}`}
                        >
                          <div className="flex justify-between items-start mb-2">
                            <cell.icon className="w-5 h-5 opacity-80" />
                            <span className="text-[10px] uppercase font-mono tracking-wider font-extrabold">{cell.label}</span>
                          </div>
                          <span className="text-[9px] font-mono text-zinc-500 block uppercase font-bold">{cell.term}</span>
                          <div className="mt-3 flex items-baseline justify-between">
                            <span className="text-[10px] font-mono font-semibold">{stateText}</span>
                            <span className="text-lg font-mono font-black">{count}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Additional Technical Metadata parameters bento box */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
                    <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Network & Attack Surface (EASM)</h5>
                    <div className="font-mono text-xs space-y-2 text-zinc-400">
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">Target Host:</span>
                        <span className="text-zinc-300 truncate max-w-[180px]">{(() => { try { return new URL(scan.url.startsWith('http') ? scan.url : `https://${scan.url}`).hostname; } catch { return scan.url; } })()}</span>
                      </div>
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">Transport Security:</span>
                        <span className={findings.some(f => f.category === 'EASM' && /ssl|tls|https/i.test(f.title)) ? 'text-[#f87171]' : 'text-[#22c55e]'}>
                          {findings.some(f => f.category === 'EASM' && /ssl|tls|https/i.test(f.title)) ? 'Issues detected' : 'Secure (HTTPS)'}
                        </span>
                      </div>
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">EASM Findings:</span>
                        <span className="text-zinc-300">{findings.filter(f => f.category === 'EASM').length} issue{findings.filter(f => f.category === 'EASM').length !== 1 ? 's' : ''} detected</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#52525b]">DNS / Subdomains:</span>
                        <span className="text-[#52525b] italic">Run EASM tab for full recon</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
                    <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Dynamic Probes Executed (DAST)</h5>
                    <div className="font-mono text-xs space-y-2 text-zinc-400">
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">Injection probes:</span>
                        <span className="text-zinc-300">SQLi, XSS, SSTI, CRLF, LFI</span>
                      </div>
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">Header analysis:</span>
                        <span className="text-zinc-300">HSTS, CSP, X-Frame, CORS, Referrer</span>
                      </div>
                      <div className="flex justify-between border-b border-[#27272a]/40 pb-1.5">
                        <span className="text-[#52525b]">Redirect / CORS:</span>
                        <span className="text-zinc-300">Open redirect, origin reflection</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#52525b]">DAST findings:</span>
                        <span className="text-zinc-300">{findings.filter(f => f.category === 'DAST').length} issue{findings.filter(f => f.category === 'DAST').length !== 1 ? 's' : ''} detected</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Total vulnerabilities warning banner */}
                {findings.length > 0 && (
                  <div className="bg-red-950/20 border border-red-500/20 rounded p-4 flex items-center space-x-3">
                    <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
                    <div>
                      <p className="text-xs text-white font-mono font-bold uppercase tracking-wide">Dynamic Perimeter Warning Summary</p>
                      <p className="text-[11px] font-mono text-red-300/80 mt-0.5 leading-relaxed">
                        Assessors detected {findings.length} actionable vulnerabilities. Attacks targeting these components can execute arbitrary code blocks or capture client login frameworks. Fix configurations immediately.
                      </p>
                    </div>
                  </div>
                )}

              </div>
            )}

            {/* DYNAMIC PER MODULE FINDINGS RENDERER */}
            {activeTab !== 'OVERVIEW' && activeTab !== 'compliance' && (
              <div className="space-y-6 animate-fade-in">
                
                {/* Module title cards */}
                <div className="flex items-center justify-between border-b border-[#27272a] pb-4">
                  <div>
                    <h4 className="text-white text-sm font-bold font-mono tracking-tight uppercase flex items-center space-x-2">
                      {React.createElement(categoryTabLabels.find(c => c.key === activeTab)?.icon || Shield, { className: 'w-5 h-5 text-[#22c55e]' })}
                      <span>{categoryTabLabels.find(c => c.key === activeTab)?.label} Module Findings</span>
                    </h4>
                    <span className="text-[10px] font-mono text-[#52525b] uppercase mt-1 block">
                      {categoryTabLabels.find(c => c.key === activeTab)?.term}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-400 block uppercase font-extrabold bg-[#18181b] border border-[#27272a] px-2.5 py-1">
                    Risk Assessment: {getCategorySeverity(activeTab)}
                  </span>
                </div>

                {/* Filtered list of findings */}
                {findings.filter(f => f.category === activeTab).length === 0 ? (
                  <div className="text-center py-16 bg-black/40 rounded border border-dashed border-[#27272a] flex flex-col items-center">
                    <CheckCircle2 className="w-10 h-10 text-[#22c55e] mb-3" />
                    <span className="text-xs text-white font-bold font-mono uppercase block">Zero Vulnerabilities Outstanding</span>
                    <p className="text-[11px] text-[#52525b] mt-1.5 font-mono max-w-md">
                      Your current configurations satisfy standard defensive criteria in {categoryTabLabels.find(c => c.key === activeTab)?.term}.
                    </p>
                    <div className="mt-5 grid grid-cols-2 gap-3 max-w-sm w-full font-mono text-[9px] text-[#52525b] text-left">
                      <div className="flex items-center space-x-1">
                        <Check className="w-3 h-3 text-[#22c55e]" />
                        <span>Hardening complete</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <Check className="w-3 h-3 text-[#22c55e]" />
                        <span>Continuous evaluation active</span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {findings.filter(f => f.category === activeTab).map(finding => {
                      let severityColor = 'bg-black text-[#52525b] border border-[#27272a]';
                      if (finding.isFalsePositive) severityColor = 'bg-zinc-800 text-zinc-400 border border-zinc-700/60 font-medium';
                      else if (finding.severity === 'critical') severityColor = 'bg-red-500/10 border border-red-500/25 text-red-400 font-bold';
                      else if (finding.severity === 'high') severityColor = 'bg-red-500/10 border border-red-500/20 text-rose-400';
                      else if (finding.severity === 'medium') severityColor = 'bg-amber-500/10 border border-amber-500/20 text-amber-400';
                      else if (finding.severity === 'low') severityColor = 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/25';

                      return (
                        <div 
                          key={finding.id} 
                          className={`border rounded p-5 transition-colors shadow ${
                            finding.isFalsePositive 
                              ? 'bg-[#0f0f11]/60 border-zinc-800 border-dashed opacity-70 hover:border-zinc-750' 
                              : 'bg-black border-[#27272a]/90 hover:border-[#3f3f46]'
                          }`}
                        >
                          
                          {/* Title element */}
                          <div className="flex flex-wrap items-start justify-between gap-2 mb-3">
                            <div className="flex items-center space-x-2.5">
                              <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded ${severityColor}`}>
                                {finding.isFalsePositive ? 'SUPPRESSED (FP)' : finding.severity}
                              </span>
                              {finding.confidence && (
                                <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded border bg-black ${
                                  finding.confidence === 'high' ? 'border-[#22c55e]/30 text-[#22c55e]' :
                                  finding.confidence === 'medium' ? 'border-amber-500/30 text-amber-500' :
                                  'border-zinc-500/30 text-zinc-500'
                                }`}>
                                  Conf: {finding.confidence}
                                </span>
                              )}
                              <h5 className={`text-xs font-bold font-mono tracking-tight leading-snug ${finding.isFalsePositive ? 'text-zinc-500 line-through' : 'text-white'}`}>{finding.title}</h5>
                            </div>
                            <span className="text-[10px] text-[#52525b] font-mono tracking-wide">ID: {finding.id}</span>
                          </div>

                          {/* Detail summary */}
                          <p className={`text-xs font-mono leading-relaxed mb-3 pl-1 ${finding.isFalsePositive ? 'text-zinc-500' : 'text-[#a1a1aa]'}`}>
                            {finding.description}
                          </p>

                          {/* Plain English impact — visible to solo devs */}
                          {finding.plainEnglish && (
                            <div className="mb-4 pl-1 py-2.5 px-3 rounded border border-[#22c55e]/15 bg-[#22c55e]/5 flex items-start space-x-2">
                              <span className="text-[#22c55e] font-mono text-[9px] uppercase tracking-wider font-bold shrink-0 mt-0.5">What this means:</span>
                              <p className="text-[#a1a1aa] text-[11px] font-sans leading-relaxed">{finding.plainEnglish}</p>
                            </div>
                          )}

                          {/* Remediation fix */}
                          <div className={`p-4 rounded border ${finding.isFalsePositive ? 'bg-zinc-950/40 border-zinc-850' : 'bg-[#0c0c0e] border-[#27272a]'}`}>
                            <div className="flex justify-between items-center mb-1.5">
                              <span className="text-[#52525b] font-mono text-[9px] uppercase tracking-wider">Remediation Steps</span>
                              <button
                                onClick={() => handleCopyCode(finding.id, finding.fix)}
                                className="text-[10px] font-mono text-[#52525b] hover:text-[#22c55e] flex items-center space-x-1 transition-colors cursor-pointer"
                              >
                                {copiedCodeId === finding.id ? (
                                  <>
                                    <Check className="w-3 h-3 text-[#22c55e] shrink-0" />
                                    <span>Copied fix</span>
                                  </>
                                ) : (
                                  <>
                                    <Clipboard className="w-3 h-3 text-[#52525b] shrink-0" />
                                    <span>Copy directive</span>
                                  </>
                                )}
                              </button>
                            </div>
                            <div className="overflow-x-auto max-h-48 scrollbar-thin">
                              <code className={`text-[11px] font-mono whitespace-pre leading-relaxed block py-1 ${finding.isFalsePositive ? 'text-zinc-600' : 'text-zinc-300'}`}>
                                {finding.fix}
                              </code>
                            </div>
                          </div>

                          {/* Code fix example */}
                          {finding.codeFixExample && (
                            <div className="mt-3 p-4 rounded border border-[#27272a] bg-black">
                              <div className="flex justify-between items-center mb-2">
                                <span className="text-[#22c55e] font-mono text-[9px] uppercase tracking-wider font-bold flex items-center space-x-1.5">
                                  <Code className="w-3 h-3" />
                                  <span>Code Fix Example</span>
                                </span>
                                <button
                                  onClick={() => handleCopyCode(`code-${finding.id}`, finding.codeFixExample!)}
                                  className="text-[10px] font-mono text-[#52525b] hover:text-[#22c55e] flex items-center space-x-1 transition-colors cursor-pointer"
                                >
                                  {copiedCodeId === `code-${finding.id}` ? (
                                    <><Check className="w-3 h-3 text-[#22c55e] shrink-0" /><span>Copied</span></>
                                  ) : (
                                    <><Clipboard className="w-3 h-3 shrink-0" /><span>Copy code</span></>
                                  )}
                                </button>
                              </div>
                              <div className="overflow-x-auto max-h-56 scrollbar-thin">
                                <code className="text-[11px] font-mono whitespace-pre leading-relaxed block py-1 text-[#22c55e]/80">
                                  {finding.codeFixExample}
                                </code>
                              </div>
                            </div>
                          )}

                          {/* Raw Request / Response Collapsible Drawer for API_SEC / Payload details */}
                          {(finding.rawRequest || finding.rawResponse) && (
                            <div className="mt-3">
                              <button 
                                onClick={() => setExpandedApiRows(p => ({ ...p, [finding.id]: !p[finding.id] }))}
                                className="w-full flex items-center justify-between p-3 rounded bg-zinc-950/40 hover:bg-zinc-900 border border-zinc-800/80 transition-colors cursor-pointer group"
                              >
                                <span className="flex items-center space-x-2 text-[10px] font-mono text-zinc-400 group-hover:text-amber-400 transition-colors uppercase tracking-wider font-bold">
                                  <Terminal className="w-3.5 h-3.5 shrink-0" />
                                  <span>Raw HTTP Probes & Response Dump</span>
                                </span>
                                {expandedApiRows[finding.id] ? <ChevronUp className="w-4 h-4 text-zinc-500" /> : <ChevronDown className="w-4 h-4 text-zinc-500" />}
                              </button>
                              
                              {expandedApiRows[finding.id] && (
                                <div className="mt-2 space-y-2 animate-fade-in">
                                  {finding.endpoint && (
                                    <div className="p-3 bg-black border border-zinc-800 rounded font-mono text-[10px] text-zinc-300 overflow-x-auto">
                                      <span className="text-zinc-500 select-none block mb-1">Target Endpoint:</span>
                                      {finding.endpoint}
                                    </div>
                                  )}
                                  
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                    {finding.rawRequest && (
                                      <div className="p-3 bg-black border border-zinc-800 rounded relative overflow-hidden group">
                                        <div className="absolute top-0 left-0 w-full bg-zinc-900/80 p-1.5 border-b border-zinc-800 text-[9px] uppercase tracking-wider font-mono text-amber-500/80 flex items-center justify-between">
                                          <span>Raw Request</span>
                                          <button onClick={() => handleCopyCode(`req-${finding.id}`, finding.rawRequest!)} className="text-zinc-500 hover:text-white cursor-pointer"><Copy className="w-3 h-3"/></button>
                                        </div>
                                        <div className="pt-6 overflow-x-auto max-h-64 scrollbar-thin">
                                          <code className="text-[10px] font-mono whitespace-pre text-zinc-400 break-all">{finding.rawRequest}</code>
                                        </div>
                                      </div>
                                    )}
                                    {finding.rawResponse && (
                                      <div className="p-3 bg-black border border-zinc-800 rounded relative overflow-hidden group">
                                        <div className="absolute top-0 left-0 w-full bg-zinc-900/80 p-1.5 border-b border-zinc-800 text-[9px] uppercase tracking-wider font-mono text-red-400/80 flex items-center justify-between">
                                          <span>Raw Response</span>
                                          <button onClick={() => handleCopyCode(`res-${finding.id}`, finding.rawResponse!)} className="text-zinc-500 hover:text-white cursor-pointer"><Copy className="w-3 h-3"/></button>
                                        </div>
                                        <div className="pt-6 overflow-x-auto max-h-64 scrollbar-thin">
                                          <code className="text-[10px] font-mono whitespace-pre text-zinc-400 break-all">{finding.rawResponse}</code>
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}

                          {/* False Positives Management UI Drawer Toggle */}
                          <div className="mt-4 border-t border-[#27272a]/30 pt-3 flex flex-col">
                            {suppressInputId === finding.id ? (
                              <div className="bg-[#121214] border border-[#27272a]/80 p-3.5 rounded space-y-3 animate-fade-in">
                                <label className="text-[10px] font-mono uppercase tracking-wider text-amber-500/90 font-bold block">
                                  Define Suppression Justification (Audit Trail)
                                </label>
                                <p className="text-[11px] text-[#52525b] font-mono">
                                  By declaring this finding a false positive or an excluded risk, its impact is subtracted from the final security score and rating, and the exemption will apply to future scans of this URL.
                                </p>
                                <input
                                  type="text"
                                  autoFocus
                                  placeholder="e.g. Host-level firewalls handle payload blocking / acceptable legacby boundary match."
                                  value={suppressReason}
                                  onChange={(e) => setSuppressReason(e.target.value)}
                                  className="w-full bg-black border border-[#27272a] rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-[#22c55e] placeholder-zinc-700"
                                />
                                {suppressError && (
                                  <p className="text-[10px] font-mono text-red-400">{suppressError}</p>
                                )}
                                <div className="flex justify-end space-x-2">
                                  <button
                                    onClick={() => { setSuppressInputId(null); setSuppressError(null); }}
                                    className="px-2.5 py-1.5 border border-[#27272a] text-[#a1a1aa] hover:text-white bg-zinc-900 hover:bg-zinc-800 text-[10px] font-mono uppercase rounded cursor-pointer transition-all"
                                  >
                                    Close
                                  </button>
                                  <button
                                    onClick={() => handleSaveSuppression(finding)}
                                    disabled={isSuppressing}
                                    className="px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/35 text-[10px] font-mono uppercase rounded font-bold cursor-pointer transition-all"
                                  >
                                    {isSuppressing ? 'Processing...' : 'Suppress Finding'}
                                  </button>
                                </div>
                              </div>
                            ) : (
                              <div className="flex justify-between items-center">
                                {finding.isFalsePositive ? (
                                  <div className="flex items-center justify-between w-full bg-zinc-900/40 border border-dashed border-zinc-800/80 px-3.5 py-2 rounded">
                                    <p className="text-[11px] font-mono text-zinc-500 flex items-center space-x-1.5">
                                      <AlertTriangle className="w-3.5 h-3.5 text-zinc-600 shrink-0" />
                                      <span><strong>Exempted Risk:</strong> {finding.suppressionReason || 'Declared acceptable false positive risk.'}</span>
                                    </p>
                                    <button
                                      disabled={isSuppressing}
                                      onClick={() => handleRemoveSuppressionDirectly(finding.title)}
                                      className="text-[10px] font-mono text-red-400 hover:text-red-300 underline cursor-pointer select-none transition-colors"
                                    >
                                      Remove Exemption
                                    </button>
                                  </div>
                                ) : (
                                  <>
                                    <span className="text-[10px] font-mono text-[#52525b]">Is this threat checked or invalid?</span>
                                    <button
                                      onClick={() => { setSuppressInputId(finding.id); setSuppressReason(''); setSuppressError(null); }}
                                      className="px-2.5 py-1 bg-zinc-900 border border-zinc-800/80 hover:border-amber-500/20 text-[#71717a] hover:text-amber-400 text-[10px] font-mono uppercase tracking-wider transition-all flex items-center space-x-1.5 cursor-pointer"
                                    >
                                      <AlertTriangle className="w-3.5 h-3.5" />
                                      <span>Mark False Positive</span>
                                    </button>
                                  </>
                                )}
                              </div>
                            )}
                          </div>

                        </div>
                      );
                    })}
                  </div>
                )}

              </div>
            )}

            {/* COMPLIANCE TAB */}
            {activeTab === 'compliance' && (() => {
              const activeFindings = findings.filter(f => !f.isFalsePositive);

              // Helper: check if any finding matches keyword list at high/critical severity
              const checkFail = (keywords: string[]) =>
                activeFindings.some(f =>
                  (f.severity === 'high' || f.severity === 'critical') &&
                  keywords.some(kw =>
                    f.title.toLowerCase().includes(kw.toLowerCase()) ||
                    f.description.toLowerCase().includes(kw.toLowerCase())
                  )
                );

              // PCI-DSS 4.0 requirements
              const pciReqs: { id: string; name: string; status: 'PASS' | 'FAIL' | 'WARN'; auto?: string }[] = [
                {
                  id: 'Req 4.2.1',
                  name: 'Strong Cryptography',
                  status: checkFail(['TLS', 'SSL', 'certificate', 'HSTS', 'expired']) ? 'FAIL' : 'PASS',
                },
                {
                  id: 'Req 6.2.4',
                  name: 'Protect Against Known Attacks',
                  status: checkFail(['injection', 'XSS', 'cross-site', 'SSTI', 'template', 'traversal', 'command']) ? 'FAIL' : 'PASS',
                },
                {
                  id: 'Req 6.3.2',
                  name: 'Software Component Inventory',
                  status: checkFail(['jQuery', 'Bootstrap', 'Lodash', 'AngularJS', 'outdated', 'library']) ? 'FAIL' : 'PASS',
                },
                {
                  id: 'Req 8.2.1',
                  name: 'User Authentication Controls',
                  status: checkFail(['CORS', 'cookie', 'session', 'authentication', 'bypass', 'credential']) ? 'FAIL' : 'PASS',
                },
                {
                  id: 'Req 11.3.2',
                  name: 'External Vulnerability Scans',
                  status: 'PASS',
                  auto: 'This scan satisfies the requirement',
                },
                {
                  id: 'Req 11.4.1',
                  name: 'Penetration Testing',
                  status: 'PASS',
                  auto: 'This scan satisfies the requirement',
                },
              ];

              // SOC2 Trust Service Criteria
              const soc2Reqs: { id: string; name: string; status: 'PASS' | 'FAIL' | 'WARN'; auto?: string }[] = [
                {
                  id: 'CC6.1',
                  name: 'Logical Access Controls',
                  status: checkFail(['CORS', 'authentication', 'bypass', 'IDOR', 'access control']) ? 'FAIL' : 'PASS',
                },
                {
                  id: 'CC6.6',
                  name: 'Logical Access Threats',
                  status: checkFail(['injection', 'XSS', 'SSRF', 'traversal', 'command']) ? 'FAIL' : 'PASS',
                },
                {
                  id: 'CC7.1',
                  name: 'Vulnerability Detection',
                  status: 'PASS',
                  auto: 'This scan satisfies the requirement',
                },
                {
                  id: 'CC8.1',
                  name: 'Change Management',
                  status: checkFail(['outdated', 'library', 'jQuery', 'Bootstrap', 'SCA']) ? 'FAIL' : 'PASS',
                },
                {
                  id: 'CC9.2',
                  name: 'Risk Monitoring',
                  status: (scan.score ?? 100) >= 70 ? 'PASS' : 'WARN',
                  auto: (scan.score ?? 100) >= 70 ? 'Score meets threshold' : `Score ${scan.score ?? 100}/100 is below the 70-point threshold`,
                },
              ];

              const pciFails = pciReqs.filter(r => r.status === 'FAIL').length;
              const soc2Fails = soc2Reqs.filter(r => r.status === 'FAIL').length;

              const badgeClass = (status: 'PASS' | 'FAIL' | 'WARN') => {
                if (status === 'PASS') return 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/20';
                if (status === 'FAIL') return 'bg-red-900/20 text-[#f87171] border border-red-900/40';
                return 'bg-amber-900/20 text-amber-400 border border-amber-900/40';
              };

              const ComplianceTable = ({ rows }: { rows: typeof pciReqs }) => (
                <table className="w-full text-xs font-mono border-collapse">
                  <thead>
                    <tr className="border-b border-[#27272a]">
                      <th className="text-left py-2 px-3 text-[#52525b] uppercase tracking-wider text-[10px] font-bold w-28">Req ID</th>
                      <th className="text-left py-2 px-3 text-[#52525b] uppercase tracking-wider text-[10px] font-bold">Criterion</th>
                      <th className="text-right py-2 px-3 text-[#52525b] uppercase tracking-wider text-[10px] font-bold w-24">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map(req => (
                      <tr key={req.id} className="border-b border-[#27272a]/40 hover:bg-black/20 transition-colors">
                        <td className="py-2.5 px-3 text-[#a1a1aa]">{req.id}</td>
                        <td className="py-2.5 px-3 text-[#a1a1aa]">
                          {req.name}
                          {req.auto && (
                            <span className="ml-2 text-[#52525b] text-[10px]">— {req.auto}</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${badgeClass(req.status)}`}>
                            {req.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              );

              return (
                <div className="space-y-8 animate-fade-in">

                  {/* PCI-DSS 4.0 Section */}
                  <div className="bg-[#0c0c0e] border border-[#27272a] rounded overflow-hidden">
                    <div className="px-5 py-4 border-b border-[#27272a] flex items-center justify-between">
                      <div>
                        <h4 className="text-white text-xs font-bold font-mono uppercase tracking-wider">PCI-DSS 4.0 Requirements</h4>
                        <p className="text-[#52525b] text-[10px] font-mono mt-0.5">Payment Card Industry Data Security Standard — mapped from scan findings</p>
                      </div>
                      {pciFails > 0 ? (
                        <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-red-900/20 text-[#f87171] border border-red-900/40 font-bold">
                          {pciFails} failing requirement{pciFails !== 1 ? 's' : ''}
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/20 font-bold">
                          All requirements passing
                        </span>
                      )}
                    </div>
                    <div className="px-2 py-2">
                      <ComplianceTable rows={pciReqs} />
                    </div>
                  </div>

                  {/* SOC2 Section */}
                  <div className="bg-[#0c0c0e] border border-[#27272a] rounded overflow-hidden">
                    <div className="px-5 py-4 border-b border-[#27272a] flex items-center justify-between">
                      <div>
                        <h4 className="text-white text-xs font-bold font-mono uppercase tracking-wider">SOC2 Trust Service Criteria</h4>
                        <p className="text-[#52525b] text-[10px] font-mono mt-0.5">Service Organization Controls — mapped from scan findings</p>
                      </div>
                      {soc2Fails > 0 ? (
                        <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-red-900/20 text-[#f87171] border border-red-900/40 font-bold">
                          {soc2Fails} failing criterion{soc2Fails !== 1 ? 'a' : ''}
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/20 font-bold">
                          All criteria passing
                        </span>
                      )}
                    </div>
                    <div className="px-2 py-2">
                      <ComplianceTable rows={soc2Reqs} />
                    </div>
                  </div>

                  {/* Export disclaimer */}
                  <p className="text-[#52525b] text-[10px] font-mono text-center leading-relaxed">
                    This compliance mapping is auto-generated from scan findings. Engage a qualified assessor for formal certification.
                  </p>

                </div>
              );
            })()}

          </div>
        </div>

        {/* Raw Header Output Inspection drawer */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
          <button
            onClick={() => setShowRaw(!showRaw)}
            className="w-full flex items-center justify-between text-[#a1a1aa] hover:text-white font-mono text-xs uppercase tracking-wider cursor-pointer"
          >
            <div className="flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-[#22c55e]" />
              <span>Diagnostic Raw Headers & Outputs</span>
            </div>
            {showRaw ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {showRaw && (
            <div className="mt-5 space-y-4 pt-4 border-t border-[#27272a] animate-fade-in">
              <p className="text-[#52525b] text-[11px] leading-relaxed font-mono">
                Captured directly from the live scan of {scan.url}. These are the actual request, DNS, path-probe, and response values observed by the scanner.
              </p>

              {!scan.diagnostics ? (
                <div className="bg-black p-4 rounded font-mono text-[11px] text-[#52525b] border border-[#27272a]">
                  Raw diagnostics are not available for this scan. Re-run the scan to capture live trace data.
                </div>
              ) : (
                <div className="bg-black p-4 rounded font-mono text-[10px] text-zinc-400 space-y-2 border border-[#27272a] max-h-96 overflow-y-auto">
                  <span className="text-[#52525b] text-[9px] uppercase font-bold block mb-1">Outbound request</span>
                  <p className="text-zinc-200">GET {(() => { try { return new URL(scan.url.startsWith('http') ? scan.url : `https://${scan.url}`).pathname || '/'; } catch { return '/'; } })()} HTTP/1.1</p>
                  <p className="text-zinc-200">Host: {scan.url.replace(/https?:\/\//i, '').replace(/\/.*$/, '')}</p>
                  {Object.entries(scan.diagnostics.requestHeaders).map(([k, v]) => (
                    <p key={k} className="text-[#52525b]">{k}: {v}</p>
                  ))}

                  <p className="text-[#22c55e] font-bold mt-3">{'[EASM — DNS & ATTACK SURFACE]'}</p>
                  <p className="text-zinc-400">Target host: {scan.url}</p>
                  <p className="text-zinc-400">Resolved IP: {scan.diagnostics.ip}</p>
                  <p className="text-zinc-400">Nameserver: {scan.diagnostics.nameserver}</p>
                  <p className="text-zinc-400">Transport: {scan.diagnostics.protocol}</p>
                  <p className="text-zinc-400">Live subdomains discovered: {scan.diagnostics.liveSubdomains}</p>
                  {scan.diagnostics.techLeaked.length > 0 && (
                    <p className="text-amber-400">Tech signatures leaked: {scan.diagnostics.techLeaked.join(', ')}</p>
                  )}

                  <p className="text-[#22c55e] font-bold mt-3">{'[DAST — SENSITIVE PATH PROBES]'}</p>
                  {scan.diagnostics.probedPaths.length > 0 ? (
                    scan.diagnostics.probedPaths.map((p, i) => (
                      <p key={i} className="text-zinc-200">
                        Path: <span className="text-amber-400">{p.path}</span> — Status: {p.status || 'no response'}{' '}
                        <span className={p.exposed ? 'text-red-500 font-bold' : 'text-[#22c55e]'}>
                          {p.exposed ? '(EXPOSED)' : '(protected)'}
                        </span>
                      </p>
                    ))
                  ) : (
                    <p className="text-zinc-500">No path-probe data captured.</p>
                  )}

                  <p className="text-[#22c55e] font-bold mt-4">{'[HTTP RESPONSE]'}</p>
                  <p className="text-zinc-300">Status: {scan.diagnostics.responseStatus || 'no response'}</p>
                  {Object.entries(scan.diagnostics.responseHeaders).length > 0 ? (
                    Object.entries(scan.diagnostics.responseHeaders).map(([k, v]) => (
                      <p key={k} className="text-zinc-300">{k}: {v}</p>
                    ))
                  ) : (
                    <p className="text-zinc-500">No response headers captured.</p>
                  )}

                  <p className="text-[#22c55e] font-bold mt-4">{'[SECURITY HEADER CONTROLS]'}</p>
                  {scan.diagnostics.missingHeaders.length > 0 ? (
                    scan.diagnostics.missingHeaders.map((h, i) => (
                      <p key={i} className="text-zinc-450">{h}: <span className="text-red-400">ABSENT</span></p>
                    ))
                  ) : (
                    <p className="text-[#22c55e]">All standard security headers present.</p>
                  )}

                  <p className="text-red-500 font-bold mt-4">{'[RED TEAM ACTIVE PROBES]'}</p>
                  {findings.filter(f => f.category === 'RED_TEAM').length > 0 ? (
                    findings.filter(f => f.category === 'RED_TEAM').map((f, i) => (
                      <p key={i} className="text-zinc-300">{`${f.title} → ${f.severity.toUpperCase()}`}</p>
                    ))
                  ) : (
                    <p className="text-zinc-300">No active exploit signatures confirmed.</p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
