import { Scan, Finding } from '../../types.js';
import { jsPDF } from "jspdf";
import autoTable from 'jspdf-autotable';
import { SeverityRgb } from './pdfCoverPages.js';

/**
 * Renders PAGE 3+ (full findings table) and the LAST PAGE (compliance
 * summary — PCI-DSS / SOC2 tables) onto the given jsPDF document.
 */
export function renderFindingsAndCompliancePages(
  doc: jsPDF,
  scan: Scan,
  findings: Finding[],
  severityRgb: SeverityRgb,
) {
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;
  const score = scan.score ?? 100;

  const truncate = (str: string, maxLen: number) =>
    str && str.length > maxLen ? str.slice(0, maxLen - 1) + '…' : (str || '');

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
    head: [['#', 'Vulnerability', 'Severity', 'Status', 'Impact', 'Remediation']],
    body: findings.map((f, i) => [
      String(i + 1),
      f.isFalsePositive ? `${f.title} (SUPPRESSED)` : f.title,
      f.severity.toUpperCase(),
      f.isFalsePositive ? 'SUPPRESSED' : ({ open: 'Open', in_progress: 'In Progress', fixed: 'Fixed', verified: 'Verified' }[f.remediationStatus || 'open']),
      truncate(f.plainEnglish || f.description, 100),
      truncate(f.fix, 100),
    ]),
    theme: 'grid',
    styles: { fontSize: 7.5, cellPadding: 2.5, overflow: 'linebreak' },
    headStyles: { fillColor: [9, 9, 11], textColor: [255, 255, 255], fontStyle: 'bold' },
    alternateRowStyles: { fillColor: [248, 248, 248] },
    columnStyles: {
      0: { cellWidth: 8 },
      1: { cellWidth: 40 },
      2: { cellWidth: 17 },
      3: { cellWidth: 20 },
      4: { cellWidth: 50 },
      5: { cellWidth: 46 },
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
}
