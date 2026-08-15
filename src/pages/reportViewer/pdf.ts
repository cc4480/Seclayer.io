import { jsPDF } from "jspdf";
import autoTable from 'jspdf-autotable';
import { Scan, Finding } from '../../types.js';

// Renders and downloads the branded PDF audit report for a completed scan.
export function downloadAuditPdf(scan: Scan, findings: Finding[]): void {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();

  // Brand header
  doc.setFillColor(9, 9, 11);
  doc.rect(0, 0, pageWidth, 40, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.text("SECLAYER", 15, 20);
  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.text("Systematic Penetration Testing & AppSec Report", 15, 28);

  doc.setTextColor(161, 161, 170); // text-zinc-400
  doc.text(`Generated: ${new Date().toISOString().split('T')[0]}`, pageWidth - 15, 25, { align: 'right' });

  // Executive Summary Info Box
  doc.setTextColor(0, 0, 0);
  doc.setFontSize(14);
  doc.setFont("helvetica", "bold");
  doc.text("EXECUTIVE SUMMARY", 15, 55);

  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  doc.text(`Target Assessed: ${scan.url}`, 15, 65);
  doc.text(`Security Posture Score: ${scan.score}/100`, 15, 72);
  const riskSev = scan.severity ? scan.severity.toUpperCase() : 'UNKNOWN';
  doc.text(`Risk Severity: ${scan.score! < 60 ? 'HIGH RISK' : scan.score! < 85 ? 'MODERATE' : 'LOW RISK'} (${riskSev})`, 15, 79);
  doc.text(`Total Vulnerabilities: ${findings.length}`, 15, 86);

  // AI Summary
  let currentY = 96;
  if (scan.aiSummary) {
    doc.setFont("helvetica", "bold");
    doc.text("Assessment Analysis", 15, currentY);
    doc.setFont("helvetica", "normal");
    currentY += 7;
    const splitAiText = doc.splitTextToSize(scan.aiSummary, pageWidth - 30);
    doc.text(splitAiText, 15, currentY);
    currentY += (splitAiText.length * 5) + 15;
  } else {
    currentY = 100;
  }

  // Findings Table
  doc.setFontSize(14);
  doc.setFont("helvetica", "bold");
  doc.text("TECHNICAL FINDINGS & REMEDIATION", 15, currentY);

  const tableBody = findings.map((f, i) => [
    i + 1,
    f.title,
    f.severity.toUpperCase(),
    f.category,
    f.description,
    f.fix
  ]);

  autoTable(doc, {
    startY: currentY + 5,
    head: [['#', 'Vulnerability', 'Severity', 'Module', 'Description', 'Remediation']],
    body: tableBody,
    theme: 'grid',
    styles: { fontSize: 8, cellPadding: 3 },
    headStyles: { fillColor: [9, 9, 11], textColor: [255, 255, 255] },
    columnStyles: {
      0: { cellWidth: 10 },
      1: { cellWidth: 35 },
      2: { cellWidth: 20 },
      3: { cellWidth: 20 },
      4: { cellWidth: 55 },
      5: { cellWidth: 50 },
    },
    didParseCell: function(data) {
      if (data.section === 'body' && data.column.index === 2) {
        // just standard formatting here, custom styles can be complex in some autotable versions, so we use string values
      }
    }
  });

  // Page footer
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text(`Page ${i} of ${pageCount} - Private & Confidential - Enterprise Security Audit Document`, pageWidth / 2, pageHeight - 10, { align: 'center' });
  }

  doc.save(`seclayer-appsec-audit-${scan.url.replace(/https?:\/\//i, '').replace(/[^a-zA-Z0-9]/g, '_')}.pdf`);
}
