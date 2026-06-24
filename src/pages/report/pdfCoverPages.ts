import { Scan, Finding } from '../../types.js';
import { jsPDF } from "jspdf";

export type SeverityRgb = (s: string) => [number, number, number];
export type EnsureSpace = (currentY: number, needed: number) => number;

/**
 * Renders PAGE 1 (executive cover) and PAGE 2 (priority fixes, if any
 * critical/high findings exist) onto the given jsPDF document.
 */
export function renderCoverAndPriorityPages(
  doc: jsPDF,
  scan: Scan,
  findings: Finding[],
  severityRgb: SeverityRgb,
  ensureSpace: EnsureSpace,
) {
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;
  const today = new Date().toISOString().split('T')[0];
  const score = scan.score ?? 100;

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
}
