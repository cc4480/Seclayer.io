import { Scan, Finding } from '../../types.js';
import { jsPDF } from "jspdf";
import { renderCoverAndPriorityPages } from './pdfCoverPages.js';
import { renderFindingsAndCompliancePages } from './pdfFindingsAndCompliance.js';

export function generatePdfReport(scan: Scan, findings: Finding[]) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const today = new Date().toISOString().split('T')[0];

  const severityRgb = (s: string): [number, number, number] =>
    s === 'critical' ? [239, 68, 68] :
    s === 'high'     ? [249, 115, 22] :
    s === 'medium'   ? [234, 179, 8] :
                       [34, 197, 94];

  const ensureSpace = (currentY: number, needed: number): number => {
    if (currentY + needed > pageHeight - 14) { doc.addPage(); return 20; }
    return currentY;
  };

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

  renderCoverAndPriorityPages(doc, scan, findings, severityRgb, ensureSpace);
  renderFindingsAndCompliancePages(doc, scan, findings, severityRgb);

  addFooters();
  doc.save(`seclayer-report-${scan.url.replace(/https?:\/\//i, '').replace(/[^a-zA-Z0-9]/g, '_')}.pdf`);
}
