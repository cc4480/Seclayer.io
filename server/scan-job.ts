import { LocalFileDb } from './db.js';
import { runDiagnostics, compileStaticFindings } from './scanner.js';
import { runCrawl } from './crawler.js';
import { generateAiReport } from './ai.js';
import { buildScanDiagnostics, mergeCrawl } from './scan-pipeline-helpers.js';
import type { Scan } from '../src/types.js';

export interface ScanJobRunner {
  processScanJob: (scanId: string) => Promise<void>;
  fireWebhook: (scan: Scan, status: 'complete' | 'failed') => Promise<void>;
}

/** Bundles the scan pipeline closures that need access to a specific LocalFileDb instance. */
export function createScanJobRunner(dbInstance: LocalFileDb): ScanJobRunner {
  async function fireWebhook(scan: Scan, status: 'complete' | 'failed') {
    if (!scan.webhookUrl) return;
    try {
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 10000);
      const findings = scan.findings ?? [];
      const payload = {
        event: `scan.${status}`,
        scanId: scan.id,
        url: scan.url,
        status,
        score: scan.score ?? null,
        severity: scan.severity ?? null,
        findingCount: findings.length,
        criticalCount: findings.filter(f => f.severity === 'critical' && !f.isFalsePositive).length,
        highCount: findings.filter(f => f.severity === 'high' && !f.isFalsePositive).length,
        mediumCount: findings.filter(f => f.severity === 'medium' && !f.isFalsePositive).length,
        lowCount: findings.filter(f => f.severity === 'low' && !f.isFalsePositive).length,
        completedAt: scan.completedAt ?? new Date().toISOString(),
        error: scan.error ?? null,
      };
      await fetch(scan.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'Seclayer-Webhook/1.0' },
        body: JSON.stringify(payload),
        signal: ctrl.signal,
      });
    } catch (err: any) {
      console.warn(`[Webhook] Delivery failed for scan ${scan.id}: ${err.message}`);
    }
  }

  async function processScanJob(scanId: string) {
    try {
      dbInstance.appendScanLog(scanId, '[SYSTEM] Scan job started');
      dbInstance.updateScan(scanId, { status: 'scanning' });

      const scan = dbInstance.getScan(scanId);
      if (!scan) return;

      dbInstance.appendScanLog(scanId, `[SCANNER] Running diagnostics against ${scan.url}`);
      const diagnostics = await runDiagnostics(scan.url, scan.authHeader);

      dbInstance.appendScanLog(scanId, `[SCANNER] HTTP ${diagnostics.responseStatus} — SSL: ${diagnostics.sslSecure ? 'valid' : 'insecure'}`);
      if (diagnostics.missingHeaders.length > 0) {
        dbInstance.appendScanLog(scanId, `[HEADERS] Missing security headers: ${diagnostics.missingHeaders.join(', ')}`);
      }
      if (diagnostics.techLeaked.length > 0) {
        dbInstance.appendScanLog(scanId, `[EASM] Technology signatures exposed: ${diagnostics.techLeaked.join(', ')}`);
      }
      if (diagnostics.probedPaths.some(p => p.exposed)) {
        const exposed = diagnostics.probedPaths.filter(p => p.exposed).map(p => p.path);
        dbInstance.appendScanLog(scanId, `[DAST] Exposed sensitive paths: ${exposed.join(', ')}`);
      }

      dbInstance.appendScanLog(scanId, '[AI] Compiling static findings and scoring...');
      const staticCompiled = compileStaticFindings(diagnostics);

      // Deep authenticated crawl — maps the application surface and derives
      // business-logic findings (insecure credential forms, missing CSRF,
      // mixed content, IDOR-style object references) the root-page probe misses.
      dbInstance.appendScanLog(scanId, '[CRAWL] Mapping application surface (authenticated deep crawl)...');
      const crawl = await runCrawl(scan.url, {
        authHeader: scan.authHeader,
        onLog: (msg) => dbInstance.appendScanLog(scanId, msg),
      });
      mergeCrawl(staticCompiled, crawl.findings);

      dbInstance.appendScanLog(scanId, '[AI] Forwarding diagnostics to DeepSeek for analysis...');
      dbInstance.updateScan(scanId, { status: 'analyzing' });

      const outputReport = await generateAiReport(scan.url, diagnostics, staticCompiled);

      const completedScan = dbInstance.updateScan(scanId, {
        status: 'complete',
        score: outputReport.score,
        severity: outputReport.severity,
        findings: outputReport.findings,
        aiSummary: outputReport.aiSummary,
        diagnostics: buildScanDiagnostics(diagnostics),
        crawl: crawl.result,
        completedAt: new Date().toISOString(),
      });
      dbInstance.appendScanLog(scanId, `[COMPLETE] Score: ${outputReport.score}/100 — ${outputReport.findings.length} findings`);
      fireWebhook(completedScan, 'complete');
    } catch (err: any) {
      console.error(`[Scanner] Scan ${scanId} failed:`, err.message);
      dbInstance.appendScanLog(scanId, `[ERROR] Scan failed: ${err.message}`);
      const failedScan = dbInstance.updateScan(scanId, {
        status: 'failed',
        error: err.message || 'Scan failed due to an unexpected error.',
      });
      fireWebhook(failedScan, 'failed');
    }
  }

  return { processScanJob, fireWebhook };
}
