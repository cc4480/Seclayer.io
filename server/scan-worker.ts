import { db } from './db.js';
import { runDiagnostics, compileStaticFindings, summarizeDiagnostics } from './scanner.js';
import { generateAiReport } from './deepseek.js';
import { logger } from './logger.js';

/** Background pipeline: runs diagnostics + AI report generation for a queued scan. */
export async function processScanJob(scanId: string) {
  const jobLog = logger.child({ scanId });
  try {
    jobLog.info('scan job started');

    await sleep(1500);
    db.updateScan(scanId, { status: 'scanning' });

    const scan = db.getScan(scanId);
    if (!scan) {
      jobLog.warn('scan disappeared before diagnostics could run');
      return;
    }

    const diagnostics = await runDiagnostics(scan.url, scan.authHeader);

    await sleep(1500);
    db.updateScan(scanId, { status: 'analyzing' });

    const staticCompiled = compileStaticFindings(diagnostics);
    const outputReport = await generateAiReport(scan.url, diagnostics, staticCompiled);

    db.updateScan(scanId, {
      status: 'complete',
      score: outputReport.score,
      severity: outputReport.severity,
      findings: outputReport.findings,
      aiSummary: outputReport.aiSummary,
      diagnostics: summarizeDiagnostics(diagnostics),
      completedAt: new Date().toISOString(),
    });
    jobLog.info('scan job completed', { score: outputReport.score, severity: outputReport.severity });
  } catch (err: unknown) {
    jobLog.error('scan job failed', { err });
    try {
      db.updateScan(scanId, {
        status: 'failed',
        error:
          err instanceof Error
            ? err.message
            : 'An unexpected server timeout occurred during scanner diagnostics.',
      });
    } catch (updateErr) {
      jobLog.error('failed to record scan failure state', { err: updateErr });
    }
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
