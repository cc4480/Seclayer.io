import { db } from './db.js';
import { runDiagnostics, compileStaticFindings, assertScanTargetSafe } from './scanner.js';
import { generateAiReport } from './deepseek.js';
import { notifyScanComplete } from './notify.js';

// --- Background scan worker ---
// Drives a scan through its real lifecycle: status reflects actual work
// boundaries (diagnostics, then AI analysis), with no artificial delays.
export async function processScanJob(scanId: string): Promise<void> {
  try {
    console.log(`[Job Worker] Starting scan ${scanId}`);

    const scan = db.getScan(scanId);
    if (!scan) return;

    // Active diagnostics (HTTP probing, header/secret/SCA/path checks, fuzzing).
    db.updateScan(scanId, { status: 'scanning' });
    const diagnostics = await runDiagnostics(scan.url, scan.authHeader);

    // Compile findings and generate the analysis report.
    db.updateScan(scanId, { status: 'analyzing' });
    const staticCompiled = compileStaticFindings(diagnostics);
    const outputReport = await generateAiReport(scan.url, diagnostics, staticCompiled);

    const completed = db.updateScan(scanId, {
      status: 'complete',
      score: outputReport.score,
      severity: outputReport.severity,
      findings: outputReport.findings,
      aiSummary: outputReport.aiSummary,
      completedAt: new Date().toISOString()
    });
    console.log(`[Job Worker] Completed scan ${scanId}`);

    // Fire the user's alert webhook for actionable results (non-blocking).
    const owner = db.getUser(completed.userId);
    notifyScanComplete(owner?.notifyWebhook, db.getScanWithSuppressedFindings(completed));

  } catch (err: any) {
    console.error(`[Job Worker] FAILED scan ${scanId}:`, err?.message || err);
    db.updateScan(scanId, {
      status: 'failed',
      error: err?.message || 'The scan could not be completed.'
    });
  }
}

// --- Continuous monitoring worker ---
// Runs real scheduled scans for due monitored targets: validates the target,
// spends a credit, and launches the same scan pipeline as a manual scan.
let monitorTickRunning = false;
async function runDueMonitoredScans(): Promise<void> {
  if (monitorTickRunning) return;
  monitorTickRunning = true;
  try {
    const due = db.listDueMonitoredTargets(new Date().toISOString());
    for (const target of due) {
      const next = new Date(Date.now() + (target.frequencyDays || 7) * 24 * 60 * 60 * 1000).toISOString();
      try {
        const user = db.getUser(target.userId);
        if (!user || user.credits < 1) continue; // retry next tick once credits exist
        await assertScanTargetSafe(target.url);
        db.deductCredits(target.userId, 1);
        const scan = db.createScan(target.userId, target.url);
        db.markMonitoredScanned(target.id, new Date().toISOString(), next);
        processScanJob(scan.id);
      } catch (err: any) {
        // Invalid/unsafe target: defer instead of retrying every tick.
        db.markMonitoredScanned(target.id, target.lastScannedAt || new Date().toISOString(), next);
        console.warn(`[monitor] Skipped ${target.url}: ${err?.message || err}`);
      }
    }
  } finally {
    monitorTickRunning = false;
  }
}

// Starts the once-a-minute monitoring tick. The interval is unref'd so it never
// keeps the process alive on its own.
export function startMonitoringWorker(): void {
  const monitorInterval = setInterval(() => {
    runDueMonitoredScans().catch((e) => console.error('[monitor] tick error:', e));
  }, 60 * 1000);
  monitorInterval.unref();
}
