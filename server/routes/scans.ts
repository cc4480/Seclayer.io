import express from 'express';
import { db } from '../db.js';
import { rateLimit } from '../rateLimit.js';
import { assertScanTargetSafe } from '../scanner.js';
import { processScanJob } from '../worker.js';
import { requireAuth, getUserId } from '../http/context.js';

// --- Scan lifecycle routes ---
export function registerScanRoutes(app: express.Express): void {
  const scanLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    keyPrefix: 'scan',
    message: 'Scan rate limit reached. Please wait a moment before launching more scans.',
  });

  app.post('/api/scans', requireAuth, scanLimiter, async (req, res) => {
    const { url, authHeader } = req.body;
    const userId = getUserId(req);
    if (!url) {
      return res.status(400).json({ status: 'error', message: 'Target URL is required' });
    }

    const user = db.getUser(userId);
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User profile not found' });
    }

    if (user.credits < 1) {
      return res.status(402).json({
        status: 'error',
        message: 'No credits remaining. Please purchase scan credits to continue.'
      });
    }

    // Reject SSRF / malformed targets before spending a credit.
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ status: 'error', message: e?.message || 'Target URL cannot be scanned.' });
    }

    // Deduct 1 credit
    db.deductCredits(userId, 1);

    // Create the scan entry in queued state
    const scan = db.createScan(userId, url, authHeader);

    // Trigger asynchronous background worker flow.
    processScanJob(scan.id);

    res.json({ status: 'ok', scan });
  });

  app.get('/api/scans', requireAuth, (req, res) => {
    const scansList = db.listScans(getUserId(req)).map(s => db.getScanWithSuppressedFindings(s));
    res.json({ scans: scansList });
  });

  app.get('/api/scans/:id', requireAuth, (req, res) => {
    let scan = db.getScan(req.params.id);
    // Enforce ownership: a scan ID alone must not grant access to another
    // user's results. Return 404 (not 403) to avoid leaking scan existence.
    if (!scan || scan.userId !== getUserId(req)) {
      return res.status(404).json({ status: 'error', message: 'Scan not found' });
    }
    scan = db.getScanWithSuppressedFindings(scan);
    res.json({ scan });
  });

  app.get('/api/scans/:id/report', requireAuth, (req, res) => {
    let scan = db.getScan(req.params.id);
    if (!scan || scan.userId !== getUserId(req)) {
      return res.status(404).json({ status: 'error', message: 'Scan not found' });
    }
    if (scan.status !== 'complete') {
      return res.status(400).json({ status: 'error', message: 'Scan report is not complete yet' });
    }
    scan = db.getScanWithSuppressedFindings(scan);
    res.json({
      scanId: scan.id,
      url: scan.url,
      score: scan.score,
      severity: scan.severity,
      aiSummary: scan.aiSummary,
      findings: scan.findings,
      createdAt: scan.createdAt,
      completedAt: scan.completedAt
    });
  });
}
