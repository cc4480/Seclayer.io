import type { Express, RequestHandler } from 'express';
import { db } from '../db.js';
import { HttpError, asyncHandler, currentUserId } from '../middleware.js';
import { assertSafeScanTarget, optionalString } from '../validation.js';
import { scanQueue } from '../scan-queue.js';

/** Scan lifecycle: submit, list, and fetch results/reports. */
export function registerScanRoutes(app: Express, scanLimiter: RequestHandler): void {
  app.post(
    '/api/scans',
    scanLimiter,
    asyncHandler(async (req, res) => {
      const url = await assertSafeScanTarget(req.body?.url);
      const userId = currentUserId(req);
      const authHeader = optionalString(req.body?.authHeader, 'authHeader');

      const user = db.getUser(userId);
      if (!user) {
        throw new HttpError(404, 'User profile not found');
      }

      if (user.credits < 1) {
        throw new HttpError(
          402,
          'No credits remaining. Please purchase scan credits to continue.',
        );
      }

      // Deduct 1 credit and create the queued scan.
      db.deductCredits(userId, 1);
      const scan = db.createScan(userId, url, authHeader);

      // Hand off to the bounded job queue (concurrency-capped, timeout-guarded).
      scanQueue.enqueue(scan.id);

      res.json({ status: 'ok', scan });
    }),
  );

  app.get('/api/scans', (req, res) => {
    const userId = currentUserId(req);
    const scansList = db.listScans(userId).map((s) => db.getScanWithSuppressedFindings(s));
    res.json({ scans: scansList });
  });

  app.get('/api/scans/:id', (req, res) => {
    let scan = db.getScan(req.params.id);
    if (!scan) {
      throw new HttpError(404, 'Scan not found');
    }
    scan = db.getScanWithSuppressedFindings(scan);
    res.json({ scan });
  });

  app.get('/api/scans/:id/report', (req, res) => {
    let scan = db.getScan(req.params.id);
    if (!scan) {
      throw new HttpError(404, 'Scan not found');
    }
    if (scan.status !== 'complete') {
      throw new HttpError(400, 'Scan report is not complete yet');
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
      completedAt: scan.completedAt,
    });
  });
}
