import type { Express } from 'express';
import { db } from '../db.js';
import { HttpError, currentUserId } from '../middleware.js';
import { requireString, optionalString } from '../validation.js';

/** False-positive suppression rules and per-finding "mark as false positive" actions. */
export function registerSuppressionRoutes(app: Express): void {
  app.get('/api/suppressions', (req, res) => {
    const userId = currentUserId(req);
    const rules = db.listSuppressions(userId);
    res.json({ suppressions: rules });
  });

  app.post('/api/suppressions', (req, res) => {
    const userId = currentUserId(req);
    const targetUrl = requireString(req.body?.targetUrl, 'targetUrl');
    const findingTitle = requireString(req.body?.findingTitle, 'findingTitle');
    const reason = optionalString(req.body?.reason, 'reason') || 'False positive confirmation';
    const rule = db.addSuppression(userId, targetUrl, findingTitle, reason);
    res.json({ status: 'ok', rule });
  });

  app.delete('/api/suppressions/:id', (req, res) => {
    const userId = currentUserId(req);
    const success = db.removeSuppression(userId, req.params.id);
    if (!success) {
      throw new HttpError(404, 'Suppression exclusion rule not found');
    }
    res.json({ status: 'ok' });
  });

  app.post('/api/scans/:scanId/findings/:findingId/suppress', (req, res) => {
    const { scanId, findingId } = req.params;
    const userId = currentUserId(req);
    const reason = optionalString(req.body?.reason, 'reason') || 'Manual enterprise validation';

    const scan = db.getScan(scanId);
    if (!scan || scan.userId !== userId) {
      throw new HttpError(404, 'Scan job not resolved');
    }

    const finding = scan.findings?.find((f) => f.id === findingId);
    if (!finding) {
      throw new HttpError(404, 'Finding payload not found');
    }

    const rule = db.addSuppression(userId, scan.url, finding.title, reason);
    res.json({ status: 'ok', rule, message: 'Finding successfully suppressed and marked as False Positive.' });
  });
}
