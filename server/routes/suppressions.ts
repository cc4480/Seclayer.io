import express from 'express';
import { db } from '../db.js';
import { requireAuth, getUserId } from '../http/context.js';

// --- False Positive & Suppression Rules ---
export function registerSuppressionRoutes(app: express.Express): void {
  app.get('/api/suppressions', requireAuth, (req, res) => {
    res.json({ suppressions: db.listSuppressions(getUserId(req)) });
  });

  app.post('/api/suppressions', requireAuth, (req, res) => {
    const { targetUrl, findingTitle, reason } = req.body;
    if (!targetUrl || !findingTitle) {
      return res.status(400).json({ error: 'targetUrl and findingTitle are required' });
    }
    const rule = db.addSuppression(getUserId(req), targetUrl, findingTitle, reason || 'False positive confirmation');
    res.json({ status: 'ok', rule });
  });

  app.delete('/api/suppressions/:id', requireAuth, (req, res) => {
    if (!db.removeSuppression(getUserId(req), req.params.id)) {
      return res.status(404).json({ error: 'Suppression exclusion rule not found' });
    }
    res.json({ status: 'ok' });
  });

  app.post('/api/scans/:scanId/findings/:findingId/suppress', requireAuth, (req, res) => {
    const { scanId, findingId } = req.params;
    const { reason = 'Manual enterprise validation' } = req.body;
    const userId = getUserId(req);

    const scan = db.getScan(scanId);
    if (!scan || scan.userId !== userId) {
      return res.status(404).json({ error: 'Scan job not resolved' });
    }

    const finding = scan.findings?.find(f => f.id === findingId);
    if (!finding) {
      return res.status(404).json({ error: 'Finding payload not found' });
    }

    const rule = db.addSuppression(userId, scan.url, finding.title, reason);
    res.json({ status: 'ok', rule, message: 'Finding successfully suppressed and marked as False Positive.' });
  });
}
