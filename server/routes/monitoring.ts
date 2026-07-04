import express from 'express';
import { db } from '../db.js';
import { assertScanTargetSafe } from '../scanner.js';
import { requireAuth, getUserId } from '../http/context.js';

// --- Continuous Monitoring + alert webhook ---
export function registerMonitoringRoutes(app: express.Express): void {
  app.get('/api/monitoring', requireAuth, (req, res) => {
    res.json({ monitoredTargets: db.listMonitoredTargets(getUserId(req)) });
  });

  app.post('/api/monitoring', requireAuth, (req, res) => {
    const { url, frequencyDays = 7, scheduleString } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'url is required' });
    }
    const target = db.addMonitoredTarget(getUserId(req), url, frequencyDays, scheduleString);
    res.json({ status: 'ok', target });
  });

  app.delete('/api/monitoring/:id', requireAuth, (req, res) => {
    if (!db.removeMonitoredTarget(getUserId(req), req.params.id)) {
      return res.status(404).json({ error: 'Monitored target not found' });
    }
    res.json({ status: 'ok' });
  });

  // --- Alert webhook (Slack-compatible) ---
  app.put('/api/user/webhook', requireAuth, async (req, res) => {
    const { url } = req.body || {};
    if (url) {
      if (typeof url !== 'string') {
        return res.status(400).json({ status: 'error', message: 'Webhook must be an http(s) URL, or empty to disable.' });
      }
      // Block internal/reserved destinations (SSRF) at set time; delivery is
      // re-validated as well in case DNS changes later.
      try {
        await assertScanTargetSafe(url.trim());
      } catch {
        return res.status(400).json({ status: 'error', message: 'Webhook must be a public http(s) URL (internal/reserved addresses are not allowed).' });
      }
    }
    const user = db.setUserWebhook(getUserId(req), url ? url.trim() : null);
    res.json({ status: 'ok', notifyWebhook: user?.notifyWebhook ?? null });
  });
}
