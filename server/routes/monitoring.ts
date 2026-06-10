import type { Express } from 'express';
import { db } from '../db.js';
import { HttpError } from '../middleware.js';
import { requireString, optionalString } from '../validation.js';

/** Continuous monitoring: scheduled re-scans of saved targets. */
export function registerMonitoringRoutes(app: Express): void {
  app.get('/api/monitoring', (req, res) => {
    const userId = (req.query.userId as string) || 'user_default';
    const monitoredTargets = db.listMonitoredTargets(userId);
    res.json({ monitoredTargets });
  });

  app.post('/api/monitoring', (req, res) => {
    const userId = optionalString(req.body?.userId, 'userId') || 'user_default';
    const url = requireString(req.body?.url, 'url');
    const frequencyDays = Number(req.body?.frequencyDays ?? 7);
    if (!Number.isFinite(frequencyDays) || frequencyDays < 1 || frequencyDays > 365) {
      throw new HttpError(400, 'frequencyDays must be a number between 1 and 365.');
    }
    const scheduleString = optionalString(req.body?.scheduleString, 'scheduleString');
    const target = db.addMonitoredTarget(userId, url, frequencyDays, scheduleString);
    res.json({ status: 'ok', target });
  });

  app.delete('/api/monitoring/:id', (req, res) => {
    const userId = (req.query.userId as string) || 'user_default';
    const success = db.removeMonitoredTarget(userId, req.params.id);
    if (!success) {
      throw new HttpError(404, 'Monitored target not found');
    }
    res.json({ status: 'ok' });
  });
}
