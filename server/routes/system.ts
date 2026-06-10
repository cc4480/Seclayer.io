import type { Express } from 'express';
import { db } from '../db.js';
import { config } from '../config.js';

/** Liveness/readiness probes for orchestrators and uptime monitors. */
export function registerSystemRoutes(app: Express): void {
  // Liveness: process is up.
  app.get('/api/system/health', (_req, res) => {
    res.json({
      status: 'Online',
      version: 'v2.1.2-stable',
      uptimeSeconds: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
    });
  });

  // Readiness: dependencies are usable (datastore reachable).
  app.get('/api/system/ready', (_req, res) => {
    const ready = db.isHealthy();
    res.status(ready ? 200 : 503).json({
      status: ready ? 'ready' : 'degraded',
      datastore: ready ? 'ok' : 'unavailable',
      aiProvider: config.deepseek.configured ? 'deepseek' : 'local-fallback',
      timestamp: new Date().toISOString(),
    });
  });
}
