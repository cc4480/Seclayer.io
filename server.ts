import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import cors from 'cors';
import { createServer as createViteServer } from 'vite';
import { db, LocalFileDb } from './server/db.js';
import { createScanJobRunner } from './server/scan-job.js';
import { registerPublicRoutes } from './server/routes/public-routes.js';
import { registerScanRoutes } from './server/routes/scan-routes.js';
import { registerMonitoringRoutes } from './server/routes/monitoring-routes.js';
import { registerGithubRoutes } from './server/routes/github-routes.js';
import { registerEnterpriseRoutes } from './server/routes/enterprise-routes.js';
import { registerEnterpriseScanRoutes } from './server/routes/enterprise-scan-routes.js';

export function createApp(dbInstance: LocalFileDb) {
  const app = express();

  app.use(cors({ origin: true, credentials: true }));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Security headers applied globally
  app.use((_req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  const { processScanJob, fireWebhook } = createScanJobRunner(dbInstance);

  registerPublicRoutes(app, dbInstance, { fireWebhook });
  registerScanRoutes(app, dbInstance, { processScanJob });
  registerMonitoringRoutes(app, dbInstance);
  registerGithubRoutes(app, dbInstance);
  registerEnterpriseRoutes(app, dbInstance);
  registerEnterpriseScanRoutes(app, dbInstance);

  // Centralized error handler
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    console.error('[Error]', err);
    res.status(err.status ?? 500).json({ error: err.message ?? 'Internal server error.' });
  });

  // Monitoring scheduler — fires every 60s, skipped in test environment
  if (!process.env.VITEST) {
    const schedulerInterval = setInterval(async () => {
      const due = dbInstance.getDueMonitoringTargets();
      for (const target of due) {
        dbInstance.touchMonitoredTarget(target.id);
        const scan = dbInstance.createScan(target.userId, target.url);
        processScanJob(scan.id).catch((err: any) =>
          console.error(`[Monitor] Scheduled scan failed for ${target.url}: ${err?.message}`)
        );
      }
    }, 60 * 1000);
    schedulerInterval.unref();
  }

  return app;
}

async function startServer() {
  const app = createApp(db);

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log(`[Seclayer] Listening on http://0.0.0.0:${port}`);
  });
}

if (!process.env.VITEST) {
  startServer().catch(err => {
    console.error('Server bootstrap error:', err);
    process.exit(1);
  });
}
