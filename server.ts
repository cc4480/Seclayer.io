import './server/env.js'; // must run first: loads .env before any module reads process.env
import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import { createServer as createViteServer } from 'vite';
import { config, validateConfigOnBoot } from './server/config.js';
import { attachSession } from './server/http/context.js';
import { jsonErrorHandler } from './server/http/errorHandler.js';
import { startMonitoringWorker } from './server/worker.js';
import { registerSystemRoutes } from './server/routes/system.js';
import { registerAuthRoutes } from './server/routes/auth.js';
import { registerScanRoutes } from './server/routes/scans.js';
import { registerSuppressionRoutes } from './server/routes/suppressions.js';
import { registerMonitoringRoutes } from './server/routes/monitoring.js';
import { registerStripeWebhook, registerCreditRoutes } from './server/routes/credits.js';
import { registerKeyRoutes } from './server/routes/keys.js';
import { registerMcpRoutes } from './server/routes/mcp.js';

async function startServer() {
  if (!validateConfigOnBoot() && config.isProd) {
    console.error('[config] Refusing to start: production-critical configuration is missing (see warnings above).');
    process.exit(1);
  }

  const app = express();
  const PORT = config.port;

  // Behind a proxy/load balancer in production so req.protocol, req.ip and
  // Secure cookies are derived from the X-Forwarded-* headers.
  if (config.isProd) app.set('trust proxy', 1);

  // Baseline security headers on every response (including API + errors).
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (config.isProd) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
    next();
  });

  // Stripe webhook needs the raw body for signature verification, so it is
  // registered before the JSON body parser.
  registerStripeWebhook(app);

  // Body parsers + cookies (explicit body size cap)
  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: true, limit: '256kb' }));
  app.use(cookieParser());

  // Resolve the session cookie to a userId for every request.
  app.use(attachSession);

  // --- API ROUTES ---
  registerSystemRoutes(app);
  registerAuthRoutes(app);
  registerScanRoutes(app);
  registerSuppressionRoutes(app);
  registerMonitoringRoutes(app);
  registerCreditRoutes(app);
  registerKeyRoutes(app);
  registerMcpRoutes(app);

  // Background continuous-monitoring worker.
  startMonitoringWorker();

  // Unknown API routes return JSON 404 (not the SPA shell).
  app.use('/api', (req, res) => {
    res.status(404).json({ status: 'error', message: `Unknown API endpoint: ${req.method} ${req.path}` });
  });

  // --- Express serving of static client files ---
  if (!config.isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // Terminal JSON error handler (classifies body-parser failures as 400/413).
  app.use(jsonErrorHandler);

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Seclayer Engine] Listening on http://0.0.0.0:${PORT} (${config.isProd ? 'production' : 'development'})`);
  });

  // Graceful shutdown for containerized deployments.
  const shutdown = (signal: string) => {
    console.log(`[server] ${signal} received — shutting down gracefully.`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// Process-level safety nets: log instead of crashing silently.
process.on('unhandledRejection', (reason) => {
  console.error('[server] Unhandled promise rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[server] Uncaught exception:', err);
});

// Global safety catch
startServer().catch((err) => {
  console.error("Critical server bootstrap error:", err);
  process.exit(1);
});
