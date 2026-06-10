import express from 'express';
import path from 'path';
import type { Server } from 'http';
import { createServer as createViteServer } from 'vite';
import { config, validateConfig } from './server/config.js';
import { logger } from './server/logger.js';
import { requestContext, securityHeaders, cors, rateLimit, notFound, errorHandler } from './server/middleware.js';
import { registerSystemRoutes } from './server/routes/system.js';
import { registerAuthRoutes } from './server/routes/auth.js';
import { registerScanRoutes } from './server/routes/scans.js';
import { registerSuppressionRoutes } from './server/routes/suppressions.js';
import { registerMonitoringRoutes } from './server/routes/monitoring.js';
import { registerCreditRoutes } from './server/routes/credits.js';
import { registerMcpRoutes } from './server/routes/mcp.js';
import { registerEnterpriseRoutes } from './server/routes/enterprise/index.js';

export async function createApp() {
  const app = express();

  // Trust the first proxy hop so req.ip / X-Forwarded-For are accurate behind
  // a load balancer (Cloud Run, nginx, etc.).
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  // Cross-cutting middleware (order matters).
  app.use(requestContext());
  app.use(securityHeaders());
  app.use(cors());

  // Body parsers with an explicit size limit to blunt large-payload DoS.
  app.use(express.json({ limit: config.bodyLimit }));
  app.use(express.urlencoded({ extended: true, limit: config.bodyLimit }));

  // Rate limiters: a general cap for the API, plus a stricter one for the
  // expensive scan endpoints.
  const apiLimiter = rateLimit({ name: 'api' });
  const scanLimiter = rateLimit({
    name: 'scan',
    max: config.rateLimit.scanMaxRequests,
  });
  app.use('/api', apiLimiter);

  registerSystemRoutes(app);
  registerAuthRoutes(app);
  registerScanRoutes(app, scanLimiter);
  registerSuppressionRoutes(app);
  registerMonitoringRoutes(app);
  registerCreditRoutes(app);
  registerMcpRoutes(app, scanLimiter);
  registerEnterpriseRoutes(app, scanLimiter);

  // --- Static client serving (Vite dev middleware or built assets) ---
  if (!config.isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res, next) => {
      // Unknown API routes should 404 as JSON, not serve the SPA shell.
      if (req.path.startsWith('/api/')) return next();
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // 404 + centralized error handler (must be registered last).
  app.use('/api', notFound());
  app.use(errorHandler());

  return app;
}

async function startServer() {
  const warnings = validateConfig();
  warnings.forEach((w) => logger.warn(w));

  const app = await createApp();

  const server: Server = app.listen(config.port, config.host, () => {
    logger.info('Seclayer engine listening', {
      url: `http://${config.host}:${config.port}`,
      env: config.nodeEnv,
    });
  });

  setupGracefulShutdown(server);
  setupProcessGuards();

  return server;
}

/** Drain in-flight requests on SIGTERM/SIGINT, then exit cleanly. */
function setupGracefulShutdown(server: Server) {
  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info('shutdown signal received, draining connections', { signal });

    const timer = setTimeout(() => {
      logger.error('graceful shutdown timed out, forcing exit');
      process.exit(1);
    }, 10_000);
    if (typeof timer.unref === 'function') timer.unref();

    server.close((err) => {
      if (err) {
        logger.error('error during server close', { err });
        process.exit(1);
      }
      logger.info('server closed cleanly');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

/** Last-resort handlers so a stray rejection/exception is logged, not silent. */
function setupProcessGuards() {
  process.on('unhandledRejection', (reason) => {
    logger.error('unhandled promise rejection', { err: reason });
  });
  process.on('uncaughtException', (err) => {
    logger.error('uncaught exception', { err });
    // An uncaught exception leaves the process in an undefined state; exit so
    // the orchestrator can restart a clean instance.
    process.exit(1);
  });
}

// Only auto-start when run directly (not when imported by tests).
const isDirectRun = process.argv[1] && /server\.(ts|js|cjs)$/.test(process.argv[1]);
if (isDirectRun) {
  startServer().catch((err) => {
    logger.error('critical server bootstrap error', { err });
    process.exit(1);
  });
}
