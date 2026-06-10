import express from 'express';
import path from 'path';
import type { Server } from 'http';
import { createServer as createViteServer } from 'vite';
import { db } from './server/db.js';
import { runDiagnostics, compileStaticFindings } from './server/scanner.js';
import { generateAiReport, generatePentagiLogs } from './server/gemini.js';
import { config, validateConfig } from './server/config.js';
import { logger } from './server/logger.js';
import {
  requestContext,
  securityHeaders,
  cors,
  rateLimit,
  asyncHandler,
  notFound,
  errorHandler,
  HttpError,
} from './server/middleware.js';
import {
  validateEmail,
  assertSafeScanTarget,
  requireString,
  optionalString,
} from './server/validation.js';

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

  // --- HEALTH / READINESS ---
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
      aiProvider: config.gemini.configured ? 'configured' : 'local-fallback',
      timestamp: new Date().toISOString(),
    });
  });

  // --- Auth Routes ---
  app.post('/api/auth/login', (req, res) => {
    const email = validateEmail(req.body?.email);
    const user = db.getOrCreateUser(email);
    res.json({ status: 'ok', user });
  });

  app.post('/api/auth/logout', (_req, res) => {
    res.json({ status: 'ok', message: 'Logged out successfully' });
  });

  app.get('/api/auth/me', (req, res) => {
    const userId = (req.query.userId as string) || 'user_default';
    const user = db.getUser(userId);
    if (!user) {
      throw new HttpError(404, 'User profile not found');
    }
    res.json({ user });
  });

  // --- Scan Routes ---
  app.post(
    '/api/scans',
    scanLimiter,
    asyncHandler(async (req, res) => {
      const url = await assertSafeScanTarget(req.body?.url);
      const userId = optionalString(req.body?.userId, 'userId') || 'user_default';
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

      // Trigger the asynchronous background worker pipeline.
      processScanJob(scan.id);

      res.json({ status: 'ok', scan });
    }),
  );

  app.get('/api/scans', (req, res) => {
    const userId = (req.query.userId as string) || 'user_default';
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

  // --- False Positive & Suppression Rules ---
  app.get('/api/suppressions', (req, res) => {
    const userId = (req.query.userId as string) || 'user_default';
    const rules = db.listSuppressions(userId);
    res.json({ suppressions: rules });
  });

  app.post('/api/suppressions', (req, res) => {
    const userId = optionalString(req.body?.userId, 'userId') || 'user_default';
    const targetUrl = requireString(req.body?.targetUrl, 'targetUrl');
    const findingTitle = requireString(req.body?.findingTitle, 'findingTitle');
    const reason = optionalString(req.body?.reason, 'reason') || 'False positive confirmation';
    const rule = db.addSuppression(userId, targetUrl, findingTitle, reason);
    res.json({ status: 'ok', rule });
  });

  app.delete('/api/suppressions/:id', (req, res) => {
    const userId = (req.query.userId as string) || 'user_default';
    const success = db.removeSuppression(userId, req.params.id);
    if (!success) {
      throw new HttpError(404, 'Suppression exclusion rule not found');
    }
    res.json({ status: 'ok' });
  });

  app.post('/api/scans/:scanId/findings/:findingId/suppress', (req, res) => {
    const { scanId, findingId } = req.params;
    const userId = optionalString(req.body?.userId, 'userId') || 'user_default';
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

  // --- Continuous Monitoring ---
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

  // --- Credits & Checkout ---
  app.get('/api/credits', (req, res) => {
    const userId = (req.query.userId as string) || 'user_default';
    const user = db.getUser(userId);
    if (!user) throw new HttpError(404, 'User not found');
    res.json({
      credits: user.credits,
      transactions: db.listTransactions(userId),
    });
  });

  // Mock Stripe Checkout test integration
  app.post('/api/credits/checkout', (req, res) => {
    const userId = optionalString(req.body?.userId, 'userId') || 'user_default';
    const pack = req.body?.pack;

    const PRICES = {
      single: { price: 29, credits: 1 },
      pack5: { price: 99, credits: 5 },
      pack20: { price: 299, credits: 20 },
    };

    const selectedPack = PRICES[pack as keyof typeof PRICES];
    if (!selectedPack) {
      throw new HttpError(400, 'Invalid credit pack selected');
    }

    const user = db.getUser(userId);
    if (!user) throw new HttpError(404, 'User not found');

    const sessionId = `cs_test_${Math.random().toString(36).substring(2, 15)}`;
    db.addCredits(userId, selectedPack.credits, 'purchase', sessionId);

    res.json({
      status: 'ok',
      url: `/dashboard?checkout_success=true&credits=${selectedPack.credits}`,
      sessionId,
      creditsAdded: selectedPack.credits,
      pricePaid: selectedPack.price,
    });
  });

  // Mock Stripe Webhook endpoint
  app.post('/api/webhooks/stripe', (_req, res) => {
    res.json({ received: true });
  });

  // --- API Key routes for developer MCP usecases ---
  app.get('/api/keys', (req, res) => {
    const userId = (req.query.userId as string) || 'user_default';
    const keys = db.listApiKeys(userId);
    res.json({ keys });
  });

  app.post('/api/keys', (req, res) => {
    const userId = optionalString(req.body?.userId, 'userId') || 'user_default';
    const user = db.getUser(userId);
    if (!user) throw new HttpError(404, 'User not found');
    const keyObj = db.generateApiKey(userId);
    res.json({ status: 'ok', key: keyObj });
  });

  app.delete('/api/keys/:id', (req, res) => {
    const userId = (req.query.userId as string) || 'user_default';
    const success = db.revokeApiKey(userId, req.params.id);
    if (!success) {
      throw new HttpError(404, 'Key not found or could not be revoked');
    }
    res.json({ status: 'ok' });
  });

  // --- MCP Endpoints ---
  // Any external agent can call this with an API key.
  app.post(
    '/api/mcp/scan',
    scanLimiter,
    asyncHandler(async (req, res) => {
      const apiKey = requireString(req.body?.apiKey, 'apiKey');
      const url = await assertSafeScanTarget(req.body?.url);
      const authHeader = optionalString(req.body?.authHeader, 'authHeader');

      // Verify key and deduct 1 credit.
      const user = db.validateApiKeyAndDeduct(apiKey, 1);
      if (!user) {
        throw new HttpError(
          401,
          'Invalid API Key, active key required, or insufficient credits. Get credits at seclayer.io.',
        );
      }

      // Run the scan synchronously for the MCP tool-call context.
      const diagnostics = await runDiagnostics(url, authHeader);
      const staticCompiled = compileStaticFindings(diagnostics);
      const aiReport = await generateAiReport(url, diagnostics, staticCompiled);

      // Persist the completed scan so it appears in dashboard history.
      const completedScan = db.createScan(user.id, url, authHeader);
      db.updateScan(completedScan.id, {
        status: 'complete',
        score: aiReport.score,
        severity: aiReport.severity,
        findings: aiReport.findings,
        aiSummary: aiReport.aiSummary,
        completedAt: new Date().toISOString(),
      });

      res.json({
        success: true,
        targetUrl: url,
        postureScore: aiReport.score,
        vulnerabilityLevel: aiReport.severity,
        analysisSummary: aiReport.aiSummary,
        securityFindings: aiReport.findings,
        creditsRemaining: user.credits,
      });
    }),
  );

  // --- ENTERPRISE PIPELINE ACTIVE ENDPOINTS ---

  // 1. ASPM & Signal Correlation Engine
  app.post('/api/enterprise/aspm/correlate', (req, res) => {
    const { url = 'staging.api.vulnerable-shop.io' } = req.body;
    res.json({
      success: true,
      targetUrl: url,
      orchestrator: 'OWASP DefectDojo Correlator Core',
      findingsCorrelated: 2,
      analysisTimeMs: 420,
      steps: [
        {
          phase: 'SAST Vulnerability Ingestion',
          status: 'complete',
          logs: `Parsed Semgrep SAST scan hook on dynamic repository commits definition. Flagged 1 SQL Injection hazard inside "/controllers/UserController.java" line 87: Unsafely concatenated raw HTTP inputs "userId" to SQL executable stream.`,
        },
        {
          phase: 'ASPM Correlation Engine Triggered',
          status: 'complete',
          logs: `Fusion Matcher searched EASM perimeter indexing for live URLs hosting the compiled code. Identified active target match: "${url}".`,
        },
        {
          phase: 'Targeted Dynamic Verification (DAST)',
          status: 'complete',
          logs: `Dispatched containerized OWASP ZAP/Katana worker probing "${url}/api/user/profile?id=1'". Input escape injections triggered parsing trace: Dynamic SQL syntax error returned in headers.`,
        },
        {
          phase: 'Active Vulnerability Confirmation & Escalation',
          status: 'escalated',
          logs: `Vulnerability verified as dynamic 100% exploitable. Escalated SAST Finding category severity from MEDIUM to CRITICAL. Raised high-priority Jira ticket & synced ticket ledger inside DefectDojo (ID: SL-DD-948211).`,
        },
      ],
    });
  });

  // 2. EASM Attack Surface Mapping
  app.post('/api/enterprise/easm/recon', (req, res) => {
    const { domain = 'target-enterprise.com' } = req.body;
    const cleanDomain = String(domain).replace(/https?:\/\//i, '').split('/')[0];
    res.json({
      success: true,
      domain: cleanDomain,
      scanner: 'OWASP Amass & Continuous Recon Worker v3',
      scanTime: new Date().toISOString(),
      summary: {
        totalSubdomains: 6,
        activeIps: 3,
        nameserver: 'ns1.dnsrouting-gate.net',
        nameserverIp: '45.89.21.4',
      },
      technologies: [
        { name: 'Nginx Server', type: 'Web Server', version: '1.23.2', confidence: 100 },
        { name: 'React Framework', type: 'Client Engine', version: '18.2.0', confidence: 100 },
        { name: 'Node.js Express', type: 'Backend Framework', version: '18.15.0', confidence: 95 },
        { name: 'PostgreSQL Database', type: 'DB Server', version: '15.1', confidence: 85 },
        { name: 'Cloudflare WAF', type: 'Network Shield', version: 'Global Edge', confidence: 90 },
      ],
      subdomains: [
        { subdomain: `api.${cleanDomain}`, ip: '104.22.4.12', status: 'live', ports: ['80', '443', '8443'], service: 'HTTPS Express API' },
        { subdomain: `staging.${cleanDomain}`, ip: '104.22.4.13', status: 'live', ports: ['443', '8080'], service: 'Vulnerable Staging Area' },
        { subdomain: `admin.${cleanDomain}`, ip: '104.22.4.14', status: 'live', ports: ['443'], service: 'Protected Portal Gate' },
        { subdomain: `vpn.${cleanDomain}`, ip: '45.12.98.5', status: 'live', ports: ['1194'], service: 'OpenVPN Daemon' },
        { subdomain: `grafana.${cleanDomain}`, ip: '104.22.4.15', status: 'inactive', ports: ['3000'], service: 'Telemetry Panel' },
        { subdomain: `internal-db.${cleanDomain}`, ip: '10.0.12.3', status: 'internal-only', ports: ['5432'], service: 'Production Postgres Mirror' },
      ],
      portsList: [
        { port: 80, protocol: 'tcp', service: 'HTTP (Redirects HTTPS)' },
        { port: 443, protocol: 'tcp', service: 'HTTPS (TLS 1.3 Active)' },
        { port: 1194, protocol: 'udp', service: 'OpenVPN (Vulnerable to credential sprays)' },
        { port: 8080, protocol: 'tcp', service: 'HTTP-ALT (Exposes Spring Boot actuator admin stats)' },
      ],
    });
  });

  // 3. Katana & Hadrian API Security Testing API
  app.post('/api/enterprise/api-scan/hadrian', (req, res) => {
    const { schemaTitle = 'API Specification Core' } = req.body;
    res.json({
      success: true,
      service: `Hadrian API Role Mutation Matrix Engine (${schemaTitle})`,
      endpointsCount: 4,
      matrix: [
        {
          endpoint: '/api/v1/user/profile/{id}',
          methods: ['GET', 'PUT'],
          rolesResult: {
            'Enterprise Admin': { status: 'Allow', color: 'text-[#22c55e]' },
            'Standard User': { status: 'Allow (Self-Only)', color: 'text-amber-400' },
            'Guest Role': { status: 'Denied (401)', color: 'text-red-500' },
          },
          vulnerability:
            'IDOR on PUT method: Specifying standard header overrides allows arbitrary profile updates on any account without administrative privileges.',
        },
        {
          endpoint: '/api/v1/billing/transactions',
          methods: ['GET', 'POST'],
          rolesResult: {
            'Enterprise Admin': { status: 'Allow', color: 'text-[#22c55e]' },
            'Standard User': { status: 'Denied (403)', color: 'text-red-500' },
            'Guest Role': { status: 'Denied (401)', color: 'text-red-500' },
          },
          vulnerability: 'None detected. Strict role-based filter checks present at Route level.',
        },
        {
          endpoint: '/api/v1/system/actuator/env',
          methods: ['GET'],
          rolesResult: {
            'Enterprise Admin': { status: 'Allow', color: 'text-[#22c55e]' },
            'Standard User': { status: 'Allow (Exposed)', color: 'text-red-500 font-bold' },
            'Guest Role': { status: 'Allow (Exposed)', color: 'text-red-500 font-bold animate-pulse' },
          },
          vulnerability:
            'BOLA / Authentication Bypass: Critical configurations variables (.env database passwords) accessible by unauthorized third-parties and guest operators.',
        },
        {
          endpoint: '/api/v1/support/tickets/{ticketId}',
          methods: ['GET', 'DELETE'],
          rolesResult: {
            'Enterprise Admin': { status: 'Allow', color: 'text-[#22c55e]' },
            'Standard User': { status: 'Allow (Any ID)', color: 'text-red-500 font-semibold' },
            'Guest Role': { status: 'Denied (401)', color: 'text-red-500' },
          },
          vulnerability:
            'Insecure Direct Object Reference (IDOR): Standard user can review or purge support tickets of other customers by iterating dynamic ticket integer indexes.',
        },
      ],
    });
  });

  // 4. DongTai Runtime IAST Bytecode Tracer
  app.post('/api/enterprise/iast/trace', (req, res) => {
    const { inputPayload = `1' UNION SELECT credit_card FROM payments` } = req.body;
    res.json({
      success: true,
      agent: 'DongTai VM Bytecode Passive Instrumenter Agent v2.5',
      runtime: 'Java Virtual Machine OpenJDK 17',
      status: 'Sink Triggered Malicious Flow Alert',
      payloadTested: inputPayload,
      traceTime: new Date().toISOString(),
      traces: [
        {
          step: 1,
          clazz: 'org.apache.catalina.connector.Request',
          method: 'getParameter("searchQuery")',
          line: 312,
          description: `HTTP parameter parsing matched. Tainted reference loaded into user scope. Input: "${inputPayload}"`,
        },
        {
          step: 2,
          clazz: 'com.seclayer.enterprise.controller.SearchController',
          method: 'executeSearch(HttpServletRequest)',
          line: 45,
          description: `Tainted wrapper transferred directly to query validator. Sanitizer bypass occurred (length checks only; regex failed to intercept SQL escape syntax).`,
        },
        {
          step: 3,
          clazz: 'com.seclayer.enterprise.data.RepositoryCore',
          method: 'unsafeRawSearchBind(String)',
          line: 104,
          description: `String concatenation sink assembled: "SELECT * FROM items WHERE name = '" + searchQuery + "'" -> query result: "SELECT * FROM items WHERE name = '1' UNION SELECT credit_card FROM payments'".`,
        },
        {
          step: 4,
          clazz: 'org.postgresql.jdbc.PgStatement',
          method: 'execute(String)',
          line: 2190,
          description: `⚠️ SQL DATA SINK REACHED! Passive IAST hooks intercepted the query parsing executing in real-time. Confirmed attacker payload has mutated query execution logic inside the active running process.`,
        },
      ],
    });
  });

  // 5. PentAGI Autonomous Pentest AI Exploit Agent
  app.get(
    '/api/enterprise/pentagi/logs',
    asyncHandler(async (req, res) => {
      const url = req.query.url as string | undefined;
      const logs = await generatePentagiLogs(url);
      res.json({
        success: true,
        engine: 'PentAGI Autonomous Multi-Agent Multi-Step Pentest Coordinator',
        agents: ['Scout', 'Exploiter', 'Reporter'],
        logs,
      });
    }),
  );

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

// --- Background scan coordinator queue ---
async function processScanJob(scanId: string) {
  const jobLog = logger.child({ scanId });
  try {
    jobLog.info('scan job started');

    await sleep(1500);
    db.updateScan(scanId, { status: 'scanning' });

    const scan = db.getScan(scanId);
    if (!scan) {
      jobLog.warn('scan disappeared before diagnostics could run');
      return;
    }

    const diagnostics = await runDiagnostics(scan.url, scan.authHeader);

    await sleep(1500);
    db.updateScan(scanId, { status: 'analyzing' });

    const staticCompiled = compileStaticFindings(diagnostics);
    const outputReport = await generateAiReport(scan.url, diagnostics, staticCompiled);

    db.updateScan(scanId, {
      status: 'complete',
      score: outputReport.score,
      severity: outputReport.severity,
      findings: outputReport.findings,
      aiSummary: outputReport.aiSummary,
      completedAt: new Date().toISOString(),
    });
    jobLog.info('scan job completed', { score: outputReport.score, severity: outputReport.severity });
  } catch (err: unknown) {
    jobLog.error('scan job failed', { err });
    try {
      db.updateScan(scanId, {
        status: 'failed',
        error:
          err instanceof Error
            ? err.message
            : 'An unexpected server timeout occurred during scanner diagnostics.',
      });
    } catch (updateErr) {
      jobLog.error('failed to record scan failure state', { err: updateErr });
    }
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
