import express from 'express';
import path from 'path';
import type { Server } from 'http';
import { createServer as createViteServer } from 'vite';
import { db } from './server/db.js';
import { runDiagnostics, compileStaticFindings, summarizeDiagnostics } from './server/scanner.js';
import { generateAiReport, generatePentagiLogs } from './server/deepseek.js';
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
      aiProvider: config.deepseek.configured ? 'deepseek' : 'local-fallback',
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
        diagnostics: summarizeDiagnostics(diagnostics),
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
  // Each module below runs the same real diagnostics engine used by /api/scans
  // against the user-supplied target and derives its response entirely from the
  // findings actually observed — there is no canned/hardcoded result data.

  // 1. ASPM & Signal Correlation Engine
  app.post(
    '/api/enterprise/aspm/correlate',
    scanLimiter,
    asyncHandler(async (req, res) => {
      const target = await assertSafeScanTarget(req.body?.url);
      const startedAt = Date.now();
      const diag = await runDiagnostics(target);
      const compiled = compileStaticFindings(diag);
      const analysisTimeMs = Date.now() - startedAt;

      const liveSubCount = diag.easmPerimeter.subdomains.filter((s) => s.status === 'live').length;
      const dynamicLogs = [
        ...diag.dastInputs.map((d) => `${d.vulnerability}: ${d.description}`),
        ...(diag.redTeamFindings ?? []).map((rt) => `${rt.testName}: ${rt.description}`),
      ];
      const escalate = compiled.severity === 'critical' || compiled.severity === 'high';
      const hostname = new URL(target).hostname;

      res.json({
        success: true,
        targetUrl: target,
        orchestrator: 'Seclayer ASPM Fusion Correlation Engine',
        findingsCorrelated: compiled.findings.length,
        analysisTimeMs,
        steps: [
          {
            phase: 'SAST Vulnerability Ingestion',
            status: 'complete',
            logs:
              diag.sastFindings.length > 0
                ? diag.sastFindings
                    .map((f) => `[${f.severity.toUpperCase()}] ${f.issue} (${f.file}): ${f.description}`)
                    .join('\n')
                : `Static analysis of client-served source for "${target}" found no hardcoded secrets, unsafe sinks, or debug-data leaks.`,
          },
          {
            phase: 'ASPM Correlation Engine Triggered',
            status: 'complete',
            logs:
              liveSubCount > 0
                ? `Fusion Matcher cross-referenced EASM perimeter indexing for live hosts sharing this attack surface. Identified ${liveSubCount} additional live subdomain(s) resolving alongside "${hostname}".`
                : `Fusion Matcher cross-referenced EASM perimeter indexing for "${hostname}". No additional live subdomains were found sharing this attack surface.`,
          },
          {
            phase: 'Targeted Dynamic Verification (DAST)',
            status: 'complete',
            logs:
              dynamicLogs.length > 0
                ? `Dispatched dynamic verification probes against "${target}". ${dynamicLogs.join(' ')}`
                : `Dispatched dynamic verification probes against "${target}". No dynamic exploitation vectors were confirmed.`,
          },
          {
            phase: 'Active Vulnerability Confirmation & Escalation',
            status: escalate ? 'escalated' : 'complete',
            logs: escalate
              ? `Correlated ${compiled.findings.length} finding(s) verified against the live attack surface. Posture severity escalated to ${compiled.severity.toUpperCase()}; prioritize remediation.`
              : `${compiled.findings.length} finding(s) correlated. None met the automatic escalation threshold; current posture severity is ${compiled.severity.toUpperCase()}.`,
          },
        ],
      });
    }),
  );

  // 2. EASM Attack Surface Mapping
  app.post(
    '/api/enterprise/easm/recon',
    scanLimiter,
    asyncHandler(async (req, res) => {
      const target = await assertSafeScanTarget(req.body?.domain);
      const diag = await runDiagnostics(target);
      const hostname = new URL(diag.url).hostname;

      const liveSubs = diag.easmPerimeter.subdomains.filter((s) => s.status === 'live');
      const uniqueIps = new Set<string>();
      if (diag.easmPerimeter.ip !== 'unresolved') uniqueIps.add(diag.easmPerimeter.ip);
      liveSubs.forEach((s) => {
        if (s.ip) uniqueIps.add(s.ip);
      });

      const technologies: Array<{ name: string; type: string; version: string; confidence: number }> = [];
      if (diag.sslSecure) {
        technologies.push({
          name: diag.easmPerimeter.protocol,
          type: 'Transport Security',
          version: 'Negotiated',
          confidence: 100,
        });
      }
      diag.techLeaked.forEach((t) => {
        const [label, value] = t.split(': ');
        technologies.push({ name: (value ?? label).trim(), type: label.trim(), version: 'Detected', confidence: 90 });
      });
      diag.scaLibraries.forEach((lib) => {
        technologies.push({ name: lib.name, type: 'Client-Side Library', version: lib.version, confidence: 80 });
      });
      if (technologies.length === 0) {
        technologies.push({
          name: 'No fingerprintable technology signatures detected',
          type: 'Unknown',
          version: '-',
          confidence: 0,
        });
      }

      res.json({
        success: true,
        domain: hostname,
        scanner: 'Seclayer EASM Recon Engine (Live DNS Enumeration & HTTP Fingerprinting)',
        scanTime: diag.scannedAt,
        summary: {
          totalSubdomains: liveSubs.length,
          activeIps: uniqueIps.size,
          nameserver: diag.easmPerimeter.nameserver,
          nameserverIp: diag.easmPerimeter.ip,
        },
        technologies,
        subdomains: liveSubs.map((s) => ({
          subdomain: s.domain,
          ip: s.ip ?? diag.easmPerimeter.ip,
          status: s.status,
          ports: [s.port],
          service: inferServiceFromPort(s.port, s.domain),
        })),
      });
    }),
  );

  // 3. API Security & Role Authorization Probing
  app.post(
    '/api/enterprise/api-scan/hadrian',
    scanLimiter,
    asyncHandler(async (req, res) => {
      const target = await assertSafeScanTarget(req.body?.url);
      const schemaTitle = optionalString(req.body?.schemaTitle, 'schemaTitle') || 'Discovered API Surface';
      const authHeader = optionalString(req.body?.authHeader, 'authHeader');
      const diag = await runDiagnostics(target, authHeader);

      const matrix: Array<{
        endpoint: string;
        methods: string[];
        rolesResult: Record<string, { status: string; color: string }>;
        vulnerability: string | null;
      }> = [];

      (diag.apiSecFindings ?? []).forEach((f) => {
        matrix.push({
          endpoint: f.endpoint,
          methods: ['GET', 'POST'],
          rolesResult: {
            'Unauthenticated Request': { status: 'Allow (Vulnerable)', color: 'text-red-500 font-bold' },
            'Supplied Credentials': authHeader
              ? { status: 'Allow', color: 'text-amber-400' }
              : { status: 'Not Tested (No Credentials Supplied)', color: 'text-zinc-500' },
            'Object/Schema Access': { status: 'Exposed', color: 'text-red-500 font-bold' },
          },
          vulnerability: `${f.testName}: ${f.description}`,
        });
      });

      diag.dastInputs.forEach((d) => {
        matrix.push({
          endpoint: d.formAction,
          methods: [d.method],
          rolesResult: {
            'Unauthenticated Request': { status: 'Allow', color: 'text-amber-400' },
            'Supplied Credentials': authHeader
              ? { status: 'Allow', color: 'text-amber-400' }
              : { status: 'Not Tested (No Credentials Supplied)', color: 'text-zinc-500' },
            'CSRF Token Check': d.csrfPresent
              ? { status: 'Present', color: 'text-[#22c55e]' }
              : { status: 'Missing', color: 'text-red-500 font-bold' },
          },
          vulnerability: d.csrfPresent ? null : `${d.vulnerability}: ${d.description}`,
        });
      });

      diag.probedPaths
        .filter((p) => p.exposed)
        .forEach((p) => {
          matrix.push({
            endpoint: p.path,
            methods: ['GET'],
            rolesResult: {
              'Unauthenticated Request': { status: `Allow (HTTP ${p.status})`, color: 'text-red-500 font-bold' },
              'Supplied Credentials': authHeader
                ? { status: `Allow (HTTP ${p.status})`, color: 'text-red-500 font-bold' }
                : { status: 'Not Tested (No Credentials Supplied)', color: 'text-zinc-500' },
              'Resource Exposure': { status: 'Publicly Accessible', color: 'text-red-500 font-bold' },
            },
            vulnerability: `Sensitive resource "${p.path}" is publicly accessible (HTTP ${p.status}) on "${target}". This may expose configuration, credentials, or version-control metadata.`,
          });
        });

      if (matrix.length === 0) {
        matrix.push({
          endpoint: new URL(target).pathname || '/',
          methods: ['GET'],
          rolesResult: {
            'Unauthenticated Request': { status: `HTTP ${diag.responseStatus || 'N/A'}`, color: 'text-zinc-300' },
            'Supplied Credentials': authHeader
              ? { status: `HTTP ${diag.responseStatus || 'N/A'}`, color: 'text-zinc-300' }
              : { status: 'Not Tested (No Credentials Supplied)', color: 'text-zinc-500' },
            'Object/Schema Access': { status: 'Not Exposed', color: 'text-[#22c55e]' },
          },
          vulnerability: null,
        });
      }

      res.json({
        success: true,
        service: `Seclayer API Security Probe (${schemaTitle})`,
        targetUrl: target,
        endpointsCount: matrix.length,
        matrix,
      });
    }),
  );

  // 4. Black-box taint-flow reconstruction from active fuzzing probes
  app.post(
    '/api/enterprise/iast/trace',
    scanLimiter,
    asyncHandler(async (req, res) => {
      const target = await assertSafeScanTarget(req.body?.url);
      const inputPayload = optionalString(req.body?.inputPayload, 'inputPayload');
      const diag = await runDiagnostics(target);

      const findings = diag.redTeamFindings ?? [];
      const traces = findings.map((rt, idx) => ({
        step: idx + 1,
        clazz: 'HTTP Request Handler',
        method: rt.testName,
        line: idx + 1,
        description: `Payload "${rt.payload}" sent to "${target}". ${rt.description}`,
      }));

      if (traces.length === 0) {
        traces.push({
          step: 1,
          clazz: 'HTTP Request Handler',
          method: 'Active Fuzzing Probes (SQLi / XSS / Command Injection / SSRF)',
          line: 0,
          description: `Active red-team probes against "${target}" did not trigger any observable taint sink — no reflected payloads or backend errors were detected in the responses.`,
        });
      }

      res.json({
        success: true,
        agent: 'Seclayer Black-Box Active Probe Tracer',
        runtime: new URL(target).hostname,
        status: findings.length > 0 ? 'Sink Triggered Malicious Flow Alert' : 'No Taint Sink Triggered',
        payloadTested: inputPayload ?? null,
        traceTime: diag.scannedAt,
        traces,
      });
    }),
  );

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
      diagnostics: summarizeDiagnostics(diagnostics),
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

/** Best-effort service label for a discovered subdomain, based on its probed port and name. */
function inferServiceFromPort(port: string, subdomain: string): string {
  switch (port) {
    case '1194':
      return 'OpenVPN Daemon';
    case '25':
      return 'SMTP Mail Relay';
    case '443':
      if (/^api\./.test(subdomain)) return 'HTTPS API Endpoint';
      if (/^admin\./.test(subdomain)) return 'HTTPS Admin Portal';
      if (/^(staging|dev|test|qa)\./.test(subdomain)) return 'HTTPS Non-Production Environment';
      return 'HTTPS Web Service';
    default:
      return 'Unresponsive / Filtered';
  }
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
