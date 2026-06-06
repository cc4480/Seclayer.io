import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import { createServer as createViteServer } from 'vite';
import { db, LocalFileDb } from './server/db.js';
import { runDiagnostics, compileStaticFindings } from './server/scanner.js';
import { generateAiReport } from './server/ai.js';
import { runPentagiExploit } from './server/pentagi.js';
import { signToken, verifyToken, hashPassword, verifyPassword } from './server/auth.js';

declare global {
  namespace Express {
    interface Request {
      userId?: string;
    }
  }
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  const token = authHeader.substring(7);
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token. Please sign in again.' });
  }
  req.userId = payload.userId;
  next();
}

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const scanLimiter = rateLimit({ windowMs: 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false });

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

  async function processScanJob(scanId: string) {
    try {
      dbInstance.appendScanLog(scanId, '[SYSTEM] Scan job started');
      dbInstance.updateScan(scanId, { status: 'scanning' });

      const scan = dbInstance.getScan(scanId);
      if (!scan) return;

      dbInstance.appendScanLog(scanId, `[SCANNER] Running diagnostics against ${scan.url}`);
      const diagnostics = await runDiagnostics(scan.url, scan.authHeader);

      dbInstance.appendScanLog(scanId, `[SCANNER] HTTP ${diagnostics.responseStatus} — SSL: ${diagnostics.sslSecure ? 'valid' : 'insecure'}`);
      if (diagnostics.missingHeaders.length > 0) {
        dbInstance.appendScanLog(scanId, `[HEADERS] Missing security headers: ${diagnostics.missingHeaders.join(', ')}`);
      }
      if (diagnostics.techLeaked.length > 0) {
        dbInstance.appendScanLog(scanId, `[EASM] Technology signatures exposed: ${diagnostics.techLeaked.join(', ')}`);
      }
      if (diagnostics.probedPaths.some(p => p.exposed)) {
        const exposed = diagnostics.probedPaths.filter(p => p.exposed).map(p => p.path);
        dbInstance.appendScanLog(scanId, `[DAST] Exposed sensitive paths: ${exposed.join(', ')}`);
      }

      dbInstance.appendScanLog(scanId, '[AI] Compiling static findings and scoring...');
      const staticCompiled = compileStaticFindings(diagnostics);

      dbInstance.appendScanLog(scanId, '[AI] Forwarding diagnostics to DeepSeek for analysis...');
      dbInstance.updateScan(scanId, { status: 'analyzing' });

      const outputReport = await generateAiReport(scan.url, diagnostics, staticCompiled);

      dbInstance.updateScan(scanId, {
        status: 'complete',
        score: outputReport.score,
        severity: outputReport.severity,
        findings: outputReport.findings,
        aiSummary: outputReport.aiSummary,
        completedAt: new Date().toISOString(),
      });
      dbInstance.appendScanLog(scanId, `[COMPLETE] Score: ${outputReport.score}/100 — ${outputReport.findings.length} findings`);
    } catch (err: any) {
      console.error(`[Scanner] Scan ${scanId} failed:`, err.message);
      dbInstance.appendScanLog(scanId, `[ERROR] Scan failed: ${err.message}`);
      dbInstance.updateScan(scanId, {
        status: 'failed',
        error: err.message || 'Scan failed due to an unexpected error.',
      });
    }
  }

  // --- PUBLIC ROUTES ---

  app.get('/api/system/health', (_req, res) => {
    res.json({ status: 'Online', version: 'v2.2.0', timestamp: new Date().toISOString() });
  });

  app.post('/api/auth/register', authLimiter, (req, res) => {
    const { email, password } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ message: 'Valid email address is required.' });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters.' });
    }
    try {
      const passwordHash = hashPassword(password);
      const user = dbInstance.registerUser(email, passwordHash);
      const token = signToken(user.id);
      res.status(201).json({ token, user });
    } catch (err: any) {
      res.status(409).json({ message: err.message });
    }
  });

  app.post('/api/auth/login', authLimiter, (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    const dbUser = dbInstance.findUserByEmail(email);
    if (!dbUser) {
      return res.status(401).json({ message: 'No account found with this email. Please register first.' });
    }
    if (!dbUser.passwordHash || !verifyPassword(password, dbUser.passwordHash)) {
      return res.status(401).json({ message: 'Incorrect password.' });
    }
    const user = dbInstance.getUser(dbUser.id)!;
    const token = signToken(user.id);
    res.json({ token, user });
  });

  app.post('/api/auth/logout', (_req, res) => {
    res.json({ status: 'ok' });
  });

  // MCP endpoint — authenticated via API key (not JWT)
  app.post('/api/mcp/scan', scanLimiter, async (req, res) => {
    const { url, apiKey, authHeader } = req.body;
    if (!url || !apiKey) {
      return res.status(400).json({ error: 'url and apiKey are required.' });
    }
    const apiKeyObj = dbInstance.findApiKey(apiKey);
    if (!apiKeyObj || !apiKeyObj.active) {
      return res.status(401).json({ error: 'Invalid or revoked API key.' });
    }
    const user = dbInstance.getUser(apiKeyObj.userId);
    if (!user) {
      return res.status(401).json({ error: 'API key owner not found.' });
    }
    try {
      const diagnostics = await runDiagnostics(url, authHeader);
      const staticCompiled = compileStaticFindings(diagnostics);
      const aiReport = await generateAiReport(url, diagnostics, staticCompiled);

      const completedScan = dbInstance.createScan(user.id, url, authHeader);
      dbInstance.updateScan(completedScan.id, {
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
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Scan failed.', details: err.message });
    }
  });

  // --- PROTECTED ROUTES ---

  app.get('/api/auth/me', requireAuth, (req, res) => {
    const user = dbInstance.getUser(req.userId!);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({ user });
  });

  // Scans
  app.post('/api/scans', scanLimiter, requireAuth, async (req, res) => {
    const { url, authHeader } = req.body;
    if (!url) return res.status(400).json({ message: 'Target URL is required.' });

    const user = dbInstance.getUser(req.userId!);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    const scan = dbInstance.createScan(req.userId!, url, authHeader);
    processScanJob(scan.id);
    res.json({ status: 'ok', scan });
  });

  app.get('/api/scans', requireAuth, (req, res) => {
    const scansList = dbInstance.listScans(req.userId!).map(s => dbInstance.getScanWithSuppressedFindings(s));
    res.json({ scans: scansList });
  });

  app.get('/api/scans/:id', requireAuth, (req, res) => {
    let scan = dbInstance.getScan(req.params.id);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    scan = dbInstance.getScanWithSuppressedFindings(scan);
    res.json({ scan });
  });

  app.get('/api/scans/:id/logs', requireAuth, (req, res) => {
    const scan = dbInstance.getScan(req.params.id);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    res.json({ logs: dbInstance.getScanLogs(req.params.id) });
  });

  app.get('/api/scans/:id/report', requireAuth, (req, res) => {
    let scan = dbInstance.getScan(req.params.id);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    if (scan.status !== 'complete') {
      return res.status(400).json({ error: 'Scan is not complete yet.' });
    }
    scan = dbInstance.getScanWithSuppressedFindings(scan);
    res.json({
      scanId: scan.id, url: scan.url, score: scan.score, severity: scan.severity,
      aiSummary: scan.aiSummary, findings: scan.findings,
      createdAt: scan.createdAt, completedAt: scan.completedAt,
    });
  });

  // Suppressions
  app.get('/api/suppressions', requireAuth, (req, res) => {
    res.json({ suppressions: dbInstance.listSuppressions(req.userId!) });
  });

  app.post('/api/suppressions', requireAuth, (req, res) => {
    const { targetUrl, findingTitle, reason } = req.body;
    if (!targetUrl || !findingTitle) {
      return res.status(400).json({ error: 'targetUrl and findingTitle are required.' });
    }
    const rule = dbInstance.addSuppression(req.userId!, targetUrl, findingTitle, reason || 'False positive');
    res.json({ status: 'ok', rule });
  });

  app.delete('/api/suppressions/:id', requireAuth, (req, res) => {
    const success = dbInstance.removeSuppression(req.userId!, req.params.id);
    if (!success) return res.status(404).json({ error: 'Suppression rule not found.' });
    res.json({ status: 'ok' });
  });

  app.post('/api/scans/:scanId/findings/:findingId/suppress', requireAuth, (req, res) => {
    const { scanId, findingId } = req.params;
    const { reason = 'Manual validation' } = req.body;
    const scan = dbInstance.getScan(scanId);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    const finding = scan.findings?.find(f => f.id === findingId);
    if (!finding) return res.status(404).json({ error: 'Finding not found.' });
    const rule = dbInstance.addSuppression(req.userId!, scan.url, finding.title, reason);
    res.json({ status: 'ok', rule });
  });

  // Monitoring
  app.get('/api/monitoring', requireAuth, (req, res) => {
    res.json({ monitoredTargets: dbInstance.listMonitoredTargets(req.userId!) });
  });

  app.post('/api/monitoring', requireAuth, (req, res) => {
    const { url, frequencyDays = 7, scheduleString } = req.body;
    if (!url) return res.status(400).json({ error: 'url is required.' });
    const target = dbInstance.addMonitoredTarget(req.userId!, url, frequencyDays, scheduleString);
    res.json({ status: 'ok', target });
  });

  app.delete('/api/monitoring/:id', requireAuth, (req, res) => {
    const success = dbInstance.removeMonitoredTarget(req.userId!, req.params.id);
    if (!success) return res.status(404).json({ error: 'Monitored target not found.' });
    res.json({ status: 'ok' });
  });

  // API Keys
  app.get('/api/keys', requireAuth, (req, res) => {
    res.json({ keys: dbInstance.listApiKeys(req.userId!) });
  });

  app.post('/api/keys', requireAuth, (req, res) => {
    const keyObj = dbInstance.generateApiKey(req.userId!);
    res.json({ status: 'ok', key: keyObj });
  });

  app.delete('/api/keys/:id', requireAuth, (req, res) => {
    const success = dbInstance.revokeApiKey(req.userId!, req.params.id);
    if (!success) return res.status(404).json({ error: 'Key not found.' });
    res.json({ status: 'ok' });
  });

  // --- ENTERPRISE ENDPOINTS ---

  // 1. ASPM — correlate findings across user's completed scans
  app.post('/api/enterprise/aspm/correlate', requireAuth, (req, res) => {
    const { url } = req.body;
    const userScans = dbInstance.listScans(req.userId!).filter(s => {
      if (s.status !== 'complete') return false;
      if (url) return s.url.toLowerCase().includes(url.toLowerCase().replace(/https?:\/\//i, ''));
      return true;
    });

    if (userScans.length === 0) {
      return res.json({
        success: true,
        targetUrl: url || 'all targets',
        scansAnalyzed: 0,
        message: 'No completed scans found for correlation. Run scans first.',
        correlatedFindings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      });
    }

    const findingMap = new Map<string, {
      title: string; severity: string; category: string;
      occurrences: number; seenIn: string[]; description: string; fix: string;
    }>();

    userScans.forEach(scan => {
      (scan.findings || []).forEach(f => {
        if (f.isFalsePositive) return;
        const existing = findingMap.get(f.title);
        if (existing) {
          existing.occurrences++;
          if (!existing.seenIn.includes(scan.url)) existing.seenIn.push(scan.url);
        } else {
          findingMap.set(f.title, {
            title: f.title, severity: f.severity, category: f.category,
            description: f.description, fix: f.fix,
            occurrences: 1, seenIn: [scan.url],
          });
        }
      });
    });

    const all = Array.from(findingMap.values()).sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity as keyof typeof order] ?? 5) - (order[b.severity as keyof typeof order] ?? 5);
    });

    const summary = { total: all.length, critical: 0, high: 0, medium: 0, low: 0 };
    all.forEach(f => { if (f.severity in summary) (summary as any)[f.severity]++; });

    res.json({
      success: true,
      targetUrl: url || 'all targets',
      scansAnalyzed: userScans.length,
      correlatedFindings: all,
      summary,
    });
  });

  // 2. EASM — real DNS + certificate transparency via crt.sh
  app.post('/api/enterprise/easm/recon', requireAuth, async (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain is required.' });

    const cleanDomain = domain.replace(/https?:\/\//i, '').split('/')[0].trim();

    try {
      const dns = await import('dns/promises');

      const [ipResult, nsResult, mxResult] = await Promise.allSettled([
        dns.resolve4(cleanDomain),
        dns.resolveNs(cleanDomain),
        dns.resolveMx(cleanDomain),
      ]);

      const ip = ipResult.status === 'fulfilled' ? ipResult.value[0] : 'N/A';
      const nameservers = nsResult.status === 'fulfilled' ? nsResult.value : [];
      const mxRecords = mxResult.status === 'fulfilled'
        ? mxResult.value.map(r => ({ exchange: r.exchange, priority: r.priority }))
        : [];

      let ctSubdomains: string[] = [];
      try {
        const ctController = new AbortController();
        const ctTimeout = setTimeout(() => ctController.abort(), 8000);
        const ctRes = await fetch(
          `https://crt.sh/?q=%.${cleanDomain}&output=json`,
          { signal: ctController.signal }
        );
        clearTimeout(ctTimeout);
        if (ctRes.ok) {
          const ctData = await ctRes.json() as Array<{ name_value: string }>;
          const names = new Set<string>();
          ctData.forEach(entry => {
            if (entry.name_value) {
              entry.name_value.split('\n').forEach(name => {
                const clean = name.trim().toLowerCase().replace(/^\*\./, '');
                if (clean.endsWith(`.${cleanDomain}`) && clean !== cleanDomain) {
                  names.add(clean);
                }
              });
            }
          });
          ctSubdomains = Array.from(names).slice(0, 30);
        }
      } catch (e) {
        console.warn('crt.sh lookup failed:', e);
      }

      const subdomainResults = await Promise.all(
        ctSubdomains.map(async sub => {
          try {
            const records = await dns.resolve4(sub);
            return { subdomain: sub, ip: records[0], status: 'live' };
          } catch {
            return { subdomain: sub, ip: 'N/A', status: 'inactive' };
          }
        })
      );

      res.json({
        success: true,
        domain: cleanDomain,
        scannedAt: new Date().toISOString(),
        ip,
        nameservers,
        mxRecords,
        subdomains: subdomainResults,
        summary: {
          totalDiscovered: ctSubdomains.length,
          live: subdomainResults.filter(s => s.status === 'live').length,
        },
      });
    } catch (err: any) {
      res.status(500).json({ error: 'EASM recon failed.', details: err.message });
    }
  });

  // 3. API Security Scan — real HTTP endpoint discovery and testing
  app.post('/api/enterprise/api-scan/hadrian', requireAuth, async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'url is required.' });

    let targetUrl = url.trim();
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

    const specPaths = [
      '/openapi.json', '/swagger.json', '/api-docs', '/api/docs',
      '/api/v1/docs', '/swagger/v1/swagger.json', '/v1/openapi.json', '/docs/openapi.json',
    ];

    let spec: any = null;
    let specPath = '';
    for (const p of specPaths) {
      try {
        const ctrl = new AbortController();
        const id = setTimeout(() => ctrl.abort(), 3000);
        const r = await fetch(`${targetUrl}${p}`, {
          signal: ctrl.signal,
          headers: { Accept: 'application/json' },
        });
        clearTimeout(id);
        if (r.ok && r.headers.get('content-type')?.includes('json')) {
          const data = await r.json();
          if (data.openapi || data.swagger || data.paths) {
            spec = data;
            specPath = p;
            break;
          }
        }
      } catch { /* not found */ }
    }

    const findings: Array<{
      endpoint: string; issue: string; severity: string; description: string; fix: string;
    }> = [];

    try {
      const ctrl = new AbortController();
      const id = setTimeout(() => ctrl.abort(), 4000);
      const r = await fetch(`${targetUrl}/graphql`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: '{__schema{types{name}}}' }),
        signal: ctrl.signal,
      });
      clearTimeout(id);
      if (r.ok) {
        const text = await r.text();
        if (text.includes('__schema') || text.includes('__Type')) {
          findings.push({
            endpoint: '/graphql', issue: 'GraphQL Introspection Enabled',
            severity: 'high',
            description: 'GraphQL introspection is globally accessible. Attackers can dump the full API schema without authentication.',
            fix: 'Disable introspection in production. Set introspection: false in your GraphQL server config.',
          });
        }
      }
    } catch { /* not exposed */ }

    try {
      const ctrl = new AbortController();
      const id = setTimeout(() => ctrl.abort(), 3000);
      const r = await fetch(`${targetUrl}/actuator/env`, { signal: ctrl.signal });
      clearTimeout(id);
      if (r.ok) {
        findings.push({
          endpoint: '/actuator/env', issue: 'Spring Boot Actuator Exposed',
          severity: 'critical',
          description: 'The Spring Boot /actuator/env endpoint is publicly accessible, potentially exposing configuration variables and secrets.',
          fix: 'Restrict actuator endpoints to internal networks only. Configure management.endpoints.web.exposure.include appropriately.',
        });
      }
    } catch { /* not exposed */ }

    const specEndpoints = spec ? Object.keys(spec.paths || {}).slice(0, 20) : [];

    res.json({
      success: true,
      targetUrl,
      scannedAt: new Date().toISOString(),
      specFound: !!spec,
      specPath: specPath || null,
      specTitle: spec?.info?.title || null,
      specVersion: spec?.info?.version || null,
      endpoints: specEndpoints,
      endpointCount: specEndpoints.length,
      findings,
    });
  });

  // 4. IAST — requires runtime agent instrumentation
  app.post('/api/enterprise/iast/trace', requireAuth, (_req, res) => {
    res.status(501).json({
      success: false,
      feature: 'IAST Runtime Instrumentation',
      message: 'IAST requires a Seclayer agent deployed inside your application runtime. The agent instruments bytecode at the JVM, Node.js, or Python interpreter level to trace taint flows in real time.',
      setupRequired: [
        'Install the Seclayer IAST agent library for your platform (Java/Node.js/Python)',
        'Configure your application startup to load the agent',
        'Trigger application flows — the agent reports findings here automatically',
      ],
      docsUrl: 'https://docs.seclayer.io/iast-agent',
    });
  });

  // 5. PentAGI — real multi-stage automated exploit runner
  app.get('/api/enterprise/pentagi/logs', requireAuth, async (req, res) => {
    const url = req.query.url as string | undefined;
    if (!url) {
      return res.status(400).json({ error: 'Target url query parameter is required.' });
    }
    try {
      const logs = await runPentagiExploit(url);
      res.json({
        success: true,
        engine: 'PentAGI Autonomous Multi-Agent Pentest Coordinator',
        agents: ['Scout Agent', 'Exploiter Agent', 'Reporter Agent'],
        logs,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Centralized error handler
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    console.error('[Error]', err);
    res.status(err.status ?? 500).json({ error: err.message ?? 'Internal server error.' });
  });

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

  app.listen(3000, '0.0.0.0', () => {
    console.log(`[Seclayer] Listening on http://0.0.0.0:3000`);
  });
}

if (!process.env.VITEST) {
  startServer().catch(err => {
    console.error('Server bootstrap error:', err);
    process.exit(1);
  });
}
