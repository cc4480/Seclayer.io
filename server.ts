import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import { createServer as createViteServer } from 'vite';
import { db, LocalFileDb } from './server/db.js';
import type { AuthProfile } from './src/types.js';
import { runDiagnostics, compileStaticFindings } from './server/scanner.js';
import { generateAiReport } from './server/ai.js';
import { runPentagiExploit } from './server/pentagi.js';
import { signToken, verifyToken, hashPassword, verifyPassword } from './server/auth.js';
import { recordInteraction } from './server/oast.js';

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

/** Accepts either a JWT Bearer token (dashboard) or X-API-Key header / ?apiKey= query (CI pipelines) */
function requireAuthOrApiKey(dbInstance: LocalFileDb) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    if (authHeader?.startsWith('Bearer ')) {
      const payload = verifyToken(authHeader.substring(7));
      if (payload) { req.userId = payload.userId; return next(); }
    }
    const apiKeyStr = (req.headers['x-api-key'] as string | undefined) || (req.query.apiKey as string | undefined);
    if (apiKeyStr) {
      const keyObj = dbInstance.findApiKey(apiKeyStr);
      if (keyObj?.active) {
        const user = dbInstance.getUser(keyObj.userId);
        if (user) { req.userId = user.id; return next(); }
      }
    }
    return res.status(401).json({ error: 'Authentication required. Provide a Bearer token or X-API-Key header.' });
  };
}

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const scanLimiter = rateLimit({ windowMs: 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false });

const PRIVATE_IP_RE = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|0\.0\.0\.0)/i;

/** Returns null when the URL is valid, or an error message string when it should be rejected. */
function validateTargetUrl(raw: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(raw.startsWith('http') ? raw : `https://${raw}`);
  } catch {
    return 'Invalid URL format.';
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return 'Only http and https targets are allowed.';
  }
  if (PRIVATE_IP_RE.test(parsed.hostname)) {
    return 'Scanning private/local addresses is not allowed.';
  }
  return null;
}

/** Resolve an AuthProfile into a concrete headers map. For form type, performs actual login. */
async function resolveAuthProfile(profile: AuthProfile): Promise<Record<string, string>> {
  switch (profile.type) {
    case 'bearer':
      return { Authorization: `Bearer ${profile.headerValue ?? ''}` };
    case 'cookie':
      return { Cookie: profile.headerValue ?? '' };
    case 'header':
      if (!profile.headerName) return {};
      return { [profile.headerName]: profile.headerValue ?? '' };
    case 'basic': {
      const creds = Buffer.from(`${profile.username ?? ''}:${profile.password ?? ''}`).toString('base64');
      return { Authorization: `Basic ${creds}` };
    }
    case 'form': {
      const {
        loginUrl, loginUsername = '', loginPassword = '',
        loginUsernameField = 'username', loginPasswordField = 'password',
      } = profile;
      if (!loginUrl || !loginUsername) return {};

      // Try JSON body login first (most modern apps)
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 8000);
        const res = await fetch(loginUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0' },
          body: JSON.stringify({ [loginUsernameField]: loginUsername, [loginPasswordField]: loginPassword }),
          redirect: 'manual',
          signal: ctrl.signal,
        });
        const body = await res.text().catch(() => '');
        try {
          const json = JSON.parse(body);
          const token = json.token || json.access_token || json.accessToken || json.jwt || json.id_token || json.authToken;
          if (token && typeof token === 'string') return { Authorization: `Bearer ${token}` };
        } catch {}
        const setCookie = res.headers.get('set-cookie');
        if (setCookie && [200, 201, 302, 301].includes(res.status)) {
          return { Cookie: setCookie.split(';')[0] };
        }
      } catch {}

      // Fallback: form-encoded login
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 8000);
        const res = await fetch(loginUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0' },
          body: new URLSearchParams({ [loginUsernameField]: loginUsername, [loginPasswordField]: loginPassword }).toString(),
          redirect: 'manual',
          signal: ctrl.signal,
        });
        const setCookie = res.headers.get('set-cookie');
        if (setCookie && [200, 201, 302, 301].includes(res.status)) {
          return { Cookie: setCookie.split(';')[0] };
        }
      } catch {}

      return {};
    }
    default:
      return {};
  }
}

/** Convert a completed scan's findings to SARIF 2.1.0 for GitHub Security tab upload */
function generateSarif(scan: import('./src/types.js').Scan) {
  const lvl = (s: string) => s === 'critical' || s === 'high' ? 'error' : s === 'medium' ? 'warning' : 'note';
  const score = (s: string) => s === 'critical' ? '9.5' : s === 'high' ? '7.5' : s === 'medium' ? '5.0' : '2.0';
  const slug = (t: string) => t.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

  const findings = scan.findings ?? [];
  const ruleMap = new Map<string, typeof findings[0]>();
  for (const f of findings) if (!ruleMap.has(slug(f.title))) ruleMap.set(slug(f.title), f);

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Seclayer',
          version: '2.2.0',
          informationUri: 'https://seclayer.io',
          rules: [...ruleMap.entries()].map(([id, f]) => ({
            id,
            name: f.title,
            shortDescription: { text: f.title },
            fullDescription: { text: f.description },
            help: { text: `Fix: ${f.fix}`, markdown: `**Fix:** ${f.fix}` },
            helpUri: 'https://seclayer.io',
            properties: { 'security-severity': score(f.severity), tags: ['security', f.severity] },
          })),
        },
      },
      results: findings.map(f => ({
        ruleId: slug(f.title),
        level: lvl(f.severity),
        message: { text: `${f.description}\n\nFix: ${f.fix}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.endpoint || scan.url } } }],
        properties: { severity: f.severity, category: f.category },
      })),
      artifacts: [{ location: { uri: scan.url }, description: { text: 'Seclayer scan target' } }],
      properties: { seclayerScore: scan.score, seclayerSeverity: scan.severity },
    }],
  };
}

/** Distil the full DiagnosticResult into the compact real data surfaced in the report's raw drawer. */
function buildScanDiagnostics(diag: import('./server/scanner.js').DiagnosticResult): import('./src/types.js').ScanDiagnostics {
  return {
    responseStatus: diag.responseStatus,
    requestHeaders: {
      'User-Agent': 'Seclayer-Security-Scanner/2.0 (seclayer.io; scanner@seclayer.io)',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    },
    responseHeaders: diag.headers,
    ip: diag.easmPerimeter.ip,
    nameserver: diag.easmPerimeter.nameserver,
    protocol: diag.easmPerimeter.protocol,
    probedPaths: diag.probedPaths,
    techLeaked: diag.techLeaked,
    missingHeaders: diag.missingHeaders,
    liveSubdomains: diag.easmPerimeter.subdomains.filter(s => s.status === 'live').length,
  };
}

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

  async function fireWebhook(scan: import('./src/types.js').Scan, status: 'complete' | 'failed') {
    if (!scan.webhookUrl) return;
    try {
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 10000);
      const findings = scan.findings ?? [];
      const payload = {
        event: `scan.${status}`,
        scanId: scan.id,
        url: scan.url,
        status,
        score: scan.score ?? null,
        severity: scan.severity ?? null,
        findingCount: findings.length,
        criticalCount: findings.filter(f => f.severity === 'critical' && !f.isFalsePositive).length,
        highCount: findings.filter(f => f.severity === 'high' && !f.isFalsePositive).length,
        mediumCount: findings.filter(f => f.severity === 'medium' && !f.isFalsePositive).length,
        lowCount: findings.filter(f => f.severity === 'low' && !f.isFalsePositive).length,
        completedAt: scan.completedAt ?? new Date().toISOString(),
        error: scan.error ?? null,
      };
      await fetch(scan.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'Seclayer-Webhook/1.0' },
        body: JSON.stringify(payload),
        signal: ctrl.signal,
      });
    } catch (err: any) {
      console.warn(`[Webhook] Delivery failed for scan ${scan.id}: ${err.message}`);
    }
  }

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

      const completedScan = dbInstance.updateScan(scanId, {
        status: 'complete',
        score: outputReport.score,
        severity: outputReport.severity,
        findings: outputReport.findings,
        aiSummary: outputReport.aiSummary,
        diagnostics: buildScanDiagnostics(diagnostics),
        completedAt: new Date().toISOString(),
      });
      dbInstance.appendScanLog(scanId, `[COMPLETE] Score: ${outputReport.score}/100 — ${outputReport.findings.length} findings`);
      fireWebhook(completedScan, 'complete');
    } catch (err: any) {
      console.error(`[Scanner] Scan ${scanId} failed:`, err.message);
      dbInstance.appendScanLog(scanId, `[ERROR] Scan failed: ${err.message}`);
      const failedScan = dbInstance.updateScan(scanId, {
        status: 'failed',
        error: err.message || 'Scan failed due to an unexpected error.',
      });
      fireWebhook(failedScan, 'failed');
    }
  }

  // --- PUBLIC ROUTES ---

  // OAST callback receiver — no auth, must respond instantly
  app.all('/oast/:token', (req, res) => {
    recordInteraction(req.params.token, req.ip || '', req.path, req.method);
    res.status(200).send('');
  });

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
    const { url, apiKey, authHeader, webhookUrl } = req.body;
    if (!url || !apiKey) {
      return res.status(400).json({ error: 'url and apiKey are required.' });
    }
    const urlErr = validateTargetUrl(url); if (urlErr) return res.status(400).json({ error: urlErr });
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

      const pendingScan = dbInstance.createScan(user.id, url, authHeader);
      const finishedScan = dbInstance.updateScan(pendingScan.id, {
        status: 'complete',
        diagnostics: buildScanDiagnostics(diagnostics),
        score: aiReport.score,
        severity: aiReport.severity,
        findings: aiReport.findings,
        aiSummary: aiReport.aiSummary,
        completedAt: new Date().toISOString(),
        ...(webhookUrl ? { webhookUrl } : {}),
      });
      if (webhookUrl) fireWebhook(finishedScan, 'complete');

      res.json({
        success: true,
        scanId: finishedScan.id,
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
    const { url, authHeader, authProfileId, webhookUrl } = req.body;
    if (!url) return res.status(400).json({ message: 'Target URL is required.' });
    const urlMsg = validateTargetUrl(url); if (urlMsg) return res.status(400).json({ message: urlMsg });

    // Validate webhookUrl if provided — must be http(s) and not SSRF target
    if (webhookUrl) {
      const whErr = validateTargetUrl(webhookUrl);
      if (whErr) return res.status(400).json({ message: `Invalid webhookUrl: ${whErr}` });
    }

    // Resolve auth profile to a header value for the scanner
    let resolvedAuthHeader = authHeader;
    if (authProfileId && !authHeader) {
      const profile = dbInstance.getAuthProfile(req.userId!, authProfileId);
      if (profile) {
        const headers = await resolveAuthProfile(profile);
        if (headers.Authorization) resolvedAuthHeader = headers.Authorization;
        else if (headers.Cookie) resolvedAuthHeader = headers.Cookie;
      }
    }
    const scan = dbInstance.createScan(req.userId!, url, resolvedAuthHeader);
    const updates: Partial<import('./src/types.js').Scan> = {};
    if (authProfileId) updates.authProfileId = authProfileId;
    if (webhookUrl) updates.webhookUrl = webhookUrl;
    if (Object.keys(updates).length) dbInstance.updateScan(scan.id, updates);
    processScanJob(scan.id);
    res.json({ status: 'ok', scan: { ...scan, ...updates } });
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

  app.get('/api/scans/:id/sarif', requireAuthOrApiKey(dbInstance), (req, res) => {
    let scan = dbInstance.getScan(req.params.id);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    if (scan.status !== 'complete') {
      return res.status(400).json({ error: 'Scan is not complete yet.' });
    }
    scan = dbInstance.getScanWithSuppressedFindings(scan);
    const sarif = generateSarif(scan);
    res.setHeader('Content-Type', 'application/sarif+json');
    res.json(sarif);
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
    const urlErr = validateTargetUrl(url); if (urlErr) return res.status(400).json({ error: urlErr });
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

  // --- AUTH PROFILES ---
  app.get('/api/auth-profiles', requireAuth, (req, res) => {
    res.json({ profiles: dbInstance.listAuthProfiles(req.userId!) });
  });

  app.post('/api/auth-profiles', requireAuth, (req, res) => {
    const { name, type, headerName, headerValue, username, password,
            loginUrl, loginUsernameField, loginPasswordField, loginUsername, loginPassword } = req.body;
    if (!name || !type) return res.status(400).json({ error: 'name and type are required.' });
    const VALID_TYPES = ['cookie', 'bearer', 'header', 'basic', 'form'];
    if (!VALID_TYPES.includes(type)) return res.status(400).json({ error: 'Invalid auth type.' });
    const profile = dbInstance.createAuthProfile(req.userId!, {
      name, type, headerName, headerValue, username, password,
      loginUrl, loginUsernameField, loginPasswordField, loginUsername, loginPassword,
    });
    res.status(201).json({ profile });
  });

  app.delete('/api/auth-profiles/:id', requireAuth, (req, res) => {
    const ok = dbInstance.deleteAuthProfile(req.userId!, req.params.id);
    if (!ok) return res.status(404).json({ error: 'Auth profile not found.' });
    res.json({ status: 'ok' });
  });

  app.post('/api/auth-profiles/:id/test', requireAuth, async (req, res) => {
    const profile = dbInstance.getAuthProfile(req.userId!, req.params.id);
    if (!profile) return res.status(404).json({ error: 'Auth profile not found.' });
    const { testUrl } = req.body;
    if (!testUrl) return res.status(400).json({ error: 'testUrl is required.' });
    const urlErr = validateTargetUrl(testUrl);
    if (urlErr) return res.status(400).json({ error: urlErr });
    try {
      const headers = await resolveAuthProfile(profile);
      if (Object.keys(headers).length === 0) {
        return res.json({ success: false, status: 0, message: 'Could not resolve auth credentials (form login may have failed or credentials are incomplete).' });
      }
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 8000);
      const testRes = await fetch(testUrl, { headers: { ...headers, 'User-Agent': 'Mozilla/5.0' }, signal: ctrl.signal });
      const ok = testRes.status < 400;
      // Mark as verified
      dbInstance.updateAuthProfile(req.userId!, req.params.id, { verifiedAt: new Date().toISOString() });
      res.json({
        success: ok,
        status: testRes.status,
        message: ok
          ? `Auth confirmed — ${testUrl} returned HTTP ${testRes.status}`
          : `Auth may be invalid — ${testUrl} returned HTTP ${testRes.status} (401/403 indicates rejected credentials)`,
      });
    } catch (err: any) {
      res.json({ success: false, status: 0, message: `Request failed: ${err.message}` });
    }
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
    const urlErr = validateTargetUrl(url); if (urlErr) return res.status(400).json({ error: urlErr });

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
    const authProfileId = req.query.authProfileId as string | undefined;
    if (!url) {
      return res.status(400).json({ error: 'Target url query parameter is required.' });
    }
    const urlErr = validateTargetUrl(url); if (urlErr) return res.status(400).json({ error: urlErr });
    try {
      let authHeaders: Record<string, string> = {};
      if (authProfileId) {
        const profile = dbInstance.getAuthProfile(req.userId!, authProfileId);
        if (profile) authHeaders = await resolveAuthProfile(profile);
      }
      const logs = await runPentagiExploit(url, authHeaders);
      res.json({
        success: true,
        engine: 'PentAGI Autonomous Multi-Agent Pentest Coordinator',
        agents: ['Scout Agent', 'Exploiter Agent', 'Reporter Agent'],
        authenticated: Object.keys(authHeaders).length > 0,
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
