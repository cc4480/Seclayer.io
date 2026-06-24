import { Express } from 'express';
import { LocalFileDb } from '../db.js';
import { runDiagnostics, compileStaticFindings } from '../scanner.js';
import { runCrawl } from '../crawler.js';
import { generateAiReport } from '../ai.js';
import { signToken, hashPassword, verifyPassword } from '../auth.js';
import { recordInteraction } from '../oast.js';
import { authLimiter, scanLimiter } from '../middleware.js';
import { validateTargetUrl, buildScanDiagnostics, mergeCrawl } from '../scan-pipeline-helpers.js';
import type { ScanJobRunner } from '../scan-job.js';

/** OAST callback, health check, auth register/login/logout, and the API-key-driven MCP scan endpoint. */
export function registerPublicRoutes(app: Express, dbInstance: LocalFileDb, ctx: { fireWebhook: ScanJobRunner['fireWebhook'] }) {
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
      const crawl = await runCrawl(url, { authHeader });
      mergeCrawl(staticCompiled, crawl.findings);
      const aiReport = await generateAiReport(url, diagnostics, staticCompiled);

      const pendingScan = dbInstance.createScan(user.id, url, authHeader);
      const finishedScan = dbInstance.updateScan(pendingScan.id, {
        status: 'complete',
        diagnostics: buildScanDiagnostics(diagnostics),
        crawl: crawl.result,
        score: aiReport.score,
        severity: aiReport.severity,
        findings: aiReport.findings,
        aiSummary: aiReport.aiSummary,
        completedAt: new Date().toISOString(),
        ...(webhookUrl ? { webhookUrl } : {}),
      });
      if (webhookUrl) ctx.fireWebhook(finishedScan, 'complete');

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
}
