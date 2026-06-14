import type { Express, RequestHandler } from 'express';
import { db } from '../db.js';
import { HttpError, asyncHandler, currentUserId } from '../middleware.js';
import { runDiagnostics, compileStaticFindings, summarizeDiagnostics } from '../scanner.js';
import { generateAiReport } from '../deepseek.js';
import { assertSafeScanTarget, requireString, optionalString } from '../validation.js';

/** Developer API key management plus the synchronous MCP scan tool-call endpoint. */
export function registerMcpRoutes(app: Express, scanLimiter: RequestHandler): void {
  app.get('/api/keys', (req, res) => {
    const userId = currentUserId(req);
    const keys = db.listApiKeys(userId);
    res.json({ keys });
  });

  app.post('/api/keys', (req, res) => {
    const userId = currentUserId(req);
    const user = db.getUser(userId);
    if (!user) throw new HttpError(404, 'User not found');
    const keyObj = db.generateApiKey(userId);
    res.json({ status: 'ok', key: keyObj });
  });

  app.delete('/api/keys/:id', (req, res) => {
    const userId = currentUserId(req);
    const success = db.revokeApiKey(userId, req.params.id);
    if (!success) {
      throw new HttpError(404, 'Key not found or could not be revoked');
    }
    res.json({ status: 'ok' });
  });

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
}
