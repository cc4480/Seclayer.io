import express from 'express';
import { db } from '../db.js';
import { runDiagnostics, compileStaticFindings, assertScanTargetSafe } from '../scanner.js';
import { generateAiReport } from '../deepseek.js';

// --- MCP Endpoints ---
// Any external agent can call this with an API key.
export function registerMcpRoutes(app: express.Express): void {
  app.post('/api/mcp/scan', async (req, res) => {
    const { url, apiKey, authHeader } = req.body;
    if (!url || !apiKey) {
      return res.status(400).json({ error: 'Missing parameters. required: url, apiKey' });
    }

    // Reject SSRF / malformed targets before validating the key or spending a credit.
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || 'Target URL cannot be scanned.' });
    }

    // Verify key and deduct 1 credit
    const user = db.validateApiKeyAndDeduct(apiKey, 1);
    if (!user) {
      return res.status(401).json({ error: 'Invalid API Key, active key required, or insufficient credits. Get credits at seclayer.io.' });
    }

    try {
      // Runs scan diagnostic synchronously for MCP tools context
      const diagnostics = await runDiagnostics(url, authHeader);
      const staticCompiled = compileStaticFindings(diagnostics);
      const aiReport = await generateAiReport(url, diagnostics, staticCompiled);

      // Save completed scan in background for dashboard history as well
      const completedScan = db.createScan(user.id, url, authHeader);
      db.updateScan(completedScan.id, {
        status: 'complete',
        score: aiReport.score,
        severity: aiReport.severity,
        findings: aiReport.findings,
        aiSummary: aiReport.aiSummary,
        completedAt: new Date().toISOString()
      });

      res.json({
        success: true,
        targetUrl: url,
        postureScore: aiReport.score,
        vulnerabilityLevel: aiReport.severity,
        analysisSummary: aiReport.aiSummary,
        securityFindings: aiReport.findings,
        creditsRemaining: user.credits
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Internal audit scanning failed', details: err.message });
    }
  });
}
