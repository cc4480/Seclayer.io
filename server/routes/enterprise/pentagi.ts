import type { Express, RequestHandler } from 'express';
import { asyncHandler } from '../../middleware.js';
import { runDiagnostics, compileStaticFindings } from '../../scanner.js';
import { assertSafeScanTarget } from '../../validation.js';
import { derivePentagiEvidence } from '../../pentagi.js';
import { generatePentagiLogs } from '../../deepseek.js';

/**
 * PentAGI Autonomous Pentest Agent: runs a live black-box scan of the target,
 * then renders a multi-agent activity feed grounded entirely in the evidence
 * the scan actually produced (AI-narrated when configured, deterministic
 * otherwise). No fabricated exploit chains.
 */
export function registerPentagiRoutes(app: Express, scanLimiter: RequestHandler): void {
  app.get(
    '/api/enterprise/pentagi/logs',
    scanLimiter,
    asyncHandler(async (req, res) => {
      const target = await assertSafeScanTarget(req.query.url);
      const diag = await runDiagnostics(target);
      const compiled = compileStaticFindings(diag);
      const evidence = derivePentagiEvidence(target, diag, compiled);
      const logs = await generatePentagiLogs(evidence);

      res.json({
        success: true,
        engine: 'PentAGI Autonomous Multi-Agent Multi-Step Pentest Coordinator',
        agents: ['Scout', 'Exploiter', 'Reporter'],
        target,
        severity: evidence.worstSeverity,
        score: evidence.score,
        findingsCount: evidence.totalFindings,
        logs,
      });
    }),
  );
}
