import type { Express, RequestHandler } from 'express';
import { asyncHandler } from '../../middleware.js';
import { runDiagnostics } from '../../scanner.js';
import { assertSafeScanTarget, optionalString } from '../../validation.js';
import { buildHadrianMatrix } from '../../enterprise-helpers.js';

/** API Security & Role Authorization Probing: per-endpoint role/auth matrix. */
export function registerHadrianRoutes(app: Express, scanLimiter: RequestHandler): void {
  app.post(
    '/api/enterprise/api-scan/hadrian',
    scanLimiter,
    asyncHandler(async (req, res) => {
      const target = await assertSafeScanTarget(req.body?.url);
      const schemaTitle = optionalString(req.body?.schemaTitle, 'schemaTitle') || 'Discovered API Surface';
      const authHeader = optionalString(req.body?.authHeader, 'authHeader');
      const diag = await runDiagnostics(target, authHeader);

      const matrix = buildHadrianMatrix(diag, target, authHeader);

      res.json({
        success: true,
        service: `Seclayer API Security Probe (${schemaTitle})`,
        targetUrl: target,
        endpointsCount: matrix.length,
        matrix,
      });
    }),
  );
}
