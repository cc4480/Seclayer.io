import type { Express, RequestHandler } from 'express';
import { asyncHandler } from '../../middleware.js';
import { runDiagnostics } from '../../scanner.js';
import { assertSafeScanTarget, optionalString } from '../../validation.js';

/** Black-box taint-flow reconstruction from active fuzzing probes. */
export function registerIastRoutes(app: Express, scanLimiter: RequestHandler): void {
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
}
