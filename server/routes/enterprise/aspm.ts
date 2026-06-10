import type { Express, RequestHandler } from 'express';
import { asyncHandler } from '../../middleware.js';
import { runDiagnostics, compileStaticFindings } from '../../scanner.js';
import { assertSafeScanTarget } from '../../validation.js';

/** ASPM & Signal Correlation Engine: fuses SAST, EASM, and DAST signals into one report. */
export function registerAspmRoutes(app: Express, scanLimiter: RequestHandler): void {
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
}
