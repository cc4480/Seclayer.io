import type { Express, RequestHandler } from 'express';
import { asyncHandler } from '../../middleware.js';
import { runDiagnostics } from '../../scanner.js';
import { assertSafeScanTarget } from '../../validation.js';
import { inferServiceFromPort } from '../../enterprise-helpers.js';

/** EASM Attack Surface Mapping: live DNS enumeration and HTTP fingerprinting. */
export function registerEasmRoutes(app: Express, scanLimiter: RequestHandler): void {
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
}
