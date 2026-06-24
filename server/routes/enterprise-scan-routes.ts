import { Express } from 'express';
import { LocalFileDb } from '../db.js';
import { runPentagiExploit } from '../pentagi.js';
import { requireAuth } from '../middleware.js';
import { validateTargetUrl, resolveAuthProfile } from '../scan-pipeline-helpers.js';

/** Enterprise endpoints: API security scan (OpenAPI/GraphQL/Actuator probing), IAST stub, and the PentAGI streaming runner. */
export function registerEnterpriseScanRoutes(app: Express, dbInstance: LocalFileDb) {
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

    let authHeaders: Record<string, string> = {};
    if (authProfileId) {
      const profile = dbInstance.getAuthProfile(req.userId!, authProfileId);
      if (profile) authHeaders = await resolveAuthProfile(profile);
    }

    // Stream the run as newline-delimited JSON so the client renders each agent
    // event as it actually happens during the live exploitation run.
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('X-Accel-Buffering', 'no');
    const write = (obj: unknown) => res.write(JSON.stringify(obj) + '\n');
    write({
      type: 'meta',
      engine: 'PentAGI Automated Exploitation Engine',
      agents: ['Scout Agent', 'Exploiter Agent', 'Reporter Agent'],
      authenticated: Object.keys(authHeaders).length > 0,
    });

    try {
      const logs = await runPentagiExploit(url, authHeaders, (entry) => write({ type: 'log', entry }));
      write({ type: 'done', success: true, count: logs.length });
    } catch (err: any) {
      write({ type: 'error', error: err?.message || 'PentAGI run failed.' });
    } finally {
      res.end();
    }
  });
}
