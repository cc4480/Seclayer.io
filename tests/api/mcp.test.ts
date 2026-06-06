import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import http from 'http';
import { makeTestApp, registerAndLogin } from '../helpers.js';
import type { Express } from 'express';
import type { LocalFileDb } from '../../server/db.js';

let app: Express;
let db: LocalFileDb;
let cleanup: () => void;

// Minimal HTTP target server — returns a real HTTP response for scanner tests
let targetServer: http.Server;
let targetUrl: string;

beforeEach(async () => {
  ({ app, db, cleanup } = makeTestApp());

  targetServer = http.createServer((_req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'X-Powered-By': 'Express',
    });
    res.end('<html><body>Test page</body></html>');
  });

  await new Promise<void>(resolve => {
    targetServer.listen(0, '127.0.0.1', () => {
      const addr = targetServer.address() as { port: number };
      targetUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

afterEach(async () => {
  cleanup();
  await new Promise<void>(resolve => targetServer.close(() => resolve()));
});

describe('POST /api/mcp/scan', () => {
  it('returns 400 when url or apiKey are missing', async () => {
    const res1 = await request(app).post('/api/mcp/scan').send({ apiKey: 'sl_live_abc' });
    expect(res1.status).toBe(400);

    const res2 = await request(app).post('/api/mcp/scan').send({ url: 'https://example.com' });
    expect(res2.status).toBe(400);
  });

  it('returns 401 for an invalid API key', async () => {
    const res = await request(app)
      .post('/api/mcp/scan')
      .send({ url: 'https://example.com', apiKey: 'sl_live_totally_invalid' });
    expect(res.status).toBe(401);
    expect(res.body.error).toContain('Invalid');
  });

  it('returns 401 for a revoked API key', async () => {
    const { user } = registerAndLogin(db);
    const key = db.generateApiKey(user.id);
    db.revokeApiKey(user.id, key.id);

    const res = await request(app)
      .post('/api/mcp/scan')
      .send({ url: 'https://example.com', apiKey: key.key });
    expect(res.status).toBe(401);
  });

  it('runs a real scan against the local test server and returns structured results', async () => {
    const { user } = registerAndLogin(db);
    const keyObj = db.findApiKey(
      db.listApiKeys(user.id)[0].key
    );

    const res = await request(app)
      .post('/api/mcp/scan')
      .send({ url: targetUrl, apiKey: keyObj!.key });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.targetUrl).toBe(targetUrl);
    expect(typeof res.body.postureScore).toBe('number');
    expect(res.body.postureScore).toBeGreaterThanOrEqual(10);
    expect(res.body.postureScore).toBeLessThanOrEqual(100);
    expect(['info', 'low', 'medium', 'high', 'critical']).toContain(res.body.vulnerabilityLevel);
    expect(typeof res.body.analysisSummary).toBe('string');
    expect(Array.isArray(res.body.securityFindings)).toBe(true);

    // Verify the scan was persisted in the database
    const scans = db.listScans(user.id).filter(s => s.url === targetUrl);
    expect(scans.length).toBeGreaterThan(0);
    expect(scans[0].status).toBe('complete');
  }, 60000);
});
