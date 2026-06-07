import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import { makeTestApp, registerAndLogin } from '../helpers.js';
import type { Express } from 'express';
import type { LocalFileDb } from '../../server/db.js';

let app: Express;
let db: LocalFileDb;
let cleanup: () => void;

beforeEach(() => {
  ({ app, db, cleanup } = makeTestApp());
});
afterEach(() => cleanup());

// ─── POST /api/scans ─────────────────────────────────────────────────────────

describe('POST /api/scans', () => {
  it('creates a scan in queued status', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://example.com' });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.scan.status).toBe('queued');
    expect(res.body.scan.url).toBe('https://example.com');
  });

  it('returns 400 when url is missing', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app)
      .post('/api/scans')
      .send({ url: 'https://example.com' });
    expect(res.status).toBe(401);
  });

  it('returns 400 for SSRF/private targets', async () => {
    const { token } = registerAndLogin(db);
    for (const ssrfUrl of ['http://localhost/admin', 'http://127.0.0.1/', 'http://192.168.1.1/']) {
      const res = await request(app)
        .post('/api/scans')
        .set('Authorization', `Bearer ${token}`)
        .send({ url: ssrfUrl });
      expect(res.status).toBe(400);
    }
  });
});

// ─── GET /api/scans ──────────────────────────────────────────────────────────

describe('GET /api/scans', () => {
  it('returns scans list for the authenticated user', async () => {
    const { token, user } = registerAndLogin(db);
    db.createScan(user.id, 'https://a.example.com');
    db.createScan(user.id, 'https://b.example.com');

    const res = await request(app)
      .get('/api/scans')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.scans).toHaveLength(2);
  });

  it('does not return scans from another user', async () => {
    const { token } = registerAndLogin(db, 'user1@example.com');
    const { user: user2 } = registerAndLogin(db, 'user2@example.com');
    db.createScan(user2.id, 'https://other.example.com');

    const res = await request(app)
      .get('/api/scans')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.scans).toHaveLength(0);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/scans');
    expect(res.status).toBe(401);
  });
});

// ─── GET /api/scans/:id ──────────────────────────────────────────────────────

describe('GET /api/scans/:id', () => {
  it('returns a specific scan for its owner', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://target.example.com');

    const res = await request(app)
      .get(`/api/scans/${scan.id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.scan.id).toBe(scan.id);
  });

  it('returns 404 for a scan owned by a different user', async () => {
    const { token } = registerAndLogin(db, 'u1@example.com');
    const { user: u2 } = registerAndLogin(db, 'u2@example.com');
    const scan = db.createScan(u2.id, 'https://private.example.com');

    const res = await request(app)
      .get(`/api/scans/${scan.id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });

  it('returns 404 for a non-existent scan', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .get('/api/scans/scan_doesnotexist')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });
});

// ─── GET /api/scans/:id/logs ─────────────────────────────────────────────────

describe('GET /api/scans/:id/logs', () => {
  it('returns empty logs array for a scan with no logs', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');

    const res = await request(app)
      .get(`/api/scans/${scan.id}/logs`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.logs)).toBe(true);
    expect(res.body.logs).toHaveLength(0);
  });

  it('returns 404 for a scan owned by a different user', async () => {
    const { token } = registerAndLogin(db, 'u1@example.com');
    const { user: u2 } = registerAndLogin(db, 'u2@example.com');
    const scan = db.createScan(u2.id, 'https://private.example.com');

    const res = await request(app)
      .get(`/api/scans/${scan.id}/logs`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });

  it('returns 404 for a non-existent scan', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .get('/api/scans/scan_doesnotexist/logs')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });

  it('returns 401 without auth', async () => {
    const { user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');
    const res = await request(app).get(`/api/scans/${scan.id}/logs`);
    expect(res.status).toBe(401);
  });
});

// ─── GET /api/scans/:id/report ───────────────────────────────────────────────

describe('GET /api/scans/:id/report', () => {
  it('returns report for a completed scan', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');
    db.updateScan(scan.id, {
      status: 'complete',
      score: 85,
      severity: 'medium',
      aiSummary: 'Test summary',
      findings: [],
      completedAt: new Date().toISOString(),
    });

    const res = await request(app)
      .get(`/api/scans/${scan.id}/report`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.score).toBe(85);
    expect(res.body.aiSummary).toBe('Test summary');
  });

  it('returns 400 for a scan that is not complete', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');

    const res = await request(app)
      .get(`/api/scans/${scan.id}/report`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(400);
  });

  it('returns the full report shape for a completed scan with findings', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');
    db.updateScan(scan.id, {
      status: 'complete',
      score: 62,
      severity: 'high',
      aiSummary: 'Executive summary text.',
      findings: [
        { id: 'f1', title: 'SQL Injection', description: 'Error-based SQLi', severity: 'critical', fix: 'Use parameterised queries', category: 'DAST' },
        { id: 'f2', title: 'Missing HSTS', description: 'No HSTS header', severity: 'medium', fix: 'Add Strict-Transport-Security header', category: 'IAST' },
      ],
      completedAt: new Date().toISOString(),
    });

    const res = await request(app)
      .get(`/api/scans/${scan.id}/report`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      scanId: scan.id,
      url: 'https://example.com',
      score: 62,
      severity: 'high',
      aiSummary: 'Executive summary text.',
    });
    expect(Array.isArray(res.body.findings)).toBe(true);
    expect(res.body.findings).toHaveLength(2);
    expect(res.body.findings[0]).toMatchObject({ id: 'f1', severity: 'critical' });
  });

  it('returns 404 for a report belonging to another user', async () => {
    const { token } = registerAndLogin(db, 'u1@example.com');
    const { user: u2 } = registerAndLogin(db, 'u2@example.com');
    const scan = db.createScan(u2.id, 'https://secret.example.com');
    db.updateScan(scan.id, { status: 'complete', score: 100, findings: [], completedAt: new Date().toISOString() });

    const res = await request(app)
      .get(`/api/scans/${scan.id}/report`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });

  it('returns 401 without auth', async () => {
    const { user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');
    const res = await request(app).get(`/api/scans/${scan.id}/report`);
    expect(res.status).toBe(401);
  });
});

// ─── GET /api/scans/:id/sarif ────────────────────────────────────────────────

describe('GET /api/scans/:id/sarif', () => {
  const completedFindings = [
    { id: 'f1', title: 'SQL Injection', description: 'Error-based SQLi', severity: 'critical' as const, fix: 'Use parameterised queries', category: 'DAST' },
    { id: 'f2', title: 'Missing HSTS', description: 'No HSTS header', severity: 'medium' as const, fix: 'Add HSTS header', category: 'Headers' },
  ];

  it('returns SARIF 2.1.0 for a completed scan using JWT auth', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');
    db.updateScan(scan.id, { status: 'complete', score: 60, severity: 'critical', findings: completedFindings, completedAt: new Date().toISOString() });

    const res = await request(app)
      .get(`/api/scans/${scan.id}/sarif`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.version).toBe('2.1.0');
    expect(res.body.runs).toHaveLength(1);
    expect(res.body.runs[0].tool.driver.name).toBe('Seclayer');
    expect(res.body.runs[0].results).toHaveLength(2);
  });

  it('returns SARIF using X-API-Key header (pipeline auth)', async () => {
    const { user } = registerAndLogin(db);
    const apiKey = db.generateApiKey(user.id);
    const scan = db.createScan(user.id, 'https://example.com');
    db.updateScan(scan.id, { status: 'complete', score: 75, severity: 'medium', findings: completedFindings, completedAt: new Date().toISOString() });

    const res = await request(app)
      .get(`/api/scans/${scan.id}/sarif`)
      .set('X-API-Key', apiKey.key);

    expect(res.status).toBe(200);
    expect(res.body.version).toBe('2.1.0');
  });

  it('maps critical severity to error level in SARIF', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');
    db.updateScan(scan.id, { status: 'complete', score: 50, severity: 'critical', findings: completedFindings, completedAt: new Date().toISOString() });

    const res = await request(app)
      .get(`/api/scans/${scan.id}/sarif`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    const criticalResult = res.body.runs[0].results.find((r: any) => r.ruleId === 'sql-injection');
    expect(criticalResult.level).toBe('error');
    const mediumResult = res.body.runs[0].results.find((r: any) => r.ruleId === 'missing-hsts');
    expect(mediumResult.level).toBe('warning');
  });

  it('returns 400 for a scan that is not complete', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');

    const res = await request(app)
      .get(`/api/scans/${scan.id}/sarif`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(400);
  });

  it('returns 404 for a scan owned by another user', async () => {
    const { token } = registerAndLogin(db, 'u1@example.com');
    const { user: u2 } = registerAndLogin(db, 'u2@example.com');
    const scan = db.createScan(u2.id, 'https://secret.example.com');
    db.updateScan(scan.id, { status: 'complete', score: 100, findings: [], completedAt: new Date().toISOString() });

    const res = await request(app)
      .get(`/api/scans/${scan.id}/sarif`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });

  it('returns 401 with no credentials', async () => {
    const { user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');
    const res = await request(app).get(`/api/scans/${scan.id}/sarif`);
    expect(res.status).toBe(401);
  });

  it('returns 401 for a revoked API key', async () => {
    const { user } = registerAndLogin(db);
    const apiKey = db.generateApiKey(user.id);
    db.revokeApiKey(user.id, apiKey.id);
    const scan = db.createScan(user.id, 'https://example.com');
    db.updateScan(scan.id, { status: 'complete', score: 100, findings: [], completedAt: new Date().toISOString() });

    const res = await request(app)
      .get(`/api/scans/${scan.id}/sarif`)
      .set('X-API-Key', apiKey.key);

    expect(res.status).toBe(401);
  });
});

// ─── POST /api/scans (webhookUrl) ────────────────────────────────────────────

describe('POST /api/scans with webhookUrl', () => {
  it('accepts a valid webhookUrl and stores it on the scan', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://example.com', webhookUrl: 'https://hooks.example.com/notify' });

    expect(res.status).toBe(200);
    expect(res.body.scan.webhookUrl).toBe('https://hooks.example.com/notify');
  });

  it('rejects a private/SSRF webhookUrl', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://example.com', webhookUrl: 'http://192.168.1.100/webhook' });

    expect(res.status).toBe(400);
  });
});
