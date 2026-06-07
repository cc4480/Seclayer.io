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

// ─── ASPM /api/enterprise/aspm/correlate ─────────────────────────────────────

describe('POST /api/enterprise/aspm/correlate', () => {
  it('returns empty correlation when user has no completed scans', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/enterprise/aspm/correlate')
      .set('Authorization', `Bearer ${token}`)
      .send({});

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.scansAnalyzed).toBe(0);
    expect(res.body.correlatedFindings).toHaveLength(0);
    expect(res.body.summary).toMatchObject({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });
  });

  it('aggregates findings from completed scans', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');
    db.updateScan(scan.id, {
      status: 'complete',
      findings: [
        { id: 'f1', title: 'Missing CSP', description: '', severity: 'high', fix: '', category: 'IAST' },
        { id: 'f2', title: 'Open Port', description: '', severity: 'medium', fix: '', category: 'EASM' },
      ],
    });

    const res = await request(app)
      .post('/api/enterprise/aspm/correlate')
      .set('Authorization', `Bearer ${token}`)
      .send({});

    expect(res.status).toBe(200);
    expect(res.body.scansAnalyzed).toBe(1);
    expect(res.body.correlatedFindings.length).toBeGreaterThan(0);
    expect(res.body.summary.high).toBeGreaterThanOrEqual(1);
  });

  it('deduplicates findings that appear across multiple scans', async () => {
    const { token, user } = registerAndLogin(db);

    const scan1 = db.createScan(user.id, 'https://a.example.com');
    db.updateScan(scan1.id, {
      status: 'complete',
      findings: [{ id: 'f1', title: 'Missing CSP', description: '', severity: 'high', fix: '', category: 'IAST' }],
    });

    const scan2 = db.createScan(user.id, 'https://b.example.com');
    db.updateScan(scan2.id, {
      status: 'complete',
      findings: [{ id: 'f2', title: 'Missing CSP', description: '', severity: 'high', fix: '', category: 'IAST' }],
    });

    const res = await request(app)
      .post('/api/enterprise/aspm/correlate')
      .set('Authorization', `Bearer ${token}`)
      .send({});

    // "Missing CSP" appears in both scans — should be deduplicated into one entry
    const cspEntry = res.body.correlatedFindings.find((f: any) => f.title === 'Missing CSP');
    expect(cspEntry).toBeDefined();
    expect(cspEntry.occurrences).toBe(2);
    expect(cspEntry.seenIn).toHaveLength(2);
  });

  it('excludes false-positive findings from correlation', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');
    db.updateScan(scan.id, {
      status: 'complete',
      findings: [
        { id: 'f1', title: 'FP Finding', description: '', severity: 'critical', fix: '', category: 'DAST', isFalsePositive: true },
      ],
    });

    const res = await request(app)
      .post('/api/enterprise/aspm/correlate')
      .set('Authorization', `Bearer ${token}`)
      .send({});

    expect(res.body.correlatedFindings).toHaveLength(0);
    expect(res.body.summary.critical).toBe(0);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app)
      .post('/api/enterprise/aspm/correlate')
      .send({});
    expect(res.status).toBe(401);
  });
});

// ─── IAST /api/enterprise/iast/trace ─────────────────────────────────────────

describe('POST /api/enterprise/iast/trace', () => {
  it('returns 501 with setup instructions', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/enterprise/iast/trace')
      .set('Authorization', `Bearer ${token}`)
      .send({});

    expect(res.status).toBe(501);
    expect(res.body.success).toBe(false);
    expect(res.body.feature).toBe('IAST Runtime Instrumentation');
    expect(Array.isArray(res.body.setupRequired)).toBe(true);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app)
      .post('/api/enterprise/iast/trace')
      .send({});
    expect(res.status).toBe(401);
  });
});

// ─── EASM /api/enterprise/easm/recon (auth guard) ────────────────────────────

describe('POST /api/enterprise/easm/recon', () => {
  it('returns 401 without auth', async () => {
    const res = await request(app)
      .post('/api/enterprise/easm/recon')
      .send({ domain: 'example.com' });
    expect(res.status).toBe(401);
  });

  it('returns 400 when domain is missing', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/enterprise/easm/recon')
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
  });
});

// ─── API Scan /api/enterprise/api-scan/hadrian (auth guard) ──────────────────

describe('POST /api/enterprise/api-scan/hadrian', () => {
  it('returns 401 without auth', async () => {
    const res = await request(app)
      .post('/api/enterprise/api-scan/hadrian')
      .send({ url: 'https://example.com' });
    expect(res.status).toBe(401);
  });

  it('returns 400 when url is missing', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/enterprise/api-scan/hadrian')
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
  });
});

// ─── PentAGI /api/enterprise/pentagi/logs (auth guard) ───────────────────────

describe('GET /api/enterprise/pentagi/logs', () => {
  it('returns 401 without auth', async () => {
    const res = await request(app)
      .get('/api/enterprise/pentagi/logs?url=https://example.com');
    expect(res.status).toBe(401);
  });

  it('returns 400 when url query param is missing', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .get('/api/enterprise/pentagi/logs')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
  });

  it('returns 400 for SSRF/private targets', async () => {
    const { token } = registerAndLogin(db);
    for (const ssrfUrl of [
      'http://localhost/admin',
      'http://127.0.0.1:8080/secret',
      'http://192.168.0.1/',
      'http://10.0.0.1/internal',
      'http://169.254.169.254/latest/meta-data/',
    ]) {
      const res = await request(app)
        .get(`/api/enterprise/pentagi/logs?url=${encodeURIComponent(ssrfUrl)}`)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status, `Expected 400 for SSRF target: ${ssrfUrl}`).toBe(400);
    }
  });
});
