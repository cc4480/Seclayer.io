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

describe('GET /api/suppressions', () => {
  it('returns empty list for a new user', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .get('/api/suppressions')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.suppressions).toHaveLength(0);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/suppressions');
    expect(res.status).toBe(401);
  });
});

describe('POST /api/suppressions', () => {
  it('creates a suppression rule', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/suppressions')
      .set('Authorization', `Bearer ${token}`)
      .send({
        targetUrl: 'https://example.com',
        findingTitle: 'Missing HSTS',
        reason: 'Intentionally configured',
      });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.rule.findingTitle).toBe('Missing HSTS');
    expect(res.body.rule.reason).toBe('Intentionally configured');
  });

  it('returns 400 when required fields are missing', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/suppressions')
      .set('Authorization', `Bearer ${token}`)
      .send({ targetUrl: 'https://example.com' }); // missing findingTitle
    expect(res.status).toBe(400);
  });

  it('uses default reason when none provided', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/suppressions')
      .set('Authorization', `Bearer ${token}`)
      .send({ targetUrl: 'https://example.com', findingTitle: 'XSS' });
    expect(res.status).toBe(200);
    expect(res.body.rule.reason).toBe('False positive');
  });
});

describe('DELETE /api/suppressions/:id', () => {
  it('removes a suppression rule', async () => {
    const { token, user } = registerAndLogin(db);
    const rule = db.addSuppression(user.id, 'https://example.com', 'HSTS Missing', 'FP');

    const res = await request(app)
      .delete(`/api/suppressions/${rule.id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(db.listSuppressions(user.id)).toHaveLength(0);
  });

  it('returns 404 for a rule from another user', async () => {
    const { token } = registerAndLogin(db, 'u1@example.com');
    const { user: u2 } = registerAndLogin(db, 'u2@example.com');
    const rule = db.addSuppression(u2.id, 'https://example.com', 'CSP', 'FP');

    const res = await request(app)
      .delete(`/api/suppressions/${rule.id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).delete('/api/suppressions/somerule');
    expect(res.status).toBe(401);
  });
});

describe('POST /api/scans/:scanId/findings/:findingId/suppress', () => {
  it('creates a suppression rule from a finding', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');
    db.updateScan(scan.id, {
      status: 'complete',
      findings: [{
        id: 'f_test001',
        title: 'Missing CSP',
        description: 'No CSP header',
        severity: 'high',
        fix: 'Add CSP header',
        category: 'IAST',
      }],
    });

    const res = await request(app)
      .post(`/api/scans/${scan.id}/findings/f_test001/suppress`)
      .set('Authorization', `Bearer ${token}`)
      .send({ reason: 'Known misconfiguration' });

    expect(res.status).toBe(200);
    expect(res.body.rule.findingTitle).toBe('Missing CSP');
  });

  it('returns 404 for a non-existent finding', async () => {
    const { token, user } = registerAndLogin(db);
    const scan = db.createScan(user.id, 'https://example.com');

    const res = await request(app)
      .post(`/api/scans/${scan.id}/findings/f_doesnotexist/suppress`)
      .set('Authorization', `Bearer ${token}`)
      .send({});

    expect(res.status).toBe(404);
  });
});
