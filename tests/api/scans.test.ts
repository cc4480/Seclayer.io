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

  it('returns 402 when user has no credits', async () => {
    const { token, user } = registerAndLogin(db);
    // drain all 5 starting credits
    for (let i = 0; i < 5; i++) db.deductCredits(user.id, 1);

    const res = await request(app)
      .post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://example.com' });

    expect(res.status).toBe(402);
    expect(res.body.message).toMatch(/insufficient credits/i);
  });

  it('deducts 1 credit when scan is created', async () => {
    const { token, user } = registerAndLogin(db);
    const before = db.getUser(user.id)!.credits;

    await request(app)
      .post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://example.com' });

    const after = db.getUser(user.id)!.credits;
    expect(after).toBe(before - 1);
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
});
