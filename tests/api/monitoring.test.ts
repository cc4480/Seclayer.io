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

describe('GET /api/monitoring', () => {
  it('returns empty list for a new user', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .get('/api/monitoring')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.monitoredTargets).toHaveLength(0);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/monitoring');
    expect(res.status).toBe(401);
  });
});

describe('POST /api/monitoring', () => {
  it('adds a monitored target', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/monitoring')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://prod.example.com', frequencyDays: 7 });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.target.url).toBe('https://prod.example.com');
    expect(res.body.target.frequencyDays).toBe(7);
    expect(res.body.target.nextScanAt).toBeDefined();
  });

  it('returns 400 when url is missing', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/monitoring')
      .set('Authorization', `Bearer ${token}`)
      .send({ frequencyDays: 7 });
    expect(res.status).toBe(400);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app)
      .post('/api/monitoring')
      .send({ url: 'https://example.com' });
    expect(res.status).toBe(401);
  });
});

describe('DELETE /api/monitoring/:id', () => {
  it('removes a monitored target', async () => {
    const { token, user } = registerAndLogin(db);
    const target = db.addMonitoredTarget(user.id, 'https://example.com', 7);

    const res = await request(app)
      .delete(`/api/monitoring/${target.id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(db.listMonitoredTargets(user.id)).toHaveLength(0);
  });

  it('returns 404 for a target from another user', async () => {
    const { token } = registerAndLogin(db, 'u1@example.com');
    const { user: u2 } = registerAndLogin(db, 'u2@example.com');
    const target = db.addMonitoredTarget(u2.id, 'https://example.com', 7);

    const res = await request(app)
      .delete(`/api/monitoring/${target.id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).delete('/api/monitoring/someid');
    expect(res.status).toBe(401);
  });
});
