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

describe('GET /api/keys', () => {
  it('returns API keys for the authenticated user', async () => {
    const { token, user } = registerAndLogin(db);
    db.generateApiKey(user.id);

    const res = await request(app)
      .get('/api/keys')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    // signup key + generated key
    expect(res.body.keys.length).toBeGreaterThanOrEqual(2);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/keys');
    expect(res.status).toBe(401);
  });
});

describe('POST /api/keys', () => {
  it('generates a new API key', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/keys')
      .set('Authorization', `Bearer ${token}`)
      .send({});

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.key.key).toMatch(/^sl_live_/);
    expect(res.body.key.active).toBe(true);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).post('/api/keys').send({});
    expect(res.status).toBe(401);
  });
});

describe('DELETE /api/keys/:id', () => {
  it('revokes an API key', async () => {
    const { token, user } = registerAndLogin(db);
    const key = db.generateApiKey(user.id);

    const res = await request(app)
      .delete(`/api/keys/${key.id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(db.findApiKey(key.key)!.active).toBe(false);
  });

  it('returns 404 for a key from a different user', async () => {
    const { token } = registerAndLogin(db, 'u1@example.com');
    const { user: u2 } = registerAndLogin(db, 'u2@example.com');
    const key = db.generateApiKey(u2.id);

    const res = await request(app)
      .delete(`/api/keys/${key.id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).delete('/api/keys/somekey');
    expect(res.status).toBe(401);
  });
});
