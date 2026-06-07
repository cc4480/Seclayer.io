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

describe('GET /api/auth-profiles', () => {
  it('returns empty list for a new user', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app).get('/api/auth-profiles').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.profiles).toHaveLength(0);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/auth-profiles');
    expect(res.status).toBe(401);
  });
});

describe('POST /api/auth-profiles', () => {
  it('creates a bearer token profile', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Staging API', type: 'bearer', headerValue: 'eyJhbGciOiJIUzI1NiJ9.test' });

    expect(res.status).toBe(201);
    expect(res.body.profile).toMatchObject({
      name: 'Staging API',
      type: 'bearer',
      headerValue: 'eyJhbGciOiJIUzI1NiJ9.test',
    });
    expect(res.body.profile.id).toMatch(/^ap_/);
  });

  it('creates a cookie profile', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Admin Cookie', type: 'cookie', headerValue: 'session=abc123; path=/' });

    expect(res.status).toBe(201);
    expect(res.body.profile.type).toBe('cookie');
  });

  it('creates a basic auth profile', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Admin Basic', type: 'basic', username: 'admin', password: 'secret' });

    expect(res.status).toBe(201);
    expect(res.body.profile.username).toBe('admin');
  });

  it('creates a form-based login profile', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: 'Staging Login',
        type: 'form',
        loginUrl: 'https://staging.example.com/login',
        loginUsername: 'user@example.com',
        loginPassword: 'password123',
        loginUsernameField: 'email',
        loginPasswordField: 'password',
      });

    expect(res.status).toBe(201);
    expect(res.body.profile.type).toBe('form');
    expect(res.body.profile.loginUrl).toBe('https://staging.example.com/login');
  });

  it('creates a custom header profile', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'API Key Header', type: 'header', headerName: 'X-API-Key', headerValue: 'key_abc123' });

    expect(res.status).toBe(201);
    expect(res.body.profile.headerName).toBe('X-API-Key');
  });

  it('returns 400 when name is missing', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${token}`)
      .send({ type: 'bearer', headerValue: 'token' });
    expect(res.status).toBe(400);
  });

  it('returns 400 when type is missing', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'My Profile' });
    expect(res.status).toBe(400);
  });

  it('returns 400 for an invalid auth type', async () => {
    const { token } = registerAndLogin(db);
    const res = await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Bad', type: 'oauth2' });
    expect(res.status).toBe(400);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).post('/api/auth-profiles').send({ name: 'x', type: 'bearer' });
    expect(res.status).toBe(401);
  });

  it('profile is visible in list after creation', async () => {
    const { token } = registerAndLogin(db);
    await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Prod Bearer', type: 'bearer', headerValue: 'tok' });

    const list = await request(app).get('/api/auth-profiles').set('Authorization', `Bearer ${token}`);
    expect(list.body.profiles).toHaveLength(1);
    expect(list.body.profiles[0].name).toBe('Prod Bearer');
  });

  it('profiles are isolated between users', async () => {
    const { token: t1 } = registerAndLogin(db, 'u1@example.com');
    const { token: t2 } = registerAndLogin(db, 'u2@example.com');

    await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${t1}`)
      .send({ name: 'U1 Profile', type: 'bearer', headerValue: 'tok' });

    const list = await request(app).get('/api/auth-profiles').set('Authorization', `Bearer ${t2}`);
    expect(list.body.profiles).toHaveLength(0);
  });
});

describe('DELETE /api/auth-profiles/:id', () => {
  it('deletes an existing profile', async () => {
    const { token } = registerAndLogin(db);
    const create = await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'To Delete', type: 'cookie', headerValue: 'x=1' });
    const { id } = create.body.profile;

    const del = await request(app).delete(`/api/auth-profiles/${id}`).set('Authorization', `Bearer ${token}`);
    expect(del.status).toBe(200);

    const list = await request(app).get('/api/auth-profiles').set('Authorization', `Bearer ${token}`);
    expect(list.body.profiles).toHaveLength(0);
  });

  it('returns 404 for a profile owned by another user', async () => {
    const { token: t1 } = registerAndLogin(db, 'u1@example.com');
    const { token: t2 } = registerAndLogin(db, 'u2@example.com');

    const create = await request(app)
      .post('/api/auth-profiles')
      .set('Authorization', `Bearer ${t1}`)
      .send({ name: 'Private', type: 'bearer', headerValue: 'tok' });
    const { id } = create.body.profile;

    const del = await request(app).delete(`/api/auth-profiles/${id}`).set('Authorization', `Bearer ${t2}`);
    expect(del.status).toBe(404);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).delete('/api/auth-profiles/ap_fake');
    expect(res.status).toBe(401);
  });
});

describe('POST /api/auth-profiles/:id/test', () => {
  it('returns 400 when testUrl is missing', async () => {
    const { token, user } = registerAndLogin(db);
    const profile = db.createAuthProfile(user.id, { name: 'Test', type: 'bearer', headerValue: 'tok' });

    const res = await request(app)
      .post(`/api/auth-profiles/${profile.id}/test`)
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
  });

  it('returns 400 for SSRF testUrl', async () => {
    const { token, user } = registerAndLogin(db);
    const profile = db.createAuthProfile(user.id, { name: 'Test', type: 'bearer', headerValue: 'tok' });

    const res = await request(app)
      .post(`/api/auth-profiles/${profile.id}/test`)
      .set('Authorization', `Bearer ${token}`)
      .send({ testUrl: 'http://127.0.0.1/secret' });
    expect(res.status).toBe(400);
  });

  it('returns 404 for a profile owned by another user', async () => {
    const { token: t1 } = registerAndLogin(db, 'u1@example.com');
    const { user: u2, token: t2 } = registerAndLogin(db, 'u2@example.com');
    const profile = db.createAuthProfile(u2.id, { name: 'Private', type: 'bearer', headerValue: 'tok' });

    const res = await request(app)
      .post(`/api/auth-profiles/${profile.id}/test`)
      .set('Authorization', `Bearer ${t1}`)
      .send({ testUrl: 'https://example.com' });
    expect(res.status).toBe(404);
    // t2 owns it, not t1
    void t2;
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).post('/api/auth-profiles/ap_fake/test').send({ testUrl: 'https://example.com' });
    expect(res.status).toBe(401);
  });
});
