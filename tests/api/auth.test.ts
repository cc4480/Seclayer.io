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

// ─── POST /api/auth/register ─────────────────────────────────────────────────

describe('POST /api/auth/register', () => {
  it('creates an account and returns token + user', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'new@example.com', password: 'supersecret' });

    expect(res.status).toBe(201);
    expect(typeof res.body.token).toBe('string');
    expect(res.body.user.email).toBe('new@example.com');
    expect(res.body.user.passwordHash).toBeUndefined();
  });

  it('rejects an invalid email', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'notanemail', password: 'supersecret' });
    expect(res.status).toBe(400);
  });

  it('rejects a password shorter than 8 characters', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'x@example.com', password: 'short' });
    expect(res.status).toBe(400);
  });

  it('returns 409 for a duplicate email', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'dup@example.com', password: 'password123' });
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'dup@example.com', password: 'password123' });
    expect(res.status).toBe(409);
  });

  it('normalises email to lowercase', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'UPPER@EXAMPLE.COM', password: 'password123' });
    expect(res.status).toBe(201);
    expect(res.body.user.email).toBe('upper@example.com');
  });
});

// ─── POST /api/auth/login ────────────────────────────────────────────────────

describe('POST /api/auth/login', () => {
  beforeEach(() => {
    registerAndLogin(db, 'login@example.com', 'correctpassword');
  });

  it('returns token + user for correct credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'login@example.com', password: 'correctpassword' });

    expect(res.status).toBe(200);
    expect(typeof res.body.token).toBe('string');
    expect(res.body.user.email).toBe('login@example.com');
  });

  it('returns 401 for a wrong password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'login@example.com', password: 'wrongpassword' });
    expect(res.status).toBe(401);
  });

  it('returns 401 for an unknown email', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nobody@example.com', password: 'password123' });
    expect(res.status).toBe(401);
  });

  it('returns 400 when fields are missing', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'login@example.com' });
    expect(res.status).toBe(400);
  });
});

// ─── GET /api/auth/me ────────────────────────────────────────────────────────

describe('GET /api/auth/me', () => {
  it('returns user profile when authenticated', async () => {
    const { token } = registerAndLogin(db, 'me@example.com', 'password123');
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('me@example.com');
  });

  it('returns 401 without a token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  it('returns 401 with a malformed token', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer notavalidtoken');
    expect(res.status).toBe(401);
  });
});

// ─── POST /api/auth/logout ───────────────────────────────────────────────────

describe('POST /api/auth/logout', () => {
  it('returns ok (stateless logout)', async () => {
    const res = await request(app).post('/api/auth/logout');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});
