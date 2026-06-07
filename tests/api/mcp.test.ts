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

  it('returns 400 for SSRF targets (localhost / private IPs)', async () => {
    const { user } = registerAndLogin(db);
    const keyObj = db.listApiKeys(user.id)[0];

    for (const ssrfUrl of [
      'http://localhost/admin',
      'http://127.0.0.1:8080/secret',
      'http://192.168.1.1/router',
      'http://10.0.0.1/internal',
    ]) {
      const res = await request(app)
        .post('/api/mcp/scan')
        .send({ url: ssrfUrl, apiKey: keyObj.key });
      expect(res.status, `Expected 400 for SSRF target: ${ssrfUrl}`).toBe(400);
      expect(res.body.error).toMatch(/private|local/i);
    }
  });
});
