import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import { makeTestApp } from '../helpers.js';
import type { Express } from 'express';

let app: Express;
let cleanup: () => void;

beforeEach(() => {
  ({ app, cleanup } = makeTestApp());
});
afterEach(() => cleanup());

describe('GET /api/system/health', () => {
  it('returns 200 with Online status', async () => {
    const res = await request(app).get('/api/system/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('Online');
    expect(res.body.version).toBeDefined();
    expect(res.body.timestamp).toBeDefined();
  });
});
