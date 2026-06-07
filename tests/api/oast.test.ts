import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import { makeTestApp } from '../helpers.js';
import { createOastToken, hasInteraction, getInteractions } from '../../server/oast.js';
import type { Express } from 'express';
import type { LocalFileDb } from '../../server/db.js';

let app: Express;
let db: LocalFileDb;
let cleanup: () => void;

beforeEach(() => {
  ({ app, db, cleanup } = makeTestApp());
});
afterEach(() => cleanup());

describe('OAST callback route /oast/:token', () => {
  it('returns 200 for a GET request on a known token', async () => {
    const token = createOastToken();
    const res = await request(app).get(`/oast/${token}`);
    expect(res.status).toBe(200);
  });

  it('returns 200 for a POST request on a known token', async () => {
    const token = createOastToken();
    const res = await request(app).post(`/oast/${token}`).send('callback-body');
    expect(res.status).toBe(200);
  });

  it('returns 200 for PUT and DELETE (accepts any HTTP method)', async () => {
    const token = createOastToken();
    expect((await request(app).put(`/oast/${token}`)).status).toBe(200);
    expect((await request(app).delete(`/oast/${token}`)).status).toBe(200);
  });

  it('records the interaction after a GET callback', async () => {
    const token = createOastToken();
    await request(app).get(`/oast/${token}`);

    expect(hasInteraction(token)).toBe(true);
    const list = getInteractions(token);
    expect(list).toHaveLength(1);
    expect(list[0].token).toBe(token);
    expect(list[0].method).toBe('GET');
  });

  it('records the interaction after a POST callback', async () => {
    const token = createOastToken();
    await request(app).post(`/oast/${token}`).send('payload');

    const list = getInteractions(token);
    expect(list).toHaveLength(1);
    expect(list[0].method).toBe('POST');
  });

  it('accumulates multiple callbacks for the same token', async () => {
    const token = createOastToken();
    await request(app).get(`/oast/${token}`);
    await request(app).post(`/oast/${token}`).send('');

    expect(getInteractions(token)).toHaveLength(2);
  });

  it('requires no authentication (route is before auth middleware)', async () => {
    const token = createOastToken();
    // No Authorization header — must still return 200
    const res = await request(app).get(`/oast/${token}`);
    expect(res.status).toBe(200);
  });

  it('returns 200 for an unknown token (does not reveal token existence)', async () => {
    // recordInteraction silently drops unknown tokens, but the route still responds 200
    const res = await request(app).get('/oast/unknowntokenvalue');
    expect(res.status).toBe(200);
  });

  it('does not record interaction for an unknown token', async () => {
    const fakeToken = 'fakefakefakefakefakefakefake';
    await request(app).get(`/oast/${fakeToken}`);
    // hasInteraction returns false for tokens not in the store
    expect(hasInteraction(fakeToken)).toBe(false);
  });
});
