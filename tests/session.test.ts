import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import http from 'http';
import express from 'express';
import { config } from '../server/config.ts';
import {
  signSession,
  verifySession,
  readSessionToken,
} from '../server/session.ts';
import { authContext, errorHandler } from '../server/middleware.ts';
import { registerAuthRoutes } from '../server/routes/auth.ts';
import { registerCreditRoutes } from '../server/routes/credits.ts';

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function craftToken(payload: object): string {
  const body = b64url(Buffer.from(JSON.stringify(payload)));
  const sig = b64url(crypto.createHmac('sha256', config.session.secret).update(body).digest());
  return `${body}.${sig}`;
}

function flipFirstChar(s: string): string {
  return (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
}

test('signSession/verifySession round-trip', () => {
  const token = signSession('user_abc');
  assert.equal(verifySession(token), 'user_abc');
});

test('verifySession rejects a tampered signature', () => {
  const token = signSession('user_abc');
  const [body, sig] = token.split('.');
  assert.equal(verifySession(`${body}.${flipFirstChar(sig)}`), null);
});

test('verifySession rejects an expired token', () => {
  const now = Math.floor(Date.now() / 1000);
  const expired = craftToken({ sub: 'user_abc', iat: now - 1000, exp: now - 1 });
  assert.equal(verifySession(expired), null);
});

test('verifySession rejects malformed or missing tokens', () => {
  assert.equal(verifySession(null), null);
  assert.equal(verifySession(undefined), null);
  assert.equal(verifySession(''), null);
  assert.equal(verifySession('not-a-token'), null);
  assert.equal(verifySession('.nodot'), null);
});

test('readSessionToken extracts the session cookie from the Cookie header', () => {
  const token = signSession('user_abc');
  const req: any = {
    headers: { cookie: `other=1; ${config.session.cookieName}=${encodeURIComponent(token)}; foo=bar` },
  };
  assert.equal(readSessionToken(req), token);
  assert.equal(readSessionToken({ headers: {} } as any), null);
});

/**
 * Mounts the real auth/credit route handlers behind the real authContext
 * middleware (sans Vite/static serving) so the cookie-based identity binding
 * is exercised end-to-end over HTTP.
 */
function buildTestApp() {
  const app = express();
  app.use(express.json());
  app.use(authContext());
  registerAuthRoutes(app);
  registerCreditRoutes(app);
  app.use(errorHandler());
  return app;
}

async function withServer<T>(fn: (base: string) => Promise<T>): Promise<T> {
  const server = http.createServer(buildTestApp());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as any).port;
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

function extractCookie(setCookieHeader: string | null): string {
  assert.ok(setCookieHeader, 'expected a Set-Cookie header');
  return setCookieHeader!.split(';')[0];
}

test('login binds identity to a signed cookie; a client-supplied userId is ignored', async () => {
  await withServer(async (base) => {
    const aliceEmail = `alice-${Math.random().toString(36).slice(2)}@example.test`;
    const bobEmail = `bob-${Math.random().toString(36).slice(2)}@example.test`;

    const aliceLogin = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: aliceEmail }),
    });
    assert.equal(aliceLogin.status, 200);
    const aliceData: any = await aliceLogin.json();
    const aliceCookie = extractCookie(aliceLogin.headers.get('set-cookie'));

    const bobLogin = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: bobEmail }),
    });
    const bobData: any = await bobLogin.json();
    assert.notEqual(aliceData.user.id, bobData.user.id);

    // Alice's cookie identifies her, even when the request claims to be Bob.
    const meRes = await fetch(`${base}/api/auth/me?userId=${bobData.user.id}`, {
      headers: { Cookie: aliceCookie },
    });
    const meData: any = await meRes.json();
    assert.equal(meData.user.id, aliceData.user.id);

    // Alice cannot read Bob's credit ledger by passing his id.
    const creditsRes = await fetch(`${base}/api/credits?userId=${bobData.user.id}`, {
      headers: { Cookie: aliceCookie },
    });
    const creditsData: any = await creditsRes.json();
    assert.equal(creditsData.credits, aliceData.user.credits);

    // Anonymous (no cookie) requests fall back to the shared default account.
    const anonRes = await fetch(`${base}/api/auth/me`);
    const anonData: any = await anonRes.json();
    assert.equal(anonData.user.id, 'user_default');
  });
});

test('logout clears the session cookie', async () => {
  await withServer(async (base) => {
    const email = `cleo-${Math.random().toString(36).slice(2)}@example.test`;
    const loginRes = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const cookie = extractCookie(loginRes.headers.get('set-cookie'));

    const logoutRes = await fetch(`${base}/api/auth/logout`, {
      method: 'POST',
      headers: { Cookie: cookie },
    });
    const cleared = logoutRes.headers.get('set-cookie');
    assert.ok(cleared);
    assert.match(cleared!, new RegExp(`${config.session.cookieName}=;`));
  });
});
