import crypto from 'crypto';
import type { Request, Response } from 'express';
import { config } from './config.js';

/**
 * Stateless signed session tokens.
 *
 * Identity must come from a value the client cannot forge, not from a `userId`
 * passed in the request. A session is a compact, HMAC-SHA256-signed token —
 * `base64url(payload).base64url(signature)` — carried in an HttpOnly cookie.
 * No server-side session store is required; the signature + expiry are the
 * source of truth.
 */

interface SessionPayload {
  sub: string; // user id
  iat: number; // issued-at (epoch seconds)
  exp: number; // expiry (epoch seconds)
}

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function sign(data: string): string {
  return b64url(crypto.createHmac('sha256', config.session.secret).update(data).digest());
}

/** Issue a signed session token for a user id. */
export function signSession(userId: string): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = { sub: userId, iat: now, exp: now + config.session.ttlSeconds };
  const body = b64url(Buffer.from(JSON.stringify(payload)));
  return `${body}.${sign(body)}`;
}

/** Verify a token and return its user id, or null if invalid/expired/tampered. */
export function verifySession(token: string | undefined | null): string | null {
  if (!token || typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  if (dot <= 0) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);

  // Constant-time signature comparison.
  const expected = sign(body);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  try {
    const payload = JSON.parse(fromB64url(body).toString('utf8')) as SessionPayload;
    if (!payload?.sub || typeof payload.exp !== 'number') return null;
    if (Math.floor(Date.now() / 1000) >= payload.exp) return null;
    return payload.sub;
  } catch {
    return null;
  }
}

/** Parse the session token out of the request's Cookie header. */
export function readSessionToken(req: Request): string | null {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === config.session.cookieName) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return null;
}

/** Set the signed session cookie on the response. */
export function setSessionCookie(res: Response, userId: string): void {
  res.cookie(config.session.cookieName, signSession(userId), {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: 'lax',
    maxAge: config.session.ttlSeconds * 1000,
    path: '/',
  });
}

/** Clear the session cookie. */
export function clearSessionCookie(res: Response): void {
  res.clearCookie(config.session.cookieName, { path: '/' });
}
