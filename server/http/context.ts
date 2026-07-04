import express from 'express';
import { db } from '../db.js';

// Shared HTTP request context: session cookie handling and auth guards. Identity
// is always derived server-side from the signed session cookie, never from
// client-supplied input.

export const SESSION_COOKIE = 'sl_session';

const isProd = process.env.NODE_ENV === 'production';
export const cookieOptions = {
  httpOnly: true,
  secure: isProd,
  sameSite: 'lax' as const,
  path: '/',
  maxAge: 30 * 24 * 60 * 60 * 1000,
};

// Resolve the session cookie to a userId for every request.
export function attachSession(req: express.Request, res: express.Response, next: express.NextFunction) {
  const token = req.cookies?.[SESSION_COOKIE];
  if (token) {
    const userId = db.getSessionUserId(token);
    if (userId) (req as any).userId = userId;
  }
  next();
}

export function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!(req as any).userId) {
    return res.status(401).json({ status: 'error', message: 'Authentication required' });
  }
  next();
}

export const getUserId = (req: express.Request): string => (req as any).userId;
