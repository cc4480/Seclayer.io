import { Request, Response, NextFunction } from 'express';
import { rateLimit } from 'express-rate-limit';
import { LocalFileDb } from './db.js';
import { verifyToken } from './auth.js';

declare global {
  namespace Express {
    interface Request {
      userId?: string;
    }
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  const token = authHeader.substring(7);
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token. Please sign in again.' });
  }
  req.userId = payload.userId;
  next();
}

/** Accepts either a JWT Bearer token (dashboard) or X-API-Key header / ?apiKey= query (CI pipelines) */
export function requireAuthOrApiKey(dbInstance: LocalFileDb) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    if (authHeader?.startsWith('Bearer ')) {
      const payload = verifyToken(authHeader.substring(7));
      if (payload) { req.userId = payload.userId; return next(); }
    }
    const apiKeyStr = (req.headers['x-api-key'] as string | undefined) || (req.query.apiKey as string | undefined);
    if (apiKeyStr) {
      const keyObj = dbInstance.findApiKey(apiKeyStr);
      if (keyObj?.active) {
        const user = dbInstance.getUser(keyObj.userId);
        if (user) { req.userId = user.id; return next(); }
      }
    }
    return res.status(401).json({ error: 'Authentication required. Provide a Bearer token or X-API-Key header.' });
  };
}

export const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
export const scanLimiter = rateLimit({ windowMs: 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false });
