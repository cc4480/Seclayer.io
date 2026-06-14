import type { Express } from 'express';
import { db } from '../db.js';
import { HttpError, currentUserId } from '../middleware.js';
import { validateEmail } from '../validation.js';
import { setSessionCookie, clearSessionCookie } from '../session.js';

/** Email-based auth backed by a signed, HttpOnly session cookie. */
export function registerAuthRoutes(app: Express): void {
  app.post('/api/auth/login', (req, res) => {
    const email = validateEmail(req.body?.email);
    const user = db.getOrCreateUser(email);
    // Bind identity to a signed cookie; the client can no longer assert a userId.
    setSessionCookie(res, user.id);
    res.json({ status: 'ok', user });
  });

  app.post('/api/auth/logout', (_req, res) => {
    clearSessionCookie(res);
    res.json({ status: 'ok', message: 'Logged out successfully' });
  });

  app.get('/api/auth/me', (req, res) => {
    // Identity comes from the verified session, falling back to the shared
    // default account for anonymous callers.
    const userId = currentUserId(req);
    const user = db.getUser(userId);
    if (!user) {
      throw new HttpError(404, 'User profile not found');
    }
    res.json({ user });
  });
}
