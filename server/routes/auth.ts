import type { Express } from 'express';
import { db } from '../db.js';
import { HttpError } from '../middleware.js';
import { validateEmail } from '../validation.js';

/** Lightweight email-based auth: looks up or creates a user record. */
export function registerAuthRoutes(app: Express): void {
  app.post('/api/auth/login', (req, res) => {
    const email = validateEmail(req.body?.email);
    const user = db.getOrCreateUser(email);
    res.json({ status: 'ok', user });
  });

  app.post('/api/auth/logout', (_req, res) => {
    res.json({ status: 'ok', message: 'Logged out successfully' });
  });

  app.get('/api/auth/me', (req, res) => {
    const userId = (req.query.userId as string) || 'user_default';
    const user = db.getUser(userId);
    if (!user) {
      throw new HttpError(404, 'User profile not found');
    }
    res.json({ user });
  });
}
