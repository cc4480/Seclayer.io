import express from 'express';
import { db } from '../db.js';
import { config } from '../config.js';
import { rateLimit } from '../rateLimit.js';
import { sendEmail, buildMagicLinkEmail, isEmailConfigured } from '../email.js';
import { SESSION_COOKIE, cookieOptions, requireAuth, getUserId } from '../http/context.js';

// --- Auth (passwordless magic link) ---
export function registerAuthRoutes(app: express.Express): void {
  const requestLinkLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    keyPrefix: 'auth',
    message: 'Too many sign-in attempts. Please wait a few minutes and try again.',
  });

  app.post('/api/auth/request-link', requestLinkLimiter, async (req, res) => {
    const { email } = req.body || {};
    if (!email || typeof email !== 'string' || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({ status: 'error', message: 'A valid email address is required.' });
    }
    const normEmail = email.toLowerCase().trim();
    const token = db.createLoginToken(normEmail);
    // Build the link from a TRUSTED base only. In production APP_URL is required
    // (enforced at boot), so the attacker-controllable Host header is never used
    // for auth links. The request-host fallback is dev-only.
    const base = config.appUrl || `${req.protocol}://${req.get('host')}`;
    const link = `${base}/api/auth/verify?token=${token}`;
    try {
      const mail = buildMagicLinkEmail(link);
      await sendEmail({ to: normEmail, subject: mail.subject, html: mail.html, text: mail.text });
    } catch (err: any) {
      console.error('Failed to send magic link email:', err?.message || err);
      return res.status(502).json({ status: 'error', message: 'Could not send the sign-in email. Please try again shortly.' });
    }
    // The login link contains a live session-granting token, so it is ONLY ever
    // returned in the response for local development (no email provider). In
    // production it is never exposed — it is delivered by email exclusively.
    const devLink = (!config.isProd && !isEmailConfigured()) ? link : undefined;
    res.json({ status: 'ok', message: 'If that email is valid, a sign-in link is on its way.', devLink });
  });

  app.get('/api/auth/verify', (req, res) => {
    const token = req.query.token as string | undefined;
    const email = token ? db.consumeLoginToken(token) : null;
    if (!email) {
      return res.status(400).send('<h1>Sign-in link invalid or expired</h1><p>Please request a new link from the Seclayer app.</p>');
    }
    const user = db.getOrCreateUser(email);
    const session = db.createSession(user.id);
    res.cookie(SESSION_COOKIE, session, cookieOptions);
    res.redirect('/');
  });

  app.post('/api/auth/logout', (req, res) => {
    const token = req.cookies?.[SESSION_COOKIE];
    if (token) db.deleteSession(token);
    res.clearCookie(SESSION_COOKIE, { ...cookieOptions, maxAge: undefined });
    res.json({ status: 'ok', message: 'Logged out successfully' });
  });

  app.get('/api/auth/me', requireAuth, (req, res) => {
    const user = db.getUser(getUserId(req));
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User profile not found' });
    }
    res.json({ user });
  });
}
