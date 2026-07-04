import express from 'express';
import { db } from '../db.js';
import { config } from '../config.js';
import { createCheckoutSession, parseWebhookEvent, isStripeConfigured } from '../stripe.js';
import { requireAuth, getUserId } from '../http/context.js';

// Stripe webhook MUST receive the raw body for signature verification, so it is
// registered before the JSON body parser (see server.ts ordering). Credits are
// granted only here, on a verified, paid checkout.session.completed event.
export function registerStripeWebhook(app: express.Express): void {
  app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
    let completion;
    try {
      completion = parseWebhookEvent(req.body as Buffer, req.headers['stripe-signature'] as string | undefined);
    } catch (err: any) {
      console.warn('[stripe] Webhook verification failed:', err?.message || err);
      return res.status(400).json({ error: `Webhook Error: ${err?.message || 'invalid signature'}` });
    }
    if (completion && !db.hasTransactionForSession(completion.sessionId)) {
      const user = db.getUser(completion.userId);
      if (user) {
        db.addCredits(user.id, completion.credits, 'purchase', completion.sessionId);
        console.log(`[stripe] Granted ${completion.credits} credits to ${user.id} (session ${completion.sessionId}).`);
      }
    }
    res.json({ received: true });
  });
}

// --- Credits ---
export function registerCreditRoutes(app: express.Express): void {
  app.get('/api/credits', requireAuth, (req, res) => {
    const userId = getUserId(req);
    const user = db.getUser(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({
      credits: user.credits,
      transactions: db.listTransactions(userId)
    });
  });

  // Real Stripe Checkout. Returns a hosted checkout URL; credits are granted by
  // the verified webhook after payment, never here.
  app.post('/api/credits/checkout', requireAuth, async (req, res) => {
    if (!isStripeConfigured()) {
      return res.status(503).json({ status: 'error', message: 'Payments are not currently available. Please contact support.' });
    }
    const { pack } = req.body;
    // Trusted base only (APP_URL enforced in production); dev falls back to host.
    const base = config.appUrl || `${req.protocol}://${req.get('host')}`;
    try {
      const url = await createCheckoutSession(getUserId(req), pack, base);
      res.json({ status: 'ok', url });
    } catch (err: any) {
      const msg = err?.message || 'Could not start checkout.';
      const code = /invalid credit pack/i.test(msg) ? 400 : 502;
      res.status(code).json({ status: 'error', message: msg });
    }
  });
}
