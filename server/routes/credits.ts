import type { Express } from 'express';
import { db } from '../db.js';
import { HttpError, currentUserId } from '../middleware.js';

/** Credit balances, mock checkout, and the mock Stripe webhook. */
export function registerCreditRoutes(app: Express): void {
  app.get('/api/credits', (req, res) => {
    const userId = currentUserId(req);
    const user = db.getUser(userId);
    if (!user) throw new HttpError(404, 'User not found');
    res.json({
      credits: user.credits,
      transactions: db.listTransactions(userId),
    });
  });

  // Mock Stripe Checkout test integration
  app.post('/api/credits/checkout', (req, res) => {
    const userId = currentUserId(req);
    const pack = req.body?.pack;

    const PRICES = {
      single: { price: 29, credits: 1 },
      pack5: { price: 99, credits: 5 },
      pack20: { price: 299, credits: 20 },
    };

    const selectedPack = PRICES[pack as keyof typeof PRICES];
    if (!selectedPack) {
      throw new HttpError(400, 'Invalid credit pack selected');
    }

    const user = db.getUser(userId);
    if (!user) throw new HttpError(404, 'User not found');

    const sessionId = `cs_test_${Math.random().toString(36).substring(2, 15)}`;
    db.addCredits(userId, selectedPack.credits, 'purchase', sessionId);

    res.json({
      status: 'ok',
      url: `/dashboard?checkout_success=true&credits=${selectedPack.credits}`,
      sessionId,
      creditsAdded: selectedPack.credits,
      pricePaid: selectedPack.price,
    });
  });

  // Mock Stripe Webhook endpoint
  app.post('/api/webhooks/stripe', (_req, res) => {
    res.json({ received: true });
  });
}
