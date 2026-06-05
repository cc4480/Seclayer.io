import Stripe from 'stripe';

const CREDIT_PACKS = {
  single: { credits: 1, label: '1 Scan Credit' },
  pack5:  { credits: 5, label: '5 Scan Credits' },
  pack20: { credits: 20, label: '20 Scan Credits' },
} as const;

function getStripe(): Stripe {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key || key === 'YOUR_STRIPE_SECRET_KEY') {
    throw new Error(
      'Stripe is not configured. Set STRIPE_SECRET_KEY in your environment variables.'
    );
  }
  return new Stripe(key);
}

export async function createCheckoutSession(
  pack: keyof typeof CREDIT_PACKS,
  userId: string,
  appUrl: string
): Promise<{ url: string; sessionId: string }> {
  const stripe = getStripe();
  const selected = CREDIT_PACKS[pack];

  const priceEnvKey = `STRIPE_PRICE_${pack.toUpperCase()}`;
  const priceId = process.env[priceEnvKey];
  if (!priceId) {
    throw new Error(
      `Stripe price ID for "${pack}" is not configured. Set ${priceEnvKey} in your environment variables.`
    );
  }

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{ price: priceId, quantity: 1 }],
    mode: 'payment',
    success_url: `${appUrl}/dashboard?checkout_success=true&credits=${selected.credits}`,
    cancel_url: `${appUrl}/dashboard`,
    metadata: {
      userId,
      pack,
      credits: String(selected.credits),
    },
  });

  return { url: session.url!, sessionId: session.id };
}

export async function handleStripeWebhook(
  rawBody: Buffer,
  signature: string
): Promise<{ userId: string; credits: number; sessionId: string } | null> {
  const stripe = getStripe();

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) {
    throw new Error('STRIPE_WEBHOOK_SECRET is not configured.');
  }

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
  } catch (err: any) {
    throw new Error(`Webhook signature verification failed: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as Stripe.Checkout.Session;
    const { userId, credits } = session.metadata || {};
    if (userId && credits) {
      return {
        userId,
        credits: parseInt(credits, 10),
        sessionId: session.id,
      };
    }
  }

  return null;
}
