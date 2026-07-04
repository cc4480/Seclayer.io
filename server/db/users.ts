import Database from 'better-sqlite3';
import crypto from 'crypto';
import { User, CreditTransaction } from '../../src/types.js';
import { rowToUser } from './mappers.js';

export function getUser(db: Database.Database, id: string): User | undefined {
  return rowToUser(db.prepare('SELECT * FROM users WHERE id = ?').get(id));
}

export function getUserByEmail(db: Database.Database, email: string): User | undefined {
  return rowToUser(
    db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim())
  );
}

export function getOrCreateUser(db: Database.Database, email: string): User {
  const normEmail = email.toLowerCase().trim();
  const existing = getUserByEmail(db, normEmail);
  if (existing) return existing;

  const id = 'user_' + crypto.randomBytes(6).toString('hex');
  const apiKey = 'sl_live_' + crypto.randomBytes(16).toString('hex');
  const now = new Date().toISOString();

  const tx = db.transaction(() => {
    db.prepare('INSERT INTO users (id, email, credits, apiKey, createdAt) VALUES (?, ?, ?, ?, ?)')
      .run(id, normEmail, 5, apiKey, now); // 5 signup credits
    db.prepare('INSERT INTO transactions (id, userId, amount, type, createdAt) VALUES (?, ?, ?, ?, ?)')
      .run('tx-signup-' + id, id, 5, 'purchase', now);
    db.prepare('INSERT INTO api_keys (id, userId, key, credits, active, createdAt) VALUES (?, ?, ?, ?, 1, ?)')
      .run('key-' + id, id, apiKey, 5, now);
  });
  tx();
  return getUser(db, id)!;
}

export function addCredits(
  db: Database.Database,
  userId: string,
  amount: number,
  type: 'purchase' | 'scan_debit',
  stripeSessionId?: string,
): User {
  const user = getUser(db, userId);
  if (!user) throw new Error('User not found');
  const newCredits = Math.max(0, user.credits + amount);

  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET credits = ? WHERE id = ?').run(newCredits, userId);
    db.prepare('UPDATE api_keys SET credits = ? WHERE userId = ? AND active = 1').run(newCredits, userId);
    db.prepare('INSERT INTO transactions (id, userId, amount, type, stripeSessionId, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
      .run('tx_' + crypto.randomBytes(8).toString('hex'), userId, amount, type, stripeSessionId ?? null, new Date().toISOString());
  });
  tx();
  return getUser(db, userId)!;
}

export function deductCredits(db: Database.Database, userId: string, amount: number): boolean {
  const user = getUser(db, userId);
  if (!user || user.credits < amount) return false;
  addCredits(db, userId, -amount, 'scan_debit');
  return true;
}

export function listTransactions(db: Database.Database, userId: string): CreditTransaction[] {
  return db.prepare('SELECT * FROM transactions WHERE userId = ? ORDER BY createdAt DESC').all(userId) as CreditTransaction[];
}

// Idempotency guard for Stripe webhooks: true if a purchase for this Checkout
// session was already recorded, so retries never grant duplicate credits.
export function hasTransactionForSession(db: Database.Database, sessionId: string): boolean {
  return !!db.prepare('SELECT 1 FROM transactions WHERE stripeSessionId = ? LIMIT 1').get(sessionId);
}

export function setUserWebhook(db: Database.Database, userId: string, url: string | null): User | undefined {
  db.prepare("UPDATE users SET notifyWebhook = ? WHERE id = ?").run(url, userId);
  return getUser(db, userId);
}
