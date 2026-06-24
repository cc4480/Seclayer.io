import crypto from 'crypto';
import Database from 'better-sqlite3';
import { User, CreditTransaction } from '../../src/types.js';

// Server-only user record — passwordHash is never sent to the client
export interface DbUser extends Omit<User, never> {
  passwordHash?: string;
}

export class UsersRepo {
  constructor(private db: Database.Database) {}

  private rowToUser(row: any): DbUser {
    return {
      id: row.id,
      email: row.email,
      credits: row.credits,
      apiKey: row.apiKey,
      createdAt: row.createdAt,
      passwordHash: row.passwordHash ?? undefined,
    };
  }

  private toPublicUser(u: DbUser): User {
    const { passwordHash: _, ...pub } = u as any;
    return pub as User;
  }

  // --- Auth ---
  findUserByEmail(email: string): DbUser | null {
    const norm = email.toLowerCase().trim();
    const row = this.db.prepare('SELECT * FROM users WHERE email = ?').get(norm);
    return row ? this.rowToUser(row) : null;
  }

  registerUser(email: string, passwordHash: string): User {
    const norm = email.toLowerCase().trim();
    if (this.findUserByEmail(norm)) {
      throw new Error('An account with this email already exists.');
    }

    const id = 'user_' + crypto.randomBytes(8).toString('hex');
    const apiKey = 'sl_live_' + crypto.randomBytes(20).toString('hex');
    const now = new Date().toISOString();

    const tx = this.db.transaction(() => {
      this.db.prepare('INSERT INTO users (id, email, credits, apiKey, passwordHash, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
        .run(id, norm, 5, apiKey, passwordHash, now);
      this.db.prepare('INSERT INTO transactions (id, userId, amount, type, stripeSessionId, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
        .run('tx_signup_' + id, id, 5, 'purchase', null, now);
      this.db.prepare('INSERT INTO api_keys (key, id, userId, credits, active, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
        .run(apiKey, 'key_' + crypto.randomBytes(8).toString('hex'), id, 5, 1, now);
    });
    tx();

    return this.toPublicUser({ id, email: norm, credits: 5, apiKey, createdAt: now, passwordHash });
  }

  // --- Users ---
  getUser(id: string): User | undefined {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    return row ? this.toPublicUser(this.rowToUser(row)) : undefined;
  }

  getDbUser(id: string): DbUser | undefined {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    return row ? this.rowToUser(row) : undefined;
  }

  addCredits(userId: string, amount: number, type: 'purchase' | 'scan_debit', stripeSessionId?: string): User {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!row) throw new Error('User not found');
    const user = this.rowToUser(row);
    const newCredits = Math.max(0, user.credits + amount);

    const tx = this.db.transaction(() => {
      this.db.prepare('UPDATE users SET credits = ? WHERE id = ?').run(newCredits, userId);
      // Mirror credits on active API keys
      this.db.prepare('UPDATE api_keys SET credits = ? WHERE userId = ? AND active = 1').run(newCredits, userId);
      this.db.prepare('INSERT INTO transactions (id, userId, amount, type, stripeSessionId, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
        .run('tx_' + crypto.randomBytes(8).toString('hex'), userId, amount, type, stripeSessionId ?? null, new Date().toISOString());
    });
    tx();

    user.credits = newCredits;
    return this.toPublicUser(user);
  }

  deductCredits(userId: string, amount: number): boolean {
    const row = this.db.prepare('SELECT credits FROM users WHERE id = ?').get(userId) as any;
    if (!row || row.credits < amount) return false;
    this.addCredits(userId, -amount, 'scan_debit');
    return true;
  }

  getTransactions(userId: string): CreditTransaction[] {
    return this.db.prepare('SELECT id, userId, amount, type, stripeSessionId, createdAt FROM transactions WHERE userId = ?')
      .all(userId)
      .map((r: any) => ({
        id: r.id, userId: r.userId, amount: r.amount, type: r.type,
        stripeSessionId: r.stripeSessionId ?? undefined, createdAt: r.createdAt,
      }));
  }
}
