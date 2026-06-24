import crypto from 'crypto';
import Database from 'better-sqlite3';
import { User, ApiKey } from '../../src/types.js';
import { UsersRepo } from './users-repo.js';

export class ApiKeysRepo {
  constructor(private db: Database.Database, private users: UsersRepo) {}

  private rowToApiKey(r: any): ApiKey {
    return { id: r.id, userId: r.userId, key: r.key, credits: r.credits, active: !!r.active, createdAt: r.createdAt };
  }

  listApiKeys(userId: string): ApiKey[] {
    return this.db.prepare('SELECT * FROM api_keys WHERE userId = ?').all(userId).map(r => this.rowToApiKey(r));
  }

  findApiKey(keyStr: string): ApiKey | null {
    const row = this.db.prepare('SELECT * FROM api_keys WHERE key = ?').get(keyStr);
    return row ? this.rowToApiKey(row) : null;
  }

  generateApiKey(userId: string): ApiKey {
    const row = this.db.prepare('SELECT credits FROM users WHERE id = ?').get(userId) as any;
    if (!row) throw new Error('User not found');
    const id = 'key_' + crypto.randomBytes(8).toString('hex');
    const keyStr = 'sl_live_' + crypto.randomBytes(20).toString('hex');
    const createdAt = new Date().toISOString();
    this.db.prepare('INSERT INTO api_keys (key, id, userId, credits, active, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
      .run(keyStr, id, userId, row.credits, 1, createdAt);
    return { id, userId, key: keyStr, credits: row.credits, active: true, createdAt };
  }

  revokeApiKey(userId: string, keyId: string): boolean {
    const info = this.db.prepare('UPDATE api_keys SET active = 0 WHERE id = ? AND userId = ?').run(keyId, userId);
    return info.changes > 0;
  }

  validateApiKeyAndDeduct(apiKeyString: string, quantity: number = 1): User | null {
    const keyRow = this.db.prepare('SELECT * FROM api_keys WHERE key = ?').get(apiKeyString) as any;
    if (!keyRow || !keyRow.active) return null;
    const user = this.users.getDbUser(keyRow.userId);
    if (!user) return null;
    if (user.credits < quantity) return null;
    return this.users.addCredits(user.id, -quantity, 'scan_debit');
  }
}
