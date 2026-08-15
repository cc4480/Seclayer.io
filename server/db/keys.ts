import Database from 'better-sqlite3';
import crypto from 'crypto';
import { ApiKey, User } from '../../src/types.js';
import { rowToApiKey } from './mappers.js';
import { getUser, addCredits } from './users.js';

export function listApiKeys(db: Database.Database, userId: string): ApiKey[] {
  return (db.prepare('SELECT * FROM api_keys WHERE userId = ?').all(userId) as any[]).map(r => rowToApiKey(r));
}

export function generateApiKey(db: Database.Database, userId: string): ApiKey {
  const user = getUser(db, userId);
  if (!user) throw new Error('User not found');
  const id = 'key_' + crypto.randomBytes(8).toString('hex');
  const keyStr = 'sl_live_' + crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO api_keys (id, userId, key, credits, active, createdAt) VALUES (?, ?, ?, ?, 1, ?)')
    .run(id, userId, keyStr, user.credits, new Date().toISOString());
  return rowToApiKey(db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id));
}

export function revokeApiKey(db: Database.Database, userId: string, keyId: string): boolean {
  const res = db.prepare('UPDATE api_keys SET active = 0 WHERE id = ? AND userId = ?').run(keyId, userId);
  return res.changes > 0;
}

export function validateApiKeyAndDeduct(db: Database.Database, apiKeyString: string, quantity: number = 1): User | null {
  const keyRow: any = db.prepare('SELECT * FROM api_keys WHERE key = ?').get(apiKeyString);
  if (!keyRow || !keyRow.active) return null;
  const user = getUser(db, keyRow.userId);
  if (!user || user.credits < quantity) return null;
  return addCredits(db, user.id, -quantity, 'scan_debit');
}
