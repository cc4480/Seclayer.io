import Database from 'better-sqlite3';
import crypto from 'crypto';
import { hashToken } from './mappers.js';

// --- Magic-link auth + sessions ---

// Issues a single-use magic-link token (default 15 min TTL). Returns the raw
// token to embed in the emailed link; only its hash is stored.
export function createLoginToken(db: Database.Database, email: string, ttlMs = 15 * 60 * 1000): string {
  const raw = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('INSERT INTO login_tokens (tokenHash, email, expiresAt, createdAt) VALUES (?, ?, ?, ?)')
    .run(hashToken(raw), email.toLowerCase().trim(), new Date(now + ttlMs).toISOString(), new Date(now).toISOString());
  return raw;
}

// Validates and burns a magic-link token, returning the associated email.
export function consumeLoginToken(db: Database.Database, raw: string): string | null {
  const hash = hashToken(raw);
  const row: any = db.prepare('SELECT * FROM login_tokens WHERE tokenHash = ?').get(hash);
  if (!row || row.consumedAt) return null;
  if (new Date(row.expiresAt).getTime() < Date.now()) return null;
  db.prepare('UPDATE login_tokens SET consumedAt = ? WHERE tokenHash = ?').run(new Date().toISOString(), hash);
  return row.email;
}

// Creates a server-side session (default 30 day TTL). Returns the raw token
// to set as an httpOnly cookie; only its hash is stored.
export function createSession(db: Database.Database, userId: string, ttlMs = 30 * 24 * 60 * 60 * 1000): string {
  const raw = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('INSERT INTO sessions (tokenHash, userId, expiresAt, createdAt) VALUES (?, ?, ?, ?)')
    .run(hashToken(raw), userId, new Date(now + ttlMs).toISOString(), new Date(now).toISOString());
  return raw;
}

// Resolves a session cookie to a userId, or null if missing/expired.
export function getSessionUserId(db: Database.Database, raw: string): string | null {
  const row: any = db.prepare('SELECT * FROM sessions WHERE tokenHash = ?').get(hashToken(raw));
  if (!row) return null;
  if (new Date(row.expiresAt).getTime() < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE tokenHash = ?').run(row.tokenHash);
    return null;
  }
  return row.userId;
}

export function deleteSession(db: Database.Database, raw: string): void {
  db.prepare('DELETE FROM sessions WHERE tokenHash = ?').run(hashToken(raw));
}
