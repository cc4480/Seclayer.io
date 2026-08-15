import Database from 'better-sqlite3';
import crypto from 'crypto';
import { SuppressionRule } from '../../src/types.js';

// --- Suppression Rules (False Positive Management) ---
// Suppression is applied as a read-model (see getScanWithSuppressedFindings),
// so adding/removing a rule is a simple row mutation with no scan rewrites.
export function listSuppressions(db: Database.Database, userId: string): SuppressionRule[] {
  return db.prepare('SELECT * FROM suppressions WHERE userId = ?').all(userId) as SuppressionRule[];
}

export function addSuppression(
  db: Database.Database,
  userId: string,
  targetUrl: string,
  findingTitle: string,
  reason: string,
): SuppressionRule {
  const id = 'supp_' + crypto.randomBytes(8).toString('hex');
  const rule: SuppressionRule = { id, userId, targetUrl, findingTitle, reason, createdAt: new Date().toISOString() };
  db.prepare('INSERT INTO suppressions (id, userId, targetUrl, findingTitle, reason, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, userId, targetUrl, findingTitle, reason, rule.createdAt);
  return rule;
}

export function removeSuppression(db: Database.Database, userId: string, ruleId: string): boolean {
  const res = db.prepare('DELETE FROM suppressions WHERE id = ? AND userId = ?').run(ruleId, userId);
  return res.changes > 0;
}
