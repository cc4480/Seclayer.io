import path from 'path';
import Database from 'better-sqlite3';
import { User, Scan, CreditTransaction, ApiKey, SuppressionRule, MonitoredTarget } from '../src/types.js';
import { scoreFindings } from './scoring.js';
import { runMigrations } from './db/schema.js';
import { cleanUrl } from './db/url.js';
import * as auth from './db/auth.js';
import * as users from './db/users.js';
import * as scans from './db/scans.js';
import * as keys from './db/keys.js';
import * as suppressions from './db/suppressions.js';
import * as monitoring from './db/monitoring.js';

const DB_FILE = process.env.DB_PATH || path.join(process.cwd(), 'data.sqlite');

// --- URL + scoring helpers ---------------------------------------------------
export { cleanUrl };

// Re-exported for callers/tests that recompute a score from a finding set.
export const recalculateScore = scoreFindings;

// SqliteDb owns the connection and delegates every operation to the domain
// modules under ./db/*. Splitting the queries out keeps each module small while
// preserving the singleton's public method surface exactly.
class SqliteDb {
  private db: Database.Database;

  constructor() {
    this.db = new Database(DB_FILE);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    runMigrations(this.db);
  }

  // --- Magic-link auth + sessions ---
  createLoginToken(email: string, ttlMs?: number): string { return auth.createLoginToken(this.db, email, ttlMs); }
  consumeLoginToken(raw: string): string | null { return auth.consumeLoginToken(this.db, raw); }
  createSession(userId: string, ttlMs?: number): string { return auth.createSession(this.db, userId, ttlMs); }
  getSessionUserId(raw: string): string | null { return auth.getSessionUserId(this.db, raw); }
  deleteSession(raw: string): void { auth.deleteSession(this.db, raw); }

  // --- Users ---
  getUser(id: string): User | undefined { return users.getUser(this.db, id); }
  getUserByEmail(email: string): User | undefined { return users.getUserByEmail(this.db, email); }
  getOrCreateUser(email: string): User { return users.getOrCreateUser(this.db, email); }
  addCredits(userId: string, amount: number, type: 'purchase' | 'scan_debit', stripeSessionId?: string): User {
    return users.addCredits(this.db, userId, amount, type, stripeSessionId);
  }
  deductCredits(userId: string, amount: number): boolean { return users.deductCredits(this.db, userId, amount); }
  listTransactions(userId: string): CreditTransaction[] { return users.listTransactions(this.db, userId); }
  hasTransactionForSession(sessionId: string): boolean { return users.hasTransactionForSession(this.db, sessionId); }
  setUserWebhook(userId: string, url: string | null): User | undefined { return users.setUserWebhook(this.db, userId, url); }

  // --- Scans ---
  listScans(userId: string): Scan[] { return scans.listScans(this.db, userId); }
  getScan(id: string): Scan | undefined { return scans.getScan(this.db, id); }
  createScan(userId: string, url: string, authHeader?: string): Scan { return scans.createScan(this.db, userId, url, authHeader); }
  updateScan(id: string, updates: Partial<Scan>): Scan { return scans.updateScan(this.db, id, updates); }
  getScanWithSuppressedFindings(scan: Scan): Scan { return scans.getScanWithSuppressedFindings(this.db, scan); }

  // --- API Keys ---
  listApiKeys(userId: string): ApiKey[] { return keys.listApiKeys(this.db, userId); }
  generateApiKey(userId: string): ApiKey { return keys.generateApiKey(this.db, userId); }
  revokeApiKey(userId: string, keyId: string): boolean { return keys.revokeApiKey(this.db, userId, keyId); }
  validateApiKeyAndDeduct(apiKeyString: string, quantity: number = 1): User | null {
    return keys.validateApiKeyAndDeduct(this.db, apiKeyString, quantity);
  }

  // --- Suppression Rules ---
  listSuppressions(userId: string): SuppressionRule[] { return suppressions.listSuppressions(this.db, userId); }
  addSuppression(userId: string, targetUrl: string, findingTitle: string, reason: string): SuppressionRule {
    return suppressions.addSuppression(this.db, userId, targetUrl, findingTitle, reason);
  }
  removeSuppression(userId: string, ruleId: string): boolean { return suppressions.removeSuppression(this.db, userId, ruleId); }

  // --- Monitored Targets ---
  listMonitoredTargets(userId: string): MonitoredTarget[] { return monitoring.listMonitoredTargets(this.db, userId); }
  addMonitoredTarget(userId: string, url: string, frequencyDays: number, scheduleString?: string): MonitoredTarget {
    return monitoring.addMonitoredTarget(this.db, userId, url, frequencyDays, scheduleString);
  }
  removeMonitoredTarget(userId: string, id: string): boolean { return monitoring.removeMonitoredTarget(this.db, userId, id); }
  listDueMonitoredTargets(nowIso: string): MonitoredTarget[] { return monitoring.listDueMonitoredTargets(this.db, nowIso); }
  markMonitoredScanned(id: string, lastScannedAt: string, nextScanAt: string): void {
    monitoring.markMonitoredScanned(this.db, id, lastScannedAt, nextScanAt);
  }
}

export const db = new SqliteDb();
