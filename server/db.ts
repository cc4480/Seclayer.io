import path from 'path';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import { User, Scan, CreditTransaction, ApiKey, Finding, SuppressionRule, MonitoredTarget } from '../src/types.js';
import { scoreFindings } from './scoring.js';

const DB_FILE = process.env.DB_PATH || path.join(process.cwd(), 'data.sqlite');

// --- URL + scoring helpers ---------------------------------------------------
export function cleanUrl(urlStr: string): string {
  try {
    return urlStr.replace(/https?:\/\//i, '').replace(/\/+$/, '').trim().toLowerCase();
  } catch {
    return String(urlStr || '').trim().toLowerCase();
  }
}

// Re-exported for callers/tests that recompute a score from a finding set.
export const recalculateScore = scoreFindings;

class SqliteDb {
  private db: Database.Database;

  constructor() {
    this.db = new Database(DB_FILE);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.migrate();
    this.seedIfEmpty();
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        credits INTEGER NOT NULL DEFAULT 0,
        apiKey TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        url TEXT NOT NULL,
        authHeader TEXT,
        status TEXT NOT NULL,
        score INTEGER,
        severity TEXT,
        findings TEXT,
        aiSummary TEXT,
        error TEXT,
        createdAt TEXT NOT NULL,
        completedAt TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(userId);
      CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        amount INTEGER NOT NULL,
        type TEXT NOT NULL,
        stripeSessionId TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(userId);
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        key TEXT UNIQUE NOT NULL,
        credits INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_keys_user ON api_keys(userId);
      CREATE TABLE IF NOT EXISTS suppressions (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        targetUrl TEXT NOT NULL,
        findingTitle TEXT NOT NULL,
        reason TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_supp_user ON suppressions(userId);
      CREATE TABLE IF NOT EXISTS monitored_targets (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        url TEXT NOT NULL,
        frequencyDays INTEGER NOT NULL,
        scheduleString TEXT,
        lastScannedAt TEXT,
        nextScanAt TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_mon_user ON monitored_targets(userId);
    `);
  }

  // --- Row mappers ---
  private rowToUser(row: any): User | undefined {
    if (!row) return undefined;
    return { id: row.id, email: row.email, credits: row.credits, apiKey: row.apiKey, createdAt: row.createdAt };
  }

  private rowToScan(row: any): Scan | undefined {
    if (!row) return undefined;
    return {
      id: row.id,
      userId: row.userId,
      url: row.url,
      authHeader: row.authHeader ?? undefined,
      status: row.status,
      score: row.score ?? undefined,
      severity: row.severity ?? undefined,
      findings: row.findings ? JSON.parse(row.findings) : undefined,
      aiSummary: row.aiSummary ?? undefined,
      error: row.error ?? undefined,
      createdAt: row.createdAt,
      completedAt: row.completedAt ?? undefined,
    };
  }

  private rowToApiKey(row: any): ApiKey {
    return {
      id: row.id, userId: row.userId, key: row.key,
      credits: row.credits, active: !!row.active, createdAt: row.createdAt,
    };
  }

  // --- Users ---
  getUser(id: string): User | undefined {
    return this.rowToUser(this.db.prepare('SELECT * FROM users WHERE id = ?').get(id));
  }

  getUserByEmail(email: string): User | undefined {
    return this.rowToUser(
      this.db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim())
    );
  }

  // Creates a user with an explicit id + credit balance (used for seeding a
  // fixed demo account). Also provisions a matching API key.
  createUserWithId(id: string, email: string, credits: number): User {
    const normEmail = email.toLowerCase().trim();
    const apiKey = 'sl_live_' + crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();
    const tx = this.db.transaction(() => {
      this.db.prepare('INSERT INTO users (id, email, credits, apiKey, createdAt) VALUES (?, ?, ?, ?, ?)')
        .run(id, normEmail, credits, apiKey, now);
      this.db.prepare('INSERT INTO transactions (id, userId, amount, type, stripeSessionId, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
        .run('tx-seed-' + id, id, credits, 'purchase', 'cs_test_initial_provision', now);
      this.db.prepare('INSERT INTO api_keys (id, userId, key, credits, active, createdAt) VALUES (?, ?, ?, ?, 1, ?)')
        .run('key-' + id, id, apiKey, credits, now);
    });
    tx();
    return this.getUser(id)!;
  }

  getOrCreateUser(email: string): User {
    const normEmail = email.toLowerCase().trim();
    const existing = this.getUserByEmail(normEmail);
    if (existing) return existing;

    const id = 'user_' + crypto.randomBytes(6).toString('hex');
    const apiKey = 'sl_live_' + crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();

    const tx = this.db.transaction(() => {
      this.db.prepare('INSERT INTO users (id, email, credits, apiKey, createdAt) VALUES (?, ?, ?, ?, ?)')
        .run(id, normEmail, 5, apiKey, now); // 5 signup credits
      this.db.prepare('INSERT INTO transactions (id, userId, amount, type, createdAt) VALUES (?, ?, ?, ?, ?)')
        .run('tx-signup-' + id, id, 5, 'purchase', now);
      this.db.prepare('INSERT INTO api_keys (id, userId, key, credits, active, createdAt) VALUES (?, ?, ?, ?, 1, ?)')
        .run('key-' + id, id, apiKey, 5, now);
    });
    tx();
    return this.getUser(id)!;
  }

  addCredits(userId: string, amount: number, type: 'purchase' | 'scan_debit', stripeSessionId?: string): User {
    const user = this.getUser(userId);
    if (!user) throw new Error('User not found');
    const newCredits = Math.max(0, user.credits + amount);

    const tx = this.db.transaction(() => {
      this.db.prepare('UPDATE users SET credits = ? WHERE id = ?').run(newCredits, userId);
      this.db.prepare('UPDATE api_keys SET credits = ? WHERE userId = ? AND active = 1').run(newCredits, userId);
      this.db.prepare('INSERT INTO transactions (id, userId, amount, type, stripeSessionId, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
        .run('tx_' + crypto.randomBytes(8).toString('hex'), userId, amount, type, stripeSessionId ?? null, new Date().toISOString());
    });
    tx();
    return this.getUser(userId)!;
  }

  deductCredits(userId: string, amount: number): boolean {
    const user = this.getUser(userId);
    if (!user || user.credits < amount) return false;
    this.addCredits(userId, -amount, 'scan_debit');
    return true;
  }

  listTransactions(userId: string): CreditTransaction[] {
    return this.db.prepare('SELECT * FROM transactions WHERE userId = ? ORDER BY createdAt DESC').all(userId) as CreditTransaction[];
  }

  // --- Scans ---
  listScans(userId: string): Scan[] {
    const rows = this.db.prepare('SELECT * FROM scans WHERE userId = ? ORDER BY createdAt DESC').all(userId);
    return rows.map(r => this.rowToScan(r)!).filter(Boolean);
  }

  getScan(id: string): Scan | undefined {
    return this.rowToScan(this.db.prepare('SELECT * FROM scans WHERE id = ?').get(id));
  }

  createScan(userId: string, url: string, authHeader?: string): Scan {
    const id = 'scan_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    this.db.prepare('INSERT INTO scans (id, userId, url, authHeader, status, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, userId, url, authHeader ?? null, 'queued', now);
    return this.getScan(id)!;
  }

  updateScan(id: string, updates: Partial<Scan>): Scan {
    const existing = this.getScan(id);
    if (!existing) throw new Error('Scan not found');
    const merged = { ...existing, ...updates };
    this.db.prepare(`
      UPDATE scans SET status = ?, score = ?, severity = ?, findings = ?, aiSummary = ?, error = ?, completedAt = ?
      WHERE id = ?
    `).run(
      merged.status,
      merged.score ?? null,
      merged.severity ?? null,
      merged.findings ? JSON.stringify(merged.findings) : null,
      merged.aiSummary ?? null,
      merged.error ?? null,
      merged.completedAt ?? null,
      id
    );
    return this.getScan(id)!;
  }

  // --- API Keys ---
  listApiKeys(userId: string): ApiKey[] {
    return (this.db.prepare('SELECT * FROM api_keys WHERE userId = ?').all(userId) as any[]).map(r => this.rowToApiKey(r));
  }

  generateApiKey(userId: string): ApiKey {
    const user = this.getUser(userId);
    if (!user) throw new Error('User not found');
    const id = 'key_' + crypto.randomBytes(8).toString('hex');
    const keyStr = 'sl_live_' + crypto.randomBytes(16).toString('hex');
    this.db.prepare('INSERT INTO api_keys (id, userId, key, credits, active, createdAt) VALUES (?, ?, ?, ?, 1, ?)')
      .run(id, userId, keyStr, user.credits, new Date().toISOString());
    return this.rowToApiKey(this.db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id));
  }

  revokeApiKey(userId: string, keyId: string): boolean {
    const res = this.db.prepare('UPDATE api_keys SET active = 0 WHERE id = ? AND userId = ?').run(keyId, userId);
    return res.changes > 0;
  }

  validateApiKeyAndDeduct(apiKeyString: string, quantity: number = 1): User | null {
    const keyRow: any = this.db.prepare('SELECT * FROM api_keys WHERE key = ?').get(apiKeyString);
    if (!keyRow || !keyRow.active) return null;
    const user = this.getUser(keyRow.userId);
    if (!user || user.credits < quantity) return null;
    return this.addCredits(user.id, -quantity, 'scan_debit');
  }

  // --- Suppression Rules (False Positive Management) ---
  // Suppression is applied as a read-model (see getScanWithSuppressedFindings),
  // so adding/removing a rule is a simple row mutation with no scan rewrites.
  listSuppressions(userId: string): SuppressionRule[] {
    return this.db.prepare('SELECT * FROM suppressions WHERE userId = ?').all(userId) as SuppressionRule[];
  }

  addSuppression(userId: string, targetUrl: string, findingTitle: string, reason: string): SuppressionRule {
    const id = 'supp_' + crypto.randomBytes(8).toString('hex');
    const rule: SuppressionRule = { id, userId, targetUrl, findingTitle, reason, createdAt: new Date().toISOString() };
    this.db.prepare('INSERT INTO suppressions (id, userId, targetUrl, findingTitle, reason, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, userId, targetUrl, findingTitle, reason, rule.createdAt);
    return rule;
  }

  removeSuppression(userId: string, ruleId: string): boolean {
    const res = this.db.prepare('DELETE FROM suppressions WHERE id = ? AND userId = ?').run(ruleId, userId);
    return res.changes > 0;
  }

  // --- Monitored Targets ---
  listMonitoredTargets(userId: string): MonitoredTarget[] {
    return this.db.prepare('SELECT * FROM monitored_targets WHERE userId = ?').all(userId) as MonitoredTarget[];
  }

  addMonitoredTarget(userId: string, url: string, frequencyDays: number, scheduleString?: string): MonitoredTarget {
    const id = 'mon_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    const nextScanAt = new Date(Date.now() + frequencyDays * 24 * 60 * 60 * 1000).toISOString();
    this.db.prepare('INSERT INTO monitored_targets (id, userId, url, frequencyDays, scheduleString, nextScanAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(id, userId, url, frequencyDays, scheduleString ?? null, nextScanAt, now);
    return this.db.prepare('SELECT * FROM monitored_targets WHERE id = ?').get(id) as MonitoredTarget;
  }

  removeMonitoredTarget(userId: string, id: string): boolean {
    const res = this.db.prepare('DELETE FROM monitored_targets WHERE id = ? AND userId = ?').run(id, userId);
    return res.changes > 0;
  }

  // Read-model: returns a scan with suppression rules applied and the score
  // recalculated. This is a PURE transform — it never writes to the database,
  // so reads have no side effects.
  getScanWithSuppressedFindings(scan: Scan): Scan {
    if (!scan || !scan.findings) return scan;
    const rules = this.listSuppressions(scan.userId);
    const scanUrlClean = cleanUrl(scan.url);

    const findings = scan.findings.map((finding) => {
      const rule = rules.find(r => cleanUrl(r.targetUrl) === scanUrlClean && r.findingTitle === finding.title);
      if (rule) {
        return { ...finding, isFalsePositive: true, suppressionReason: rule.reason, suppressedAt: rule.createdAt };
      }
      // Strip any stale suppression metadata if no rule currently matches.
      const { isFalsePositive, suppressionReason, suppressedAt, ...rest } = finding;
      return rest as Finding;
    });

    const { score, severity } = scoreFindings(findings);
    return { ...scan, findings, score, severity };
  }

  private seedIfEmpty() {
    const count = (this.db.prepare('SELECT COUNT(*) AS n FROM users').get() as any).n;
    if (count > 0) return;
    seedDemoData(this);
  }
}

// Seeds a demo user + two illustrative scans so a fresh install is not empty.
// Uses the fixed `user_default` id the zero-config frontend loads on boot.
function seedDemoData(db: SqliteDb) {
  const user = db.createUserWithId('user_default', 'demo@seclayer.io', 10);

  const s1 = db.createScan(user.id, 'https://seclayer.io');
  db.updateScan(s1.id, {
    status: 'complete',
    score: 95,
    severity: 'low',
    completedAt: new Date(Date.now() - 3600000 * 47.9).toISOString(),
    aiSummary: 'The target website is exceptionally well-secured. All standard security headers are present with secure configurations. SSL/TLS is modern and correctly configured. The server does not leak technological implementations, which limits vector fingerprinting.',
    findings: [
      { id: 'finding-1', title: 'Missing Subresource Integrity (SRI) on external vendor assets', description: 'Several script tags loaded from third-party CDNs do not feature integrity hashes. If these vendors are compromised, malicious code could run in visitors\' browser context.', severity: 'low', confidence: 'high', fix: 'Add the integrity="" attribute with correct SHA-384 hashes and crossorigin="anonymous" to all external script and stylesheet links.', category: 'SCA' },
    ],
  });

  const s2 = db.createScan(user.id, 'https://vulnerable-test-shop.org');
  db.updateScan(s2.id, {
    status: 'complete',
    score: 35,
    severity: 'critical',
    completedAt: new Date(Date.now() - 3600000 * 119.8).toISOString(),
    aiSummary: 'The application exhibits severe perimeter exposures. Critical issues were uncovered, including sensitive file leakage (.env containing database credentials) and a missing Content-Security-Policy. Remediation is an urgent requirement to avoid data exfiltration or site hijacking.',
    findings: [
      { id: 'finding-3', title: 'Exposed Environment Configuration File (.env)', description: 'A raw /.env configuration file was detected via root directory probing. This file contains active credentials, including database passwords and Stripe private keys.', severity: 'critical', confidence: 'high', fix: 'Immediately rotate all leaked credentials. Move the .env file out of the public web root and block requests to dotfiles.', category: 'DAST' },
      { id: 'finding-5', title: 'Missing Content-Security-Policy (CSP) Header', description: 'The response does not contain a Content-Security-Policy header, leaving browsers vulnerable to Cross-Site Scripting (XSS) and data injection attacks.', severity: 'high', confidence: 'high', fix: 'Implement a strict CSP header declaring trusted sources for scripts, styles, images, and frame origins.', category: 'IAST' },
    ],
  });
}

export const db = new SqliteDb();
