import path from 'path';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import { User, Scan, CreditTransaction, ApiKey, Finding, Severity, SuppressionRule, MonitoredTarget, AuthProfile } from '../src/types.js';

const DEFAULT_DB_FILE = process.env.DB_PATH || path.join(process.cwd(), 'seclayer.db');

// Server-only user record — passwordHash is never sent to the client
interface DbUser extends Omit<User, never> {
  passwordHash?: string;
}

/**
 * SQLite-backed persistent store (better-sqlite3 — synchronous).
 * Class name kept as LocalFileDb for drop-in compatibility with existing
 * imports across server.ts and the test suite. Data survives restarts and
 * redeploys when DB_PATH points at a persistent volume.
 */
export class LocalFileDb {
  private db: Database.Database;
  private readonly scanLogs = new Map<string, string[]>();

  constructor(dbFilePath: string = DEFAULT_DB_FILE) {
    this.db = new Database(dbFilePath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.migrate();
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        credits INTEGER NOT NULL DEFAULT 0,
        apiKey TEXT,
        passwordHash TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        amount INTEGER NOT NULL,
        type TEXT NOT NULL,
        stripeSessionId TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS api_keys (
        key TEXT PRIMARY KEY,
        id TEXT NOT NULL,
        userId TEXT NOT NULL,
        credits INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1,
        createdAt TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        url TEXT NOT NULL,
        authHeader TEXT,
        authProfileId TEXT,
        webhookUrl TEXT,
        status TEXT NOT NULL,
        score INTEGER,
        severity TEXT,
        findings TEXT,
        aiSummary TEXT,
        diagnostics TEXT,
        crawl TEXT,
        error TEXT,
        createdAt TEXT NOT NULL,
        completedAt TEXT
      );
      CREATE TABLE IF NOT EXISTS suppressions (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        targetUrl TEXT NOT NULL,
        findingTitle TEXT NOT NULL,
        reason TEXT,
        createdAt TEXT NOT NULL
      );
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
      CREATE TABLE IF NOT EXISTS auth_profiles (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        data TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_scans_userId ON scans(userId);
      CREATE INDEX IF NOT EXISTS idx_tx_userId ON transactions(userId);
      CREATE INDEX IF NOT EXISTS idx_keys_userId ON api_keys(userId);
      CREATE INDEX IF NOT EXISTS idx_supp_userId ON suppressions(userId);
      CREATE INDEX IF NOT EXISTS idx_mon_userId ON monitored_targets(userId);
      CREATE INDEX IF NOT EXISTS idx_ap_userId ON auth_profiles(userId);
    `);
  }

  // --- (de)serialization helpers ---
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

  private rowToScan(row: any): Scan {
    const scan: Scan = {
      id: row.id,
      userId: row.userId,
      url: row.url,
      status: row.status,
      createdAt: row.createdAt,
    };
    if (row.authHeader != null) scan.authHeader = row.authHeader;
    if (row.authProfileId != null) scan.authProfileId = row.authProfileId;
    if (row.webhookUrl != null) scan.webhookUrl = row.webhookUrl;
    if (row.score != null) scan.score = row.score;
    if (row.severity != null) scan.severity = row.severity;
    if (row.findings != null) scan.findings = JSON.parse(row.findings);
    if (row.aiSummary != null) scan.aiSummary = row.aiSummary;
    if (row.diagnostics != null) scan.diagnostics = JSON.parse(row.diagnostics);
    if (row.crawl != null) scan.crawl = JSON.parse(row.crawl);
    if (row.error != null) scan.error = row.error;
    if (row.completedAt != null) scan.completedAt = row.completedAt;
    return scan;
  }

  private writeScan(scan: Scan) {
    this.db.prepare(`
      INSERT INTO scans (id, userId, url, authHeader, authProfileId, webhookUrl, status, score, severity, findings, aiSummary, diagnostics, crawl, error, createdAt, completedAt)
      VALUES (@id, @userId, @url, @authHeader, @authProfileId, @webhookUrl, @status, @score, @severity, @findings, @aiSummary, @diagnostics, @crawl, @error, @createdAt, @completedAt)
      ON CONFLICT(id) DO UPDATE SET
        userId=excluded.userId, url=excluded.url, authHeader=excluded.authHeader,
        authProfileId=excluded.authProfileId, webhookUrl=excluded.webhookUrl, status=excluded.status,
        score=excluded.score, severity=excluded.severity, findings=excluded.findings,
        aiSummary=excluded.aiSummary, diagnostics=excluded.diagnostics, crawl=excluded.crawl,
        error=excluded.error, createdAt=excluded.createdAt, completedAt=excluded.completedAt
    `).run({
      id: scan.id,
      userId: scan.userId,
      url: scan.url,
      authHeader: scan.authHeader ?? null,
      authProfileId: scan.authProfileId ?? null,
      webhookUrl: scan.webhookUrl ?? null,
      status: scan.status,
      score: scan.score ?? null,
      severity: scan.severity ?? null,
      findings: scan.findings != null ? JSON.stringify(scan.findings) : null,
      aiSummary: scan.aiSummary ?? null,
      diagnostics: scan.diagnostics != null ? JSON.stringify(scan.diagnostics) : null,
      crawl: scan.crawl != null ? JSON.stringify(scan.crawl) : null,
      error: scan.error ?? null,
      createdAt: scan.createdAt,
      completedAt: scan.completedAt ?? null,
    });
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

  // --- Scans ---
  listScans(userId: string): Scan[] {
    return this.db.prepare('SELECT * FROM scans WHERE userId = ? ORDER BY createdAt DESC')
      .all(userId)
      .map(r => this.rowToScan(r));
  }

  getScan(id: string): Scan | undefined {
    const row = this.db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
    return row ? this.rowToScan(row) : undefined;
  }

  createScan(userId: string, url: string, authHeader?: string): Scan {
    const id = 'scan_' + crypto.randomBytes(10).toString('hex');
    const scan: Scan = {
      id,
      userId,
      url,
      authHeader,
      status: 'queued',
      createdAt: new Date().toISOString(),
    };
    this.writeScan(scan);
    return scan;
  }

  updateScan(id: string, updates: Partial<Scan>): Scan {
    const existing = this.getScan(id);
    if (!existing) throw new Error('Scan not found');
    const merged = { ...existing, ...updates };
    this.writeScan(merged);
    return merged;
  }

  /** Patch a single finding inside a scan (remediation lifecycle updates). */
  updateFinding(scanId: string, findingId: string, updates: Partial<Finding>): Scan | null {
    const scan = this.getScan(scanId);
    if (!scan || !scan.findings) return null;
    let found = false;
    scan.findings = scan.findings.map(f => {
      if (f.id === findingId) { found = true; return { ...f, ...updates }; }
      return f;
    });
    if (!found) return null;
    this.writeScan(scan);
    return scan;
  }

  // --- API Keys ---
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
    const userRow = this.db.prepare('SELECT * FROM users WHERE id = ?').get(keyRow.userId);
    if (!userRow) return null;
    const user = this.rowToUser(userRow);
    if (user.credits < quantity) return null;
    return this.addCredits(user.id, -quantity, 'scan_debit');
  }

  // --- Suppression Rules ---
  listSuppressions(userId: string): SuppressionRule[] {
    return this.db.prepare('SELECT id, userId, targetUrl, findingTitle, reason, createdAt FROM suppressions WHERE userId = ?')
      .all(userId)
      .map((r: any) => ({ id: r.id, userId: r.userId, targetUrl: r.targetUrl, findingTitle: r.findingTitle, reason: r.reason ?? '', createdAt: r.createdAt }));
  }

  addSuppression(userId: string, targetUrl: string, findingTitle: string, reason: string): SuppressionRule {
    const id = 'supp_' + crypto.randomBytes(8).toString('hex');
    const rule: SuppressionRule = { id, userId, targetUrl, findingTitle, reason, createdAt: new Date().toISOString() };

    const tx = this.db.transaction(() => {
      this.db.prepare('INSERT INTO suppressions (id, userId, targetUrl, findingTitle, reason, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
        .run(id, userId, targetUrl, findingTitle, reason, rule.createdAt);

      // Retroactively flag matching findings across the user's scans on this URL
      const scans = this.db.prepare('SELECT * FROM scans WHERE userId = ?').all(userId).map(r => this.rowToScan(r));
      const targetClean = cleanUrl(targetUrl);
      for (const scan of scans) {
        if (cleanUrl(scan.url) !== targetClean || !scan.findings) continue;
        let dirty = false;
        scan.findings = scan.findings.map(f => {
          if (f.title === findingTitle) {
            dirty = true;
            return { ...f, isFalsePositive: true, suppressionReason: reason, suppressedAt: rule.createdAt };
          }
          return f;
        });
        if (dirty) {
          const r = recalculateScore(scan.findings);
          scan.score = r.score;
          scan.severity = r.severity;
          this.writeScan(scan);
        }
      }
    });
    tx();

    return rule;
  }

  removeSuppression(userId: string, ruleId: string): boolean {
    const ruleToRemove = this.db.prepare('SELECT * FROM suppressions WHERE id = ? AND userId = ?').get(ruleId, userId) as any;
    if (!ruleToRemove) return false;

    const tx = this.db.transaction(() => {
      this.db.prepare('DELETE FROM suppressions WHERE id = ? AND userId = ?').run(ruleId, userId);

      const scans = this.db.prepare('SELECT * FROM scans WHERE userId = ?').all(userId).map(r => this.rowToScan(r));
      const targetClean = cleanUrl(ruleToRemove.targetUrl);
      for (const scan of scans) {
        if (cleanUrl(scan.url) !== targetClean || !scan.findings) continue;
        let dirty = false;
        scan.findings = scan.findings.map(f => {
          if (f.title === ruleToRemove.findingTitle) {
            dirty = true;
            const { isFalsePositive: _, suppressionReason: __, suppressedAt: ___, ...rest } = f as any;
            return rest;
          }
          return f;
        });
        if (dirty) {
          const r = recalculateScore(scan.findings);
          scan.score = r.score;
          scan.severity = r.severity;
          this.writeScan(scan);
        }
      }
    });
    tx();

    return true;
  }

  // --- Monitored Targets ---
  private rowToMonitored(r: any): MonitoredTarget {
    return {
      id: r.id, userId: r.userId, url: r.url, frequencyDays: r.frequencyDays,
      scheduleString: r.scheduleString ?? undefined, lastScannedAt: r.lastScannedAt ?? undefined,
      nextScanAt: r.nextScanAt ?? undefined, createdAt: r.createdAt,
    };
  }

  listMonitoredTargets(userId: string): MonitoredTarget[] {
    return this.db.prepare('SELECT * FROM monitored_targets WHERE userId = ?').all(userId).map(r => this.rowToMonitored(r));
  }

  addMonitoredTarget(userId: string, url: string, frequencyDays: number, scheduleString?: string): MonitoredTarget {
    const id = 'mon_' + crypto.randomBytes(8).toString('hex');
    const target: MonitoredTarget = {
      id,
      userId,
      url,
      frequencyDays,
      scheduleString,
      createdAt: new Date().toISOString(),
      nextScanAt: new Date(Date.now() + frequencyDays * 86400000).toISOString(),
    };
    this.db.prepare('INSERT INTO monitored_targets (id, userId, url, frequencyDays, scheduleString, lastScannedAt, nextScanAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, userId, url, frequencyDays, scheduleString ?? null, null, target.nextScanAt, target.createdAt);
    return target;
  }

  removeMonitoredTarget(userId: string, id: string): boolean {
    const info = this.db.prepare('DELETE FROM monitored_targets WHERE id = ? AND userId = ?').run(id, userId);
    return info.changes > 0;
  }

  getDueMonitoringTargets(): MonitoredTarget[] {
    const now = new Date().toISOString();
    return this.db.prepare('SELECT * FROM monitored_targets WHERE nextScanAt IS NOT NULL AND nextScanAt <= ?')
      .all(now).map(r => this.rowToMonitored(r));
  }

  touchMonitoredTarget(id: string): void {
    const row = this.db.prepare('SELECT frequencyDays FROM monitored_targets WHERE id = ?').get(id) as any;
    if (!row) return;
    const lastScannedAt = new Date().toISOString();
    const nextScanAt = new Date(Date.now() + row.frequencyDays * 86400000).toISOString();
    this.db.prepare('UPDATE monitored_targets SET lastScannedAt = ?, nextScanAt = ? WHERE id = ?')
      .run(lastScannedAt, nextScanAt, id);
  }

  // --- Scan logs (transient, in-memory — only relevant during an active scan) ---
  appendScanLog(scanId: string, message: string): void {
    if (!this.scanLogs.has(scanId)) this.scanLogs.set(scanId, []);
    const ts = new Date().toISOString();
    this.scanLogs.get(scanId)!.push(`[${ts}] ${message}`);
  }

  getScanLogs(scanId: string): string[] {
    return this.scanLogs.get(scanId) ?? [];
  }

  getScanWithSuppressedFindings(scan: Scan): Scan {
    if (!scan?.findings) return scan;
    const userRules = this.listSuppressions(scan.userId);
    const scanUrlClean = cleanUrl(scan.url);

    let dirty = false;
    const updatedFindings = scan.findings.map(finding => {
      const matchingRule = userRules.find(r =>
        cleanUrl(r.targetUrl) === scanUrlClean && r.findingTitle === finding.title
      );
      if (matchingRule && !finding.isFalsePositive) {
        dirty = true;
        return { ...finding, isFalsePositive: true, suppressionReason: matchingRule.reason, suppressedAt: matchingRule.createdAt };
      }
      if (!matchingRule && finding.isFalsePositive) {
        dirty = true;
        const { isFalsePositive: _, suppressionReason: __, suppressedAt: ___, ...rest } = finding as any;
        return rest;
      }
      return finding;
    });

    if (dirty) {
      const recalc = recalculateScore(updatedFindings);
      scan.findings = updatedFindings;
      scan.score = recalc.score;
      scan.severity = recalc.severity;
      this.writeScan(scan);
    }

    return scan;
  }

  // --- Auth Profiles ---
  createAuthProfile(userId: string, data: Omit<AuthProfile, 'id' | 'userId' | 'createdAt'>): AuthProfile {
    const id = 'ap_' + crypto.randomBytes(8).toString('hex');
    const profile: AuthProfile = { ...data, id, userId, createdAt: new Date().toISOString() };
    this.db.prepare('INSERT INTO auth_profiles (id, userId, data) VALUES (?, ?, ?)')
      .run(id, userId, JSON.stringify(profile));
    return profile;
  }

  getAuthProfile(userId: string, id: string): AuthProfile | null {
    const row = this.db.prepare('SELECT data FROM auth_profiles WHERE id = ? AND userId = ?').get(id, userId) as any;
    return row ? (JSON.parse(row.data) as AuthProfile) : null;
  }

  listAuthProfiles(userId: string): AuthProfile[] {
    return this.db.prepare('SELECT data FROM auth_profiles WHERE userId = ?')
      .all(userId).map((r: any) => JSON.parse(r.data) as AuthProfile);
  }

  deleteAuthProfile(userId: string, id: string): boolean {
    const info = this.db.prepare('DELETE FROM auth_profiles WHERE id = ? AND userId = ?').run(id, userId);
    return info.changes > 0;
  }

  updateAuthProfile(userId: string, id: string, updates: Partial<Omit<AuthProfile, 'id' | 'userId' | 'createdAt'>>): AuthProfile | null {
    const existing = this.getAuthProfile(userId, id);
    if (!existing) return null;
    const merged = { ...existing, ...updates };
    this.db.prepare('UPDATE auth_profiles SET data = ? WHERE id = ? AND userId = ?')
      .run(JSON.stringify(merged), id, userId);
    return merged;
  }
}

// Helpers
export function cleanUrl(urlStr: string): string {
  try {
    return urlStr.replace(/https?:\/\//i, '').replace(/\/+$/, '').trim().toLowerCase();
  } catch {
    return String(urlStr || '').trim().toLowerCase();
  }
}

export function recalculateScore(findings: Finding[]): { score: number; severity: Severity } {
  let score = 100;
  const active = findings.filter(f => !f.isFalsePositive);

  active.forEach(f => {
    const s = f.severity?.toLowerCase();
    if (s === 'critical') score -= 35;
    else if (s === 'high') score -= 25;
    else if (s === 'medium') score -= 15;
    else if (s === 'low') score -= 5;
  });

  score = Math.max(12, Math.min(100, score));

  let severity: Severity = 'low';
  if (active.some(f => f.severity === 'critical')) severity = 'critical';
  else if (active.some(f => f.severity === 'high')) severity = 'high';
  else if (active.some(f => f.severity === 'medium')) severity = 'medium';

  return { score, severity };
}

export const db = new LocalFileDb();
