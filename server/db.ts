import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { User, Scan, CreditTransaction, ApiKey, Finding, Severity, SuppressionRule, MonitoredTarget } from '../src/types.js';

const DB_FILE = path.join(process.cwd(), 'db.json');

// Server-only user record — passwordHash is never sent to the client
interface DbUser extends Omit<User, never> {
  passwordHash?: string;
}

interface DbSchema {
  users: Record<string, DbUser>;
  scans: Record<string, Scan>;
  transactions: CreditTransaction[];
  apiKeys: Record<string, ApiKey>;
  suppressions: SuppressionRule[];
  monitoredTargets: MonitoredTarget[];
}

class LocalFileDb {
  private data: DbSchema;

  constructor() {
    this.data = {
      users: {},
      scans: {},
      transactions: [],
      apiKeys: {},
      suppressions: [],
      monitoredTargets: [],
    };
    this.load();
  }

  private load() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        const parsed = JSON.parse(raw) as DbSchema;
        this.data = {
          suppressions: [],
          monitoredTargets: [],
          ...parsed,
        };
      }
    } catch (err) {
      console.error('Error loading DB file:', err);
    }
  }

  private save() {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), 'utf8');
    } catch (err) {
      console.error('Error saving DB file:', err);
    }
  }

  private toPublicUser(u: DbUser): User {
    const { passwordHash: _, ...pub } = u as any;
    return pub as User;
  }

  // --- Auth ---
  findUserByEmail(email: string): DbUser | null {
    const norm = email.toLowerCase().trim();
    return Object.values(this.data.users).find(u => u.email.toLowerCase() === norm) || null;
  }

  registerUser(email: string, passwordHash: string): User {
    const norm = email.toLowerCase().trim();
    if (this.findUserByEmail(norm)) {
      throw new Error('An account with this email already exists.');
    }

    const id = 'user_' + crypto.randomBytes(8).toString('hex');
    const apiKey = 'sl_live_' + crypto.randomBytes(20).toString('hex');

    const newUser: DbUser = {
      id,
      email: norm,
      credits: 5,
      apiKey,
      createdAt: new Date().toISOString(),
      passwordHash,
    };

    this.data.users[id] = newUser;

    // Signup credit grant
    this.data.transactions.push({
      id: 'tx_signup_' + id,
      userId: id,
      amount: 5,
      type: 'purchase',
      createdAt: new Date().toISOString(),
    });

    // Matching API key record
    this.data.apiKeys[apiKey] = {
      id: 'key_' + crypto.randomBytes(8).toString('hex'),
      userId: id,
      key: apiKey,
      credits: 5,
      active: true,
      createdAt: new Date().toISOString(),
    };

    this.save();
    return this.toPublicUser(newUser);
  }

  // --- Users ---
  getUser(id: string): User | undefined {
    const u = this.data.users[id];
    return u ? this.toPublicUser(u) : undefined;
  }

  getDbUser(id: string): DbUser | undefined {
    return this.data.users[id];
  }

  addCredits(userId: string, amount: number, type: 'purchase' | 'scan_debit', stripeSessionId?: string): User {
    const user = this.data.users[userId];
    if (!user) throw new Error('User not found');
    user.credits = Math.max(0, user.credits + amount);

    // Mirror credits on active API keys
    Object.values(this.data.apiKeys).forEach(k => {
      if (k.userId === userId && k.active) {
        k.credits = user.credits;
      }
    });

    this.data.transactions.push({
      id: 'tx_' + crypto.randomBytes(8).toString('hex'),
      userId,
      amount,
      type,
      stripeSessionId,
      createdAt: new Date().toISOString(),
    });
    this.save();
    return this.toPublicUser(user);
  }

  deductCredits(userId: string, amount: number): boolean {
    const user = this.data.users[userId];
    if (!user || user.credits < amount) return false;
    this.addCredits(userId, -amount, 'scan_debit');
    return true;
  }

  getTransactions(userId: string): CreditTransaction[] {
    return this.data.transactions.filter(t => t.userId === userId);
  }

  // --- Scans ---
  listScans(userId: string): Scan[] {
    return Object.values(this.data.scans)
      .filter(s => s.userId === userId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  getScan(id: string): Scan | undefined {
    return this.data.scans[id];
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
    this.data.scans[id] = scan;
    this.save();
    return scan;
  }

  updateScan(id: string, updates: Partial<Scan>): Scan {
    const scan = this.data.scans[id];
    if (!scan) throw new Error('Scan not found');
    this.data.scans[id] = { ...scan, ...updates };
    this.save();
    return this.data.scans[id];
  }

  // --- API Keys ---
  listApiKeys(userId: string): ApiKey[] {
    return Object.values(this.data.apiKeys).filter(k => k.userId === userId);
  }

  findApiKey(keyStr: string): ApiKey | null {
    return this.data.apiKeys[keyStr] || null;
  }

  generateApiKey(userId: string): ApiKey {
    const user = this.data.users[userId];
    if (!user) throw new Error('User not found');
    const id = 'key_' + crypto.randomBytes(8).toString('hex');
    const keyStr = 'sl_live_' + crypto.randomBytes(20).toString('hex');
    const keyObj: ApiKey = {
      id,
      userId,
      key: keyStr,
      credits: user.credits,
      active: true,
      createdAt: new Date().toISOString(),
    };
    this.data.apiKeys[keyStr] = keyObj;
    this.save();
    return keyObj;
  }

  revokeApiKey(userId: string, keyId: string): boolean {
    const keyObj = Object.values(this.data.apiKeys).find(k => k.id === keyId && k.userId === userId);
    if (!keyObj) return false;
    keyObj.active = false;
    this.save();
    return true;
  }

  validateApiKeyAndDeduct(apiKeyString: string, quantity: number = 1): User | null {
    const keyObj = this.data.apiKeys[apiKeyString];
    if (!keyObj || !keyObj.active) return null;
    const user = this.data.users[keyObj.userId];
    if (!user || user.credits < quantity) return null;
    this.addCredits(user.id, -quantity, 'scan_debit');
    return this.toPublicUser(user);
  }

  // --- Suppression Rules ---
  listSuppressions(userId: string): SuppressionRule[] {
    return this.data.suppressions.filter(s => s.userId === userId);
  }

  addSuppression(userId: string, targetUrl: string, findingTitle: string, reason: string): SuppressionRule {
    const id = 'supp_' + crypto.randomBytes(8).toString('hex');
    const rule: SuppressionRule = { id, userId, targetUrl, findingTitle, reason, createdAt: new Date().toISOString() };
    this.data.suppressions.push(rule);

    Object.values(this.data.scans).forEach(scan => {
      if (scan.userId === userId && cleanUrl(scan.url) === cleanUrl(targetUrl)) {
        let dirty = false;
        if (scan.findings) {
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
          }
        }
      }
    });

    this.save();
    return rule;
  }

  removeSuppression(userId: string, ruleId: string): boolean {
    const ruleToRemove = this.data.suppressions.find(r => r.id === ruleId && r.userId === userId);
    if (!ruleToRemove) return false;

    this.data.suppressions = this.data.suppressions.filter(r => !(r.id === ruleId && r.userId === userId));

    Object.values(this.data.scans).forEach(scan => {
      if (scan.userId === userId && cleanUrl(scan.url) === cleanUrl(ruleToRemove.targetUrl)) {
        let dirty = false;
        if (scan.findings) {
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
          }
        }
      }
    });

    this.save();
    return true;
  }

  // --- Monitored Targets ---
  listMonitoredTargets(userId: string): MonitoredTarget[] {
    return this.data.monitoredTargets.filter(t => t.userId === userId);
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
    this.data.monitoredTargets.push(target);
    this.save();
    return target;
  }

  removeMonitoredTarget(userId: string, id: string): boolean {
    const before = this.data.monitoredTargets.length;
    this.data.monitoredTargets = this.data.monitoredTargets.filter(t => !(t.id === id && t.userId === userId));
    const removed = this.data.monitoredTargets.length !== before;
    if (removed) this.save();
    return removed;
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
      this.data.scans[scan.id] = scan;
      this.save();
    }

    return scan;
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
