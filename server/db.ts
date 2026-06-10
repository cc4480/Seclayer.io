import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { User, Scan, CreditTransaction, ApiKey, Finding, Severity, SuppressionRule, MonitoredTarget } from '../src/types.js';
import { config } from './config.js';
import { logger } from './logger.js';
import { INITIAL_DEMO_SCANS } from './seed-data.js';

const DB_FILE = path.isAbsolute(config.dbFile)
  ? config.dbFile
  : path.join(process.cwd(), config.dbFile);

interface DbSchema {
  users: Record<string, User>;
  scans: Record<string, Scan>;
  transactions: CreditTransaction[];
  apiKeys: Record<string, ApiKey>;
  suppressions?: SuppressionRule[];
  monitoredTargets?: MonitoredTarget[];
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
      monitoredTargets: []
    };
    this.load();
  }

  private load() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const fileContent = fs.readFileSync(DB_FILE, 'utf8');
        this.data = JSON.parse(fileContent);
        if (!this.data.suppressions) {
          this.data.suppressions = [];
        }
        if (!this.data.monitoredTargets) {
          this.data.monitoredTargets = [];
        }
      } else {
        // Seed default user and default data
        const defaultUser: User = {
          id: 'user_default',
          email: 'c.c4480131515@gmail.com',
          credits: 10,
          apiKey: 'sl_live_' + crypto.randomBytes(16).toString('hex'),
          createdAt: new Date().toISOString()
        };
        
        this.data.users[defaultUser.id] = defaultUser;
        this.data.scans = { ...INITIAL_DEMO_SCANS };
        
        // Seed default transactions
        this.data.transactions.push({
          id: 'tx-seed',
          userId: 'user_default',
          amount: 10,
          type: 'purchase',
          stripeSessionId: 'cs_test_initial_provision',
          createdAt: new Date().toISOString()
        });

        // Seed API key matching the user's default key
        this.data.apiKeys[defaultUser.apiKey] = {
          id: 'key-default',
          userId: 'user_default',
          key: defaultUser.apiKey,
          credits: 10,
          active: true,
          createdAt: new Date().toISOString()
        };

        this.save();
      }
    } catch (err) {
      logger.error('Failed to load datastore; starting from in-memory defaults.', { err, dbFile: DB_FILE });
    }
  }

  private save() {
    // Atomic write: serialize to a temp file then rename so a crash mid-write
    // cannot leave a truncated / corrupt db.json behind.
    const tmpFile = `${DB_FILE}.${process.pid}.tmp`;
    try {
      fs.writeFileSync(tmpFile, JSON.stringify(this.data, null, 2), 'utf8');
      fs.renameSync(tmpFile, DB_FILE);
    } catch (err) {
      logger.error('Failed to persist datastore.', { err, dbFile: DB_FILE });
      try {
        if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
      } catch {
        /* best-effort cleanup */
      }
    }
  }

  /** Readiness probe: confirm the datastore directory is writable. */
  isHealthy(): boolean {
    try {
      const dir = path.dirname(DB_FILE);
      fs.accessSync(dir, fs.constants.W_OK);
      return true;
    } catch {
      return false;
    }
  }

  // --- Users ---
  getUser(id: string): User | undefined {
    return this.data.users[id];
  }

  getOrCreateUser(email: string): User {
    const normEmail = email.toLowerCase().trim();
    let user = Object.values(this.data.users).find(u => u.email.toLowerCase() === normEmail);
    if (!user) {
      const id = 'user_' + crypto.randomBytes(6).toString('hex');
      const apiKey = 'sl_live_' + crypto.randomBytes(16).toString('hex');
      user = {
        id,
        email: normEmail,
        credits: 5, // 5 signup credits
        apiKey,
        createdAt: new Date().toISOString()
      };
      this.data.users[id] = user;
      
      // Seed initial credit transaction
      this.data.transactions.push({
        id: 'tx-signup-' + id,
        userId: id,
        amount: 5,
        type: 'purchase',
        createdAt: new Date().toISOString()
      });

      // Create matching API key record
      this.data.apiKeys[apiKey] = {
        id: 'key-' + id,
        userId: id,
        key: apiKey,
        credits: 5,
        active: true,
        createdAt: new Date().toISOString()
      };

      this.save();
    }
    return user;
  }

  // --- Credits ---
  addCredits(userId: string, amount: number, type: 'purchase' | 'scan_debit', stripeSessionId?: string): User {
    const user = this.data.users[userId];
    if (!user) throw new Error('User not found');
    user.credits = Math.max(0, user.credits + amount);
    
    // Also mirror credits on API key active entries
    Object.values(this.data.apiKeys).forEach(k => {
      if (k.userId === userId && k.active) {
        k.credits = user.credits;
      }
    });

    const tx: CreditTransaction = {
      id: 'tx_' + crypto.randomBytes(8).toString('hex'),
      userId,
      amount,
      type,
      stripeSessionId,
      createdAt: new Date().toISOString()
    };
    this.data.transactions.push(tx);
    this.save();
    return user;
  }

  deductCredits(userId: string, amount: number): boolean {
    const user = this.data.users[userId];
    if (!user || user.credits < amount) return false;
    this.addCredits(userId, -amount, 'scan_debit');
    return true;
  }

  // --- Transactions ---
  listTransactions(userId: string): CreditTransaction[] {    return this.data.transactions
      .filter((tx) => tx.userId === userId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
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
    const id = 'scan_' + crypto.randomBytes(8).toString('hex');
    const scan: Scan = {
      id,
      userId,
      url,
      authHeader,
      status: 'queued',
      createdAt: new Date().toISOString()
    };
    this.data.scans[id] = scan;
    this.save();
    return scan;
  }

  updateScan(id: string, updates: Partial<Scan>): Scan {
    const scan = this.data.scans[id];
    if (!scan) throw new Error('Scan not found');
    
    this.data.scans[id] = {
      ...scan,
      ...updates
    };
    this.save();
    return this.data.scans[id];
  }

  // --- API Keys ---
  listApiKeys(userId: string): ApiKey[] {
    return Object.values(this.data.apiKeys).filter(k => k.userId === userId);
  }

  generateApiKey(userId: string): ApiKey {
    const user = this.data.users[userId];
    if (!user) throw new Error('User not found');
    const id = 'key_' + crypto.randomBytes(8).toString('hex');
    const keyStr = 'sl_live_' + crypto.randomBytes(16).toString('hex');
    
    const keyObj: ApiKey = {
      id,
      userId,
      key: keyStr,
      credits: user.credits,
      active: true,
      createdAt: new Date().toISOString()
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

    // Deduct credit
    this.addCredits(user.id, -quantity, 'scan_debit');
    return user;
  }

  // --- Suppression Rules (False Positives Management) ---
  listSuppressions(userId: string): SuppressionRule[] {
    return (this.data.suppressions || []).filter(s => s.userId === userId);
  }

  addSuppression(userId: string, targetUrl: string, findingTitle: string, reason: string): SuppressionRule {
    const id = 'supp_' + crypto.randomBytes(8).toString('hex');
    const rule: SuppressionRule = {
      id,
      userId,
      targetUrl,
      findingTitle,
      reason,
      createdAt: new Date().toISOString()
    };
    if (!this.data.suppressions) {
      this.data.suppressions = [];
    }
    this.data.suppressions.push(rule);

    // Apply suppression retroactively to all existing scans for this user & URL
    Object.values(this.data.scans).forEach(scan => {
      if (scan.userId === userId && cleanUrl(scan.url) === cleanUrl(targetUrl)) {
        let dirty = false;
        if (scan.findings) {
          scan.findings = scan.findings.map(finding => {
            if (finding.title === findingTitle) {
              dirty = true;
              return {
                ...finding,
                isFalsePositive: true,
                suppressionReason: reason,
                suppressedAt: rule.createdAt
              };
            }
            return finding;
          });
          if (dirty) {
            const recalc = recalculateScore(scan.findings);
            scan.score = recalc.score;
            scan.severity = recalc.severity;
          }
        }
      }
    });

    this.save();
    return rule;
  }

  removeSuppression(userId: string, ruleId: string): boolean {
    if (!this.data.suppressions) return false;
    const initialLen = this.data.suppressions.length;
    const ruleToRemove = this.data.suppressions.find(r => r.id === ruleId && r.userId === userId);
    if (!ruleToRemove) return false;

    this.data.suppressions = this.data.suppressions.filter(r => !(r.id === ruleId && r.userId === userId));
    const finalLen = this.data.suppressions.length;

    if (initialLen !== finalLen) {
      // Un-suppress retroactively as well
      Object.values(this.data.scans).forEach(scan => {
        if (scan.userId === userId && cleanUrl(scan.url) === cleanUrl(ruleToRemove.targetUrl)) {
          let dirty = false;
          if (scan.findings) {
            scan.findings = scan.findings.map(finding => {
              if (finding.title === ruleToRemove.findingTitle) {
                dirty = true;
                const updated = { ...finding };
                delete updated.isFalsePositive;
                delete updated.suppressionReason;
                delete updated.suppressedAt;
                return updated;
              }
              return finding;
            });
            if (dirty) {
              const recalc = recalculateScore(scan.findings);
              scan.score = recalc.score;
              scan.severity = recalc.severity;
            }
          }
        }
      });
      this.save();
      return true;
    }
    return false;
  }

  getScanWithSuppressedFindings(scan: Scan): Scan {
    if (!scan || !scan.findings) return scan;
    const userRules = this.listSuppressions(scan.userId);
    const scanUrlClean = cleanUrl(scan.url);

    let dirty = false;
    const updatedFindings = scan.findings.map(finding => {
      const matchingRule = userRules.find(r =>
        cleanUrl(r.targetUrl) === scanUrlClean &&
        r.findingTitle === finding.title
      );
      if (matchingRule) {
        if (!finding.isFalsePositive) {
          dirty = true;
          return {
            ...finding,
            isFalsePositive: true,
            suppressionReason: matchingRule.reason,
            suppressedAt: matchingRule.createdAt
          };
        }
      } else {
        if (finding.isFalsePositive) {
          dirty = true;
          const cloned = { ...finding };
          delete cloned.isFalsePositive;
          delete cloned.suppressionReason;
          delete cloned.suppressedAt;
          return cloned;
        }
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

  // --- Monitored Targets ---
  listMonitoredTargets(userId: string): MonitoredTarget[] {
    return (this.data.monitoredTargets || []).filter(t => t.userId === userId);
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
      nextScanAt: new Date(Date.now() + frequencyDays * 24 * 60 * 60 * 1000).toISOString()
    };
    if (!this.data.monitoredTargets) {
      this.data.monitoredTargets = [];
    }
    this.data.monitoredTargets.push(target);
    this.save();
    return target;
  }

  removeMonitoredTarget(userId: string, id: string): boolean {
    if (!this.data.monitoredTargets) return false;
    const initialLen = this.data.monitoredTargets.length;
    this.data.monitoredTargets = this.data.monitoredTargets.filter(t => !(t.id === id && t.userId === userId));
    const removed = this.data.monitoredTargets.length !== initialLen;
    if (removed) this.save();
    return removed;
  }
}

// Helpers
export function cleanUrl(urlStr: string): string {
  try {
    let clean = urlStr.replace(/https?:\/\//i, '').replace(/\/+$/, '').trim();
    return clean.toLowerCase();
  } catch {
    return String(urlStr || '').trim().toLowerCase();
  }
}

export function recalculateScore(findings: Finding[]): { score: number; severity: Severity } {
  let score = 100;
  const activeFindings = findings.filter(f => !f.isFalsePositive);

  activeFindings.forEach(f => {
    const sev = f.severity?.toLowerCase();
    if (sev === 'critical') {
      score -= 35;
    } else if (sev === 'high') {
      score -= 25;
    } else if (sev === 'medium') {
      score -= 15;
    } else if (sev === 'low') {
      score -= 5;
    }
  });

  score = Math.max(12, Math.min(100, score));

  let severity: Severity = 'low';
  if (activeFindings.some(f => f.severity === 'critical')) severity = 'critical';
  else if (activeFindings.some(f => f.severity === 'high')) severity = 'high';
  else if (activeFindings.some(f => f.severity === 'medium')) severity = 'medium';
  else if (activeFindings.some(f => f.severity === 'low')) severity = 'low';

  return { score, severity };
}

export const db = new LocalFileDb();
