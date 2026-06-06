import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { makeTempDb } from '../helpers.js';
import { hashPassword } from '../../server/auth.js';
import { recalculateScore, cleanUrl } from '../../server/db.js';
import type { LocalFileDb } from '../../server/db.js';

let db: LocalFileDb;
let cleanup: () => void;

beforeEach(() => {
  ({ db, cleanup } = makeTempDb());
});

afterEach(() => cleanup());

// ─── registerUser ────────────────────────────────────────────────────────────

describe('registerUser', () => {
  it('creates a user with expected fields', () => {
    const user = db.registerUser('alice@example.com', hashPassword('pass1234'));
    expect(user.id).toMatch(/^user_/);
    expect(user.email).toBe('alice@example.com');
    expect((user as any).passwordHash).toBeUndefined();
  });

  it('normalises email to lowercase', () => {
    const user = db.registerUser('ALICE@EXAMPLE.COM', hashPassword('pass1234'));
    expect(user.email).toBe('alice@example.com');
  });

  it('throws when the email is already registered', () => {
    db.registerUser('bob@example.com', hashPassword('pass1234'));
    expect(() => db.registerUser('bob@example.com', hashPassword('other'))).toThrow();
  });

  it('is case-insensitive for duplicate detection', () => {
    db.registerUser('Carol@example.com', hashPassword('pass1234'));
    expect(() => db.registerUser('carol@example.com', hashPassword('other'))).toThrow();
  });
});

// ─── findUserByEmail ─────────────────────────────────────────────────────────

describe('findUserByEmail', () => {
  it('finds a registered user', () => {
    db.registerUser('dave@example.com', hashPassword('pass1234'));
    const found = db.findUserByEmail('dave@example.com');
    expect(found).not.toBeNull();
    expect(found!.email).toBe('dave@example.com');
    expect(found!.passwordHash).toBeDefined();
  });

  it('returns null for an unknown email', () => {
    expect(db.findUserByEmail('nobody@example.com')).toBeNull();
  });
});

// ─── getUser ─────────────────────────────────────────────────────────────────

describe('getUser', () => {
  it('strips passwordHash from the returned object', () => {
    const created = db.registerUser('eve@example.com', hashPassword('pass1234'));
    const user = db.getUser(created.id);
    expect(user).toBeDefined();
    expect((user as any).passwordHash).toBeUndefined();
  });

  it('returns undefined for an unknown id', () => {
    expect(db.getUser('user_doesnotexist')).toBeUndefined();
  });
});

// ─── createScan / getScan / updateScan / listScans ───────────────────────────

describe('scan CRUD', () => {
  it('creates a scan in queued status', () => {
    const user = db.registerUser('frank@example.com', hashPassword('pass1234'));
    const scan = db.createScan(user.id, 'https://example.com');
    expect(scan.id).toMatch(/^scan_/);
    expect(scan.status).toBe('queued');
    expect(scan.url).toBe('https://example.com');
  });

  it('retrieves a scan by id', () => {
    const user = db.registerUser('grace@example.com', hashPassword('pass1234'));
    const scan = db.createScan(user.id, 'https://test.io');
    expect(db.getScan(scan.id)).toMatchObject({ id: scan.id });
  });

  it('updates scan fields', () => {
    const user = db.registerUser('helen@example.com', hashPassword('pass1234'));
    const scan = db.createScan(user.id, 'https://example.com');
    db.updateScan(scan.id, { status: 'complete', score: 72 });
    const updated = db.getScan(scan.id)!;
    expect(updated.status).toBe('complete');
    expect(updated.score).toBe(72);
  });

  it('lists scans for the correct user only', () => {
    const u1 = db.registerUser('user1@example.com', hashPassword('pass1234'));
    const u2 = db.registerUser('user2@example.com', hashPassword('pass1234'));
    db.createScan(u1.id, 'https://a.com');
    db.createScan(u1.id, 'https://b.com');
    db.createScan(u2.id, 'https://c.com');
    expect(db.listScans(u1.id)).toHaveLength(2);
    expect(db.listScans(u2.id)).toHaveLength(1);
  });
});

// ─── API Keys ────────────────────────────────────────────────────────────────

describe('API key management', () => {
  it('generates a key that can be found', () => {
    const user = db.registerUser('ivan@example.com', hashPassword('pass1234'));
    const key = db.generateApiKey(user.id);
    expect(key.key).toMatch(/^sl_live_/);
    expect(key.active).toBe(true);
    expect(db.findApiKey(key.key)).not.toBeNull();
  });

  it('revokes a key so findApiKey returns inactive', () => {
    const user = db.registerUser('jane@example.com', hashPassword('pass1234'));
    const key = db.generateApiKey(user.id);
    expect(db.revokeApiKey(user.id, key.id)).toBe(true);
    expect(db.findApiKey(key.key)!.active).toBe(false);
  });

  it('lists only keys belonging to the user', () => {
    const u1 = db.registerUser('u1@example.com', hashPassword('pass1234'));
    const u2 = db.registerUser('u2@example.com', hashPassword('pass1234'));
    db.generateApiKey(u1.id);
    db.generateApiKey(u1.id);
    db.generateApiKey(u2.id);
    expect(db.listApiKeys(u1.id)).toHaveLength(3); // 2 generated + 1 from signup
    expect(db.listApiKeys(u2.id)).toHaveLength(2); // 1 generated + 1 from signup
  });

  it('returns false when revoking a key from a different user', () => {
    const u1 = db.registerUser('u1b@example.com', hashPassword('pass1234'));
    const u2 = db.registerUser('u2b@example.com', hashPassword('pass1234'));
    const key = db.generateApiKey(u1.id);
    expect(db.revokeApiKey(u2.id, key.id)).toBe(false);
  });
});

// ─── Suppressions ────────────────────────────────────────────────────────────

describe('suppression rules', () => {
  it('adds and lists rules', () => {
    const user = db.registerUser('kim@example.com', hashPassword('pass1234'));
    const rule = db.addSuppression(user.id, 'https://example.com', 'Missing HSTS', 'Known config');
    expect(db.listSuppressions(user.id)).toHaveLength(1);
    expect(rule.findingTitle).toBe('Missing HSTS');
  });

  it('removes a rule by id', () => {
    const user = db.registerUser('lee@example.com', hashPassword('pass1234'));
    const rule = db.addSuppression(user.id, 'https://example.com', 'CSP Missing', 'FP');
    expect(db.removeSuppression(user.id, rule.id)).toBe(true);
    expect(db.listSuppressions(user.id)).toHaveLength(0);
  });

  it('returns false when removing a rule owned by another user', () => {
    const u1 = db.registerUser('u1s@example.com', hashPassword('pass1234'));
    const u2 = db.registerUser('u2s@example.com', hashPassword('pass1234'));
    const rule = db.addSuppression(u1.id, 'https://example.com', 'XSS', 'FP');
    expect(db.removeSuppression(u2.id, rule.id)).toBe(false);
  });
});

// ─── Monitored Targets ───────────────────────────────────────────────────────

describe('monitored targets', () => {
  it('adds and lists targets', () => {
    const user = db.registerUser('mike@example.com', hashPassword('pass1234'));
    const target = db.addMonitoredTarget(user.id, 'https://prod.example.com', 7);
    expect(db.listMonitoredTargets(user.id)).toHaveLength(1);
    expect(target.frequencyDays).toBe(7);
  });

  it('removes a target', () => {
    const user = db.registerUser('nina@example.com', hashPassword('pass1234'));
    const target = db.addMonitoredTarget(user.id, 'https://prod.example.com', 14);
    expect(db.removeMonitoredTarget(user.id, target.id)).toBe(true);
    expect(db.listMonitoredTargets(user.id)).toHaveLength(0);
  });
});

// ─── cleanUrl ────────────────────────────────────────────────────────────────

describe('cleanUrl', () => {
  it('strips protocol and trailing slashes', () => {
    expect(cleanUrl('https://example.com/')).toBe('example.com');
    expect(cleanUrl('http://example.com')).toBe('example.com');
  });

  it('lowercases the result', () => {
    expect(cleanUrl('https://EXAMPLE.COM')).toBe('example.com');
  });
});

// ─── recalculateScore ────────────────────────────────────────────────────────

describe('recalculateScore', () => {
  it('returns 100 with no active findings', () => {
    const { score, severity } = recalculateScore([]);
    expect(score).toBe(100);
    expect(severity).toBe('low');
  });

  it('deducts 35 for a critical finding', () => {
    const { score, severity } = recalculateScore([
      { id: 'f1', title: 'Test', description: '', severity: 'critical', fix: '', category: 'DAST' },
    ]);
    expect(score).toBe(65);
    expect(severity).toBe('critical');
  });

  it('floors score at 12', () => {
    const findings = Array.from({ length: 5 }, (_, i) => ({
      id: `f${i}`, title: 'RCE', description: '', severity: 'critical' as const, fix: '', category: 'DAST',
    }));
    const { score } = recalculateScore(findings);
    expect(score).toBe(12);
  });

  it('ignores false-positive findings', () => {
    const { score } = recalculateScore([
      { id: 'f1', title: 'Test', description: '', severity: 'critical', fix: '', category: 'DAST', isFalsePositive: true },
    ]);
    expect(score).toBe(100);
  });
});
