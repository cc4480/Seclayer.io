import Database from 'better-sqlite3';
import crypto from 'crypto';
import { Scan, Finding } from '../../src/types.js';
import { rowToScan } from './mappers.js';
import { scoreFindings } from '../scoring.js';
import { cleanUrl } from './url.js';
import { listSuppressions } from './suppressions.js';

export function listScans(db: Database.Database, userId: string): Scan[] {
  const rows = db.prepare('SELECT * FROM scans WHERE userId = ? ORDER BY createdAt DESC').all(userId);
  return rows.map(r => rowToScan(r)!).filter(Boolean);
}

export function getScan(db: Database.Database, id: string): Scan | undefined {
  return rowToScan(db.prepare('SELECT * FROM scans WHERE id = ?').get(id));
}

export function createScan(db: Database.Database, userId: string, url: string, authHeader?: string): Scan {
  const id = 'scan_' + crypto.randomBytes(8).toString('hex');
  const now = new Date().toISOString();
  db.prepare('INSERT INTO scans (id, userId, url, authHeader, status, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, userId, url, authHeader ?? null, 'queued', now);
  return getScan(db, id)!;
}

export function updateScan(db: Database.Database, id: string, updates: Partial<Scan>): Scan {
  const existing = getScan(db, id);
  if (!existing) throw new Error('Scan not found');
  const merged = { ...existing, ...updates };
  db.prepare(`
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
  return getScan(db, id)!;
}

// Read-model: returns a scan with suppression rules applied and the score
// recalculated. This is a PURE transform — it never writes to the database,
// so reads have no side effects.
export function getScanWithSuppressedFindings(db: Database.Database, scan: Scan): Scan {
  if (!scan || !scan.findings) return scan;
  const rules = listSuppressions(db, scan.userId);
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
