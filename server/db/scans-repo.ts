import crypto from 'crypto';
import Database from 'better-sqlite3';
import { Scan, Finding } from '../../src/types.js';

export class ScansRepo {
  constructor(private db: Database.Database) {}

  rowToScan(row: any): Scan {
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

  writeScan(scan: Scan) {
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

  getAllForUser(userId: string): Scan[] {
    return this.db.prepare('SELECT * FROM scans WHERE userId = ?').all(userId).map(r => this.rowToScan(r));
  }
}
