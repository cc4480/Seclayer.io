import crypto from 'crypto';
import Database from 'better-sqlite3';
import { Scan, SuppressionRule } from '../../src/types.js';
import { ScansRepo } from './scans-repo.js';
import { cleanUrl, recalculateScore } from './score-helpers.js';

export class SuppressionsRepo {
  constructor(private db: Database.Database, private scans: ScansRepo) {}

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
      const scansForUser = this.scans.getAllForUser(userId);
      const targetClean = cleanUrl(targetUrl);
      for (const scan of scansForUser) {
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
          this.scans.writeScan(scan);
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

      const scansForUser = this.scans.getAllForUser(userId);
      const targetClean = cleanUrl(ruleToRemove.targetUrl);
      for (const scan of scansForUser) {
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
          this.scans.writeScan(scan);
        }
      }
    });
    tx();

    return true;
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
      this.scans.writeScan(scan);
    }

    return scan;
  }
}
