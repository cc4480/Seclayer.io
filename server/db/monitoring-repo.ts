import crypto from 'crypto';
import Database from 'better-sqlite3';
import { MonitoredTarget } from '../../src/types.js';

export class MonitoringRepo {
  constructor(private db: Database.Database) {}

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
}
