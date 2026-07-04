import Database from 'better-sqlite3';
import crypto from 'crypto';
import { MonitoredTarget } from '../../src/types.js';

export function listMonitoredTargets(db: Database.Database, userId: string): MonitoredTarget[] {
  return db.prepare('SELECT * FROM monitored_targets WHERE userId = ?').all(userId) as MonitoredTarget[];
}

export function addMonitoredTarget(
  db: Database.Database,
  userId: string,
  url: string,
  frequencyDays: number,
  scheduleString?: string,
): MonitoredTarget {
  const id = 'mon_' + crypto.randomBytes(8).toString('hex');
  const now = new Date().toISOString();
  const nextScanAt = new Date(Date.now() + frequencyDays * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO monitored_targets (id, userId, url, frequencyDays, scheduleString, nextScanAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, userId, url, frequencyDays, scheduleString ?? null, nextScanAt, now);
  return db.prepare('SELECT * FROM monitored_targets WHERE id = ?').get(id) as MonitoredTarget;
}

export function removeMonitoredTarget(db: Database.Database, userId: string, id: string): boolean {
  const res = db.prepare('DELETE FROM monitored_targets WHERE id = ? AND userId = ?').run(id, userId);
  return res.changes > 0;
}

// Targets whose next scheduled scan is due (used by the monitoring worker).
export function listDueMonitoredTargets(db: Database.Database, nowIso: string): MonitoredTarget[] {
  return db.prepare(
    'SELECT * FROM monitored_targets WHERE nextScanAt IS NOT NULL AND nextScanAt <= ?'
  ).all(nowIso) as MonitoredTarget[];
}

export function markMonitoredScanned(db: Database.Database, id: string, lastScannedAt: string, nextScanAt: string): void {
  db.prepare('UPDATE monitored_targets SET lastScannedAt = ?, nextScanAt = ? WHERE id = ?')
    .run(lastScannedAt, nextScanAt, id);
}
