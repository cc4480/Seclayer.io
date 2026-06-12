import { db } from './db.js';
import { config } from './config.js';
import { logger } from './logger.js';
import { scanQueue } from './scan-queue.js';

/**
 * Continuous-monitoring scheduler.
 *
 * Monitored targets carry a `nextScanAt`, but nothing executed them — the
 * feature was inert. This scheduler polls for due targets, enqueues a scan for
 * each (charging the owner a credit, like an interactive scan), and reschedules
 * the next run. It is interval-driven, unref'd so it never blocks shutdown, and
 * disabled under test.
 */

let timer: ReturnType<typeof setInterval> | undefined;

export async function runDueMonitoredScans(nowIso = new Date().toISOString()): Promise<number> {
  const due = db.listDueMonitoredTargets(nowIso);
  let dispatched = 0;
  for (const target of due) {
    try {
      const user = db.getUser(target.userId);
      if (!user) {
        // Orphaned monitor (owner gone): push the schedule forward, don't loop.
        db.recordMonitoredScan(target.id, target.lastScanId ?? '', target.frequencyDays);
        continue;
      }
      if (user.credits < 1) {
        logger.warn('skipping monitored scan: owner has no credits', { targetId: target.id, userId: target.userId });
        db.recordMonitoredScan(target.id, target.lastScanId ?? '', target.frequencyDays);
        continue;
      }
      db.deductCredits(target.userId, 1);
      const scan = db.createScan(target.userId, target.url);
      scanQueue.enqueue(scan.id);
      db.recordMonitoredScan(target.id, scan.id, target.frequencyDays);
      dispatched++;
      logger.info('dispatched scheduled monitored scan', { targetId: target.id, scanId: scan.id, url: target.url });
    } catch (err) {
      logger.error('failed to dispatch monitored scan', { targetId: target.id, err });
    }
  }
  return dispatched;
}

/** Start the polling scheduler. Returns a stop function. */
export function startMonitorScheduler(): () => void {
  if (!config.monitoring.enabled) {
    logger.info('monitoring scheduler disabled');
    return () => {};
  }
  timer = setInterval(() => {
    runDueMonitoredScans().catch((err) => logger.error('monitor scheduler tick failed', { err }));
  }, config.monitoring.pollIntervalMs);
  if (typeof timer.unref === 'function') timer.unref();
  logger.info('monitoring scheduler started', { pollIntervalMs: config.monitoring.pollIntervalMs });
  return stopMonitorScheduler;
}

export function stopMonitorScheduler(): void {
  if (timer) {
    clearInterval(timer);
    timer = undefined;
  }
}
