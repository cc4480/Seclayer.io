import { db } from './db.js';
import { config } from './config.js';
import { logger } from './logger.js';
import { processScanJob } from './scan-worker.js';

/**
 * Bounded scan-job queue.
 *
 * Every `POST /api/scans` (and every due monitored target) used to fire a job
 * immediately, so a burst of submissions meant unbounded concurrent scans —
 * each opening many sockets and running the AI call — which can exhaust CPU,
 * memory, and file descriptors. This queue caps concurrency and enforces a hard
 * per-job timeout so a single pathological target can't run forever.
 */
class ScanQueue {
  private active = 0;
  private readonly waiting: string[] = [];

  constructor(
    private readonly maxConcurrent: number,
    private readonly timeoutMs: number,
    private readonly run: (scanId: string) => Promise<void> = processScanJob,
  ) {}

  /** Schedule a scan job; it runs immediately if a slot is free, else it queues. */
  enqueue(scanId: string): void {
    this.waiting.push(scanId);
    this.pump();
  }

  get stats(): { active: number; queued: number; maxConcurrent: number } {
    return { active: this.active, queued: this.waiting.length, maxConcurrent: this.maxConcurrent };
  }

  private pump(): void {
    while (this.active < this.maxConcurrent && this.waiting.length > 0) {
      const scanId = this.waiting.shift()!;
      this.active++;
      void this.execute(scanId).finally(() => {
        this.active--;
        this.pump();
      });
    }
  }

  private async execute(scanId: string): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<'timeout'>((resolve) => {
      timer = setTimeout(() => resolve('timeout'), this.timeoutMs);
    });
    try {
      const result = await Promise.race([this.run(scanId).then(() => 'done' as const), timeout]);
      if (result === 'timeout') {
        logger.error('scan job exceeded its time budget; marking failed', { scanId, timeoutMs: this.timeoutMs });
        this.failTimedOut(scanId);
      }
    } catch (err) {
      // processScanJob handles its own failures, but guard the queue regardless.
      logger.error('scan job threw outside its handler', { scanId, err });
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private failTimedOut(scanId: string): void {
    try {
      const scan = db.getScan(scanId);
      if (scan && scan.status !== 'complete' && scan.status !== 'failed') {
        db.updateScan(scanId, { status: 'failed', error: 'Scan exceeded the maximum allowed duration and was stopped.' });
      }
    } catch (err) {
      logger.error('failed to mark timed-out scan', { scanId, err });
    }
  }
}

export const scanQueue = new ScanQueue(config.scan.maxConcurrent, config.scan.timeoutMs);

export { ScanQueue };
