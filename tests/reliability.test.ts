import { test } from 'node:test';
import assert from 'node:assert/strict';
import { db } from '../server/db.ts';
import { ScanQueue } from '../server/scan-queue.ts';

function freshUser() {
  return db.getOrCreateUser(`rel-${Math.random().toString(36).slice(2)}@example.test`);
}

test('failStuckScans recovers non-terminal scans left by a restart', () => {
  const user = freshUser();
  const queued = db.createScan(user.id, 'https://a.test');
  const scanning = db.createScan(user.id, 'https://b.test');
  db.updateScan(scanning.id, { status: 'scanning' });
  const done = db.createScan(user.id, 'https://c.test');
  db.updateScan(done.id, { status: 'complete', score: 90 });

  const recovered = db.failStuckScans();
  assert.ok(recovered >= 2);
  assert.equal(db.getScan(queued.id)!.status, 'failed');
  assert.equal(db.getScan(scanning.id)!.status, 'failed');
  assert.match(db.getScan(scanning.id)!.error || '', /restart/i);
  // Terminal scans are untouched.
  assert.equal(db.getScan(done.id)!.status, 'complete');
});

test('ScanQueue caps concurrency and drains the backlog', async () => {
  let active = 0;
  let peak = 0;
  const order: number[] = [];
  const run = (id: string) =>
    new Promise<void>((resolve) => {
      active++;
      peak = Math.max(peak, active);
      setTimeout(() => {
        active--;
        order.push(Number(id));
        resolve();
      }, 10);
    });

  const q = new ScanQueue(2, 1000, run);
  for (let i = 0; i < 6; i++) q.enqueue(String(i));
  assert.ok(q.stats.active <= 2);

  await new Promise((r) => setTimeout(r, 120));
  assert.ok(peak <= 2, `peak concurrency ${peak} exceeded the cap of 2`);
  assert.equal(order.length, 6);
  assert.equal(q.stats.active, 0);
  assert.equal(q.stats.queued, 0);
});

test('ScanQueue fails a job that exceeds its timeout', async () => {
  const user = freshUser();
  const scan = db.createScan(user.id, 'https://slow.test');
  db.updateScan(scan.id, { status: 'scanning' });

  // A job that never resolves within the (tiny) timeout.
  const run = () => new Promise<void>(() => {});
  const q = new ScanQueue(1, 20, run);
  q.enqueue(scan.id);

  await new Promise((r) => setTimeout(r, 80));
  const after = db.getScan(scan.id)!;
  assert.equal(after.status, 'failed');
  assert.match(after.error || '', /maximum allowed duration/i);
});

test('listDueMonitoredTargets and recordMonitoredScan drive the schedule', () => {
  const user = freshUser();
  const target = db.addMonitoredTarget(user.id, 'https://mon.test', 7);
  // Freshly added: next scan is a week out, so not due now.
  assert.equal(db.listDueMonitoredTargets(new Date().toISOString()).some((t) => t.id === target.id), false);

  // Force it due, then confirm it lists and reschedules.
  db.recordMonitoredScan(target.id, 'scan_x', 0); // nextScanAt = now
  const due = db.listDueMonitoredTargets(new Date(Date.now() + 1000).toISOString());
  assert.ok(due.some((t) => t.id === target.id));

  db.recordMonitoredScan(target.id, 'scan_y', 7);
  const t2 = db.listMonitoredTargets(user.id).find((t) => t.id === target.id)!;
  assert.equal(t2.lastScanId, 'scan_y');
  assert.ok(new Date(t2.nextScanAt!).getTime() > Date.now() + 6 * 24 * 3600 * 1000);
});
