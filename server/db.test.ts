import { test } from 'node:test';
import assert from 'node:assert/strict';

// Use an isolated in-memory database. Set before importing the db singleton.
process.env.DB_PATH = ':memory:';
const { db } = await import('./db.js');

test('a new user receives signup credits and a matching API key', () => {
  const u = db.getOrCreateUser('t1@test.io');
  assert.equal(u.credits, 5);
  assert.equal(db.listApiKeys(u.id).length, 1);
  // getOrCreateUser is idempotent by email
  assert.equal(db.getOrCreateUser('T1@test.io').id, u.id);
});

test('deductCredits respects the balance', () => {
  const u = db.getOrCreateUser('t2@test.io');
  assert.equal(db.deductCredits(u.id, 99), false);
  assert.equal(db.deductCredits(u.id, 5), true);
  assert.equal(db.getUser(u.id)!.credits, 0);
});

test('a magic-link token is single-use and validates ownership', () => {
  const raw = db.createLoginToken('t3@test.io');
  assert.equal(db.consumeLoginToken(raw), 't3@test.io');
  assert.equal(db.consumeLoginToken(raw), null, 'token cannot be reused');
  assert.equal(db.consumeLoginToken('not-a-real-token'), null);
});

test('an expired magic-link token is rejected', () => {
  const raw = db.createLoginToken('t3b@test.io', -1); // already expired
  assert.equal(db.consumeLoginToken(raw), null);
});

test('sessions resolve to a user and can be revoked', () => {
  const u = db.getOrCreateUser('t4@test.io');
  const s = db.createSession(u.id);
  assert.equal(db.getSessionUserId(s), u.id);
  db.deleteSession(s);
  assert.equal(db.getSessionUserId(s), null);
});

test('suppression is a pure read-model: it recomputes the score without writing', () => {
  const u = db.getOrCreateUser('t5@test.io');
  const scan = db.createScan(u.id, 'https://acme.test');
  db.updateScan(scan.id, {
    status: 'complete', score: 75, severity: 'high',
    findings: [{ id: 'a', title: 'Missing CSP', description: '', severity: 'high', fix: '', category: 'IAST' }],
  });

  db.addSuppression(u.id, 'https://acme.test', 'Missing CSP', 'accepted risk');

  const view = db.getScanWithSuppressedFindings(db.getScan(scan.id)!);
  assert.equal(view.findings![0].isFalsePositive, true);
  assert.equal(view.score, 100, 'suppressing the only high returns the score to 100');

  // The stored row is untouched — reads must not mutate state.
  assert.equal(db.getScan(scan.id)!.score, 75);
  assert.equal(db.getScan(scan.id)!.findings![0].isFalsePositive, undefined);
});

test('scan ownership is queryable for authorization checks', () => {
  const a = db.getOrCreateUser('owner@test.io');
  const b = db.getOrCreateUser('other@test.io');
  const scan = db.createScan(a.id, 'https://owned.test');
  assert.equal(db.getScan(scan.id)!.userId, a.id);
  assert.notEqual(db.getScan(scan.id)!.userId, b.id);
});

test('Stripe webhook idempotency: a session is only credited once', () => {
  const u = db.getOrCreateUser('billing@test.io');
  const sessionId = 'cs_test_idem_1';
  assert.equal(db.hasTransactionForSession(sessionId), false);
  db.addCredits(u.id, 5, 'purchase', sessionId);
  assert.equal(db.hasTransactionForSession(sessionId), true); // retry would be skipped
});

test('monitoring scheduler surfaces only due targets', () => {
  const u = db.getOrCreateUser('monitor@test.io');
  const t = db.addMonitoredTarget(u.id, 'https://watch.test', 7);
  // Freshly added target is scheduled in the future -> not yet due.
  assert.equal(db.listDueMonitoredTargets(new Date().toISOString()).some((x) => x.id === t.id), false);
  // Backdate its next scan -> becomes due.
  db.markMonitoredScanned(t.id, new Date(Date.now() - 1000).toISOString(), new Date(Date.now() - 1000).toISOString());
  assert.equal(db.listDueMonitoredTargets(new Date().toISOString()).some((x) => x.id === t.id), true);
});
