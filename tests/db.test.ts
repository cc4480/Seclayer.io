import { test } from 'node:test';
import assert from 'node:assert/strict';
import { db } from '../server/db.ts';

// Each test provisions its own user so the file-backed singleton stays isolated.
function freshUser() {
  const email = `db-test-${Math.random().toString(36).slice(2)}@example.test`;
  return db.getOrCreateUser(email);
}

test('getOrCreateUser is idempotent and grants signup credits', () => {
  const email = `idem-${Math.random().toString(36).slice(2)}@example.test`;
  const first = db.getOrCreateUser(email);
  const second = db.getOrCreateUser(email);
  assert.equal(first.id, second.id);
  assert.equal(first.credits, 5);
});

test('addCredits and deductCredits adjust the balance and record transactions', () => {
  const user = freshUser();
  db.addCredits(user.id, 10, 'purchase', 'cs_test_db');
  assert.equal(db.getUser(user.id)!.credits, 15);

  const ok = db.deductCredits(user.id, 4);
  assert.equal(ok, true);
  assert.equal(db.getUser(user.id)!.credits, 11);

  // Deducting more than the balance is rejected and leaves credits untouched.
  assert.equal(db.deductCredits(user.id, 999), false);
  assert.equal(db.getUser(user.id)!.credits, 11);

  const txns = db.listTransactions(user.id);
  assert.ok(txns.some((t) => t.type === 'purchase' && t.amount === 10));
  assert.ok(txns.some((t) => t.type === 'scan_debit' && t.amount === -4));
});

test('API key lifecycle: generate, validate-and-deduct, then revoke', () => {
  const user = freshUser();
  const key = db.generateApiKey(user.id);
  assert.ok(db.listApiKeys(user.id).some((k) => k.id === key.id));

  const validated = db.validateApiKeyAndDeduct(key.key, 1);
  assert.ok(validated);
  assert.equal(validated!.id, user.id);
  assert.equal(db.getUser(user.id)!.credits, 4);

  assert.equal(db.revokeApiKey(user.id, key.id), true);
  // A revoked key no longer validates.
  assert.equal(db.validateApiKeyAndDeduct(key.key, 1), null);
});

test('suppression rules round-trip and retroactively flag matching findings', () => {
  const user = freshUser();
  const scan = db.createScan(user.id, 'https://supp.example.test');
  db.updateScan(scan.id, {
    status: 'complete',
    findings: [
      { id: 'a', title: 'Missing CSP', description: 'd', severity: 'high', fix: 'f', category: 'DAST' },
    ],
  });

  const rule = db.addSuppression(user.id, 'https://supp.example.test', 'Missing CSP', 'accepted risk');
  assert.ok(db.listSuppressions(user.id).some((r) => r.id === rule.id));

  const suppressed = db.getScan(scan.id)!;
  assert.equal(suppressed.findings![0].isFalsePositive, true);

  assert.equal(db.removeSuppression(user.id, rule.id), true);
  assert.equal(db.getScan(scan.id)!.findings![0].isFalsePositive, undefined);
  // Removing a non-existent rule reports failure.
  assert.equal(db.removeSuppression(user.id, 'supp_missing'), false);
});

test('monitored targets can be added and removed', () => {
  const user = freshUser();
  const target = db.addMonitoredTarget(user.id, 'https://mon.example.test', 7, 'Every Monday at 09:00');
  assert.ok(db.listMonitoredTargets(user.id).some((t) => t.id === target.id));
  assert.ok(target.nextScanAt);

  assert.equal(db.removeMonitoredTarget(user.id, target.id), true);
  assert.equal(db.listMonitoredTargets(user.id).some((t) => t.id === target.id), false);
  assert.equal(db.removeMonitoredTarget(user.id, 'mon_missing'), false);
});
