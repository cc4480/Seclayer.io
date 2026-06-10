import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cleanUrl, recalculateScore } from '../server/db.ts';
import type { Finding } from '../src/types.ts';

function finding(severity: Finding['severity'], extra: Partial<Finding> = {}): Finding {
  return {
    id: Math.random().toString(36).slice(2),
    title: 't',
    description: 'd',
    severity,
    fix: 'f',
    category: 'DAST',
    ...extra,
  };
}

test('cleanUrl normalizes scheme, trailing slashes and case', () => {
  assert.equal(cleanUrl('https://Seclayer.IO/'), 'seclayer.io');
  assert.equal(cleanUrl('http://example.test///'), 'example.test');
  assert.equal(cleanUrl('EXAMPLE.test'), 'example.test');
});

test('recalculateScore deducts by severity and reports the highest', () => {
  const { score, severity } = recalculateScore([finding('critical'), finding('low')]);
  assert.equal(score, 100 - 35 - 5);
  assert.equal(severity, 'critical');
});

test('recalculateScore ignores suppressed false positives', () => {
  const { score, severity } = recalculateScore([
    finding('critical', { isFalsePositive: true }),
    finding('medium'),
  ]);
  assert.equal(score, 100 - 15);
  assert.equal(severity, 'medium');
});

test('recalculateScore never drops below the 12 floor', () => {
  const many = Array.from({ length: 20 }, () => finding('critical'));
  const { score } = recalculateScore(many);
  assert.equal(score, 12);
});
