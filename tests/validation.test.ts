import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isPrivateAddress,
  normalizeTargetUrl,
  validateEmail,
  requireString,
  optionalString,
  assertSafeScanTarget,
} from '../server/validation.ts';

test('isPrivateAddress flags loopback, RFC1918, link-local and CGNAT ranges', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.5', '172.16.9.9', '169.254.169.254', '100.64.0.1', '0.0.0.0']) {
    assert.equal(isPrivateAddress(ip), true, `${ip} should be private`);
  }
});

test('isPrivateAddress allows public addresses', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '104.22.4.12', '172.15.0.1', '172.32.0.1']) {
    assert.equal(isPrivateAddress(ip), false, `${ip} should be public`);
  }
});

test('isPrivateAddress handles IPv6 loopback, ULA, link-local and mapped v4', () => {
  assert.equal(isPrivateAddress('::1'), true);
  assert.equal(isPrivateAddress('fe80::1'), true);
  assert.equal(isPrivateAddress('fd00::1'), true);
  assert.equal(isPrivateAddress('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateAddress('2606:4700:4700::1111'), false);
});

test('normalizeTargetUrl adds https scheme and rejects junk', () => {
  assert.equal(normalizeTargetUrl('seclayer.io'), 'https://seclayer.io/');
  assert.equal(normalizeTargetUrl('http://x.test/a'), 'http://x.test/a');
  assert.throws(() => normalizeTargetUrl(''), /required/i);
  assert.throws(() => normalizeTargetUrl('ftp://x.test'), /http and https/i);
  assert.throws(() => normalizeTargetUrl('https://'), /malformed|hostname/i);
});

test('validateEmail normalizes and rejects malformed input', () => {
  assert.equal(validateEmail('  Foo@Bar.COM '), 'foo@bar.com');
  assert.throws(() => validateEmail('not-an-email'), /valid email/i);
  assert.throws(() => validateEmail(123), /valid email/i);
});

test('requireString / optionalString enforce presence and caps', () => {
  assert.equal(requireString('hi', 'field'), 'hi');
  assert.throws(() => requireString('', 'field'), /required/i);
  assert.throws(() => requireString('x'.repeat(10), 'field', 5), /maximum length/i);
  assert.equal(optionalString(undefined, 'field'), undefined);
  assert.equal(optionalString('keep', 'field'), 'keep');
});

test('assertSafeScanTarget blocks private IP literals and localhost (SSRF guard)', async () => {
  await assert.rejects(() => assertSafeScanTarget('http://127.0.0.1:22'), /private or reserved/i);
  await assert.rejects(() => assertSafeScanTarget('http://localhost:8080'), /internal\/loopback/i);
  await assert.rejects(() => assertSafeScanTarget('http://169.254.169.254/latest/meta-data'), /private or reserved/i);
});

test('assertSafeScanTarget allows public IP literals', async () => {
  assert.equal(await assertSafeScanTarget('https://8.8.8.8'), 'https://8.8.8.8/');
});
