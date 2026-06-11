import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isStoredReflection,
  objectish,
  isIdorEvidence,
  detectStoredXss,
  detectIdor,
} from '../server/chain-detectors.ts';
import type { CrawlResult } from '../server/crawler.ts';

test('isStoredReflection matches only an unencoded marker', () => {
  assert.equal(isStoredReflection('m1', '<p><script>m1</script></p>'), true);
  assert.equal(isStoredReflection('m1', '<p>&lt;script&gt;m1&lt;/script&gt;</p>'), false);
});

test('objectish distinguishes JSON objects from HTML/empty', () => {
  assert.equal(objectish('{"id":1,"name":"a"}'), true);
  assert.equal(objectish('[{"id":1}]'), true);
  assert.equal(objectish('<html>not json</html>'), false);
  assert.equal(objectish('{}'), false);
});

test('isIdorEvidence requires a distinct, readable neighbouring object', () => {
  const own = { status: 200, body: '{"id":1,"owner":"u1"}' };
  const sibling = { status: 200, body: '{"id":2,"owner":"u2"}' };
  const notFound = { status: 404, body: '{"error":"not found"}' };
  assert.equal(isIdorEvidence(own, sibling, notFound), true);

  // Forbidden neighbour (ownership enforced) -> not IDOR.
  assert.equal(isIdorEvidence(own, { status: 403, body: '{"error":"forbidden"}' }, notFound), false);
  // Neighbour identical to own -> not cross-object.
  assert.equal(isIdorEvidence(own, own, notFound), false);
  // Neighbour equals the not-found page -> not a real object.
  assert.equal(isIdorEvidence(own, notFound, notFound), false);
});

function fakeFetch(routes: Record<string, { status: number; body: string }>) {
  return async (url: string) => {
    const r = routes[url] || { status: 404, body: '{"error":"not found"}' };
    return { status: r.status, headers: { get: () => 'application/json' }, text: async () => r.body };
  };
}

test('detectStoredXss confirms a persisted, unencoded marker', async () => {
  const crawl: CrawlResult = {
    pages: [{ url: 'http://h.test/guestbook', status: 200, contentType: 'text/html', html: '', depth: 1 }],
    forms: [{ pageUrl: 'http://h.test/guestbook', action: 'http://h.test/guestbook', method: 'POST', fields: ['comment'] }],
    idRefs: [],
  };
  // The read of the guestbook echoes whatever marker the POST stored, unencoded.
  let stored = '';
  const ff = async (url: string, init?: any) => {
    if (init?.method === 'POST') {
      stored = decodeURIComponent((init.body as string).split('=')[1]);
      return { status: 200, headers: { get: () => 'text/html' }, text: async () => 'saved' };
    }
    return { status: 200, headers: { get: () => 'text/html' }, text: async () => `<div>${stored}</div>` };
  };

  const { findings, exploits } = await detectStoredXss(crawl, {}, ff as any);
  assert.equal(findings.length, 1);
  assert.match(findings[0].testName, /stored cross-site scripting/i);
  assert.equal(findings[0].validated, true);
  assert.equal(exploits[0].validationStatus, 'validated');
});

test('detectIdor confirms cross-object access and skips ownership-enforced endpoints', async () => {
  const crawl: CrawlResult = {
    pages: [],
    forms: [],
    idRefs: [{ url: 'http://h.test/api/orders/1', kind: 'path', key: '2', value: 1 }],
  };

  const vulnerable = fakeFetch({
    'http://h.test/api/orders/1': { status: 200, body: '{"id":1,"owner":"u1"}' },
    'http://h.test/api/orders/2': { status: 200, body: '{"id":2,"owner":"u2"}' },
    'http://h.test/api/orders/99992': { status: 404, body: '{"error":"nf"}' },
  });
  const vuln = await detectIdor(crawl, {}, vulnerable as any);
  assert.equal(vuln.findings.length, 1);
  assert.match(vuln.findings[0].testName, /insecure direct object reference/i);
  assert.equal(vuln.findings[0].validated, true);

  const hardened = fakeFetch({
    'http://h.test/api/orders/1': { status: 200, body: '{"id":1,"owner":"u1"}' },
    'http://h.test/api/orders/2': { status: 403, body: '{"error":"forbidden"}' },
    'http://h.test/api/orders/99992': { status: 403, body: '{"error":"forbidden"}' },
  });
  const safe = await detectIdor(crawl, {}, hardened as any);
  assert.equal(safe.findings.length, 0);
});
