import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  sameOriginUrl,
  extractLinks,
  extractForms,
  extractIdRefs,
  withId,
  crawl,
} from '../server/crawler.ts';

test('sameOriginUrl keeps same-origin links and rejects cross-origin', () => {
  assert.equal(sameOriginUrl('/a', 'http://h.test/x'), 'http://h.test/a');
  assert.equal(sameOriginUrl('page?id=2', 'http://h.test/dir/'), 'http://h.test/dir/page?id=2');
  assert.equal(sameOriginUrl('http://evil.test/a', 'http://h.test/'), null);
  assert.equal(sameOriginUrl('javascript:alert(1)', 'http://h.test/'), null);
});

test('extractLinks returns deduped same-origin anchors', () => {
  const html = '<a href="/a">A</a><a href="/a">dup</a><a href="http://evil.test/x">x</a><a href="/b#frag">B</a>';
  assert.deepEqual(extractLinks(html, 'http://h.test/').sort(), ['http://h.test/a', 'http://h.test/b']);
});

test('extractForms captures method, absolute action, and field names', () => {
  const html = '<form method="POST" action="/save"><input name="a"><textarea name="b"></textarea></form>';
  const forms = extractForms(html, 'http://h.test/page');
  assert.equal(forms.length, 1);
  assert.equal(forms[0].method, 'POST');
  assert.equal(forms[0].action, 'http://h.test/save');
  assert.deepEqual(forms[0].fields.sort(), ['a', 'b']);
});

test('extractIdRefs finds query and path object ids; withId rewrites them', () => {
  const q = extractIdRefs('http://h.test/acct?id=5');
  assert.equal(q.length, 1);
  assert.equal(q[0].kind, 'query');
  assert.equal(withId(q[0], 6), 'http://h.test/acct?id=6');

  const p = extractIdRefs('http://h.test/api/orders/7');
  assert.ok(p.some((r) => r.kind === 'path' && r.value === 7));
  const pathRef = p.find((r) => r.kind === 'path')!;
  assert.equal(withId(pathRef, 8), 'http://h.test/api/orders/8');
});

test('crawl performs a bounded same-origin BFS over an injected fetch', async () => {
  const pages: Record<string, { status: number; ct: string; body: string }> = {
    'http://h.test/': { status: 200, ct: 'text/html', body: '<a href="/list">List</a><a href="http://evil.test/">x</a>' },
    'http://h.test/list': {
      status: 200,
      ct: 'text/html',
      body: '<a href="/api/orders/1">order</a><form method="post" action="/comment"><input name="c"></form>',
    },
    'http://h.test/api/orders/1': { status: 200, ct: 'application/json', body: '{"id":1}' },
  };
  const fakeFetch = async (url: string) => {
    const p = pages[url] || { status: 404, ct: 'text/plain', body: 'nope' };
    return { status: p.status, headers: { get: () => p.ct }, text: async () => p.body };
  };

  const result = await crawl('http://h.test/', { fetchImpl: fakeFetch as any, maxPages: 5, maxDepth: 2 });
  const urls = result.pages.map((p) => p.url);
  assert.ok(urls.includes('http://h.test/list'));
  assert.ok(!urls.some((u) => u.includes('evil.test')));
  assert.ok(result.forms.some((f) => f.action === 'http://h.test/comment'));
  assert.ok(result.idRefs.some((r) => r.value === 1));
});
