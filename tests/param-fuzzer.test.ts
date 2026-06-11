import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isReflectedXss, enumerateInjectionPoints, runParamFuzzing } from '../server/param-fuzzer.ts';
import type { CrawlResult } from '../server/crawler.ts';

test('isReflectedXss matches only an unencoded marker', () => {
  assert.equal(isReflectedXss('m', '<div><script>m</script></div>'), true);
  assert.equal(isReflectedXss('m', '<div>&lt;script&gt;m&lt;/script&gt;</div>'), false);
});

test('enumerateInjectionPoints collects query params and GET-form fields (deduped, GET-only)', () => {
  const crawl: CrawlResult = {
    pages: [
      { url: 'http://h.test/search?term=x', status: 200, contentType: 'text/html', html: '', depth: 1 },
      { url: 'http://h.test/search?term=y', status: 200, contentType: 'text/html', html: '', depth: 1 },
    ],
    forms: [
      { pageUrl: 'http://h.test/f', action: 'http://h.test/find', method: 'GET', fields: ['q'] },
      { pageUrl: 'http://h.test/g', action: 'http://h.test/save', method: 'POST', fields: ['comment'] },
    ],
    idRefs: [],
  };
  const points = enumerateInjectionPoints(crawl);
  const keys = points.map((p) => `${new URL(p.url).pathname}?${p.param}`).sort();
  // /search?term deduped to one; GET form field included; POST field excluded.
  assert.deepEqual(keys, ['/find?q', '/search?term']);
});

test('runParamFuzzing finds reflected XSS on a discovered parameter and validates it', async () => {
  const crawl: CrawlResult = {
    pages: [{ url: 'http://h.test/search?term=demo', status: 200, contentType: 'text/html', html: '', depth: 1 }],
    forms: [],
    idRefs: [],
  };
  const ff = async (url: string) => {
    const u = new URL(url);
    const term = u.searchParams.get('term') || '';
    return { status: 200, text: async () => `<div>Results for: ${term}</div>` }; // reflects unencoded
  };
  const { findings, exploits } = await runParamFuzzing(crawl, {}, ff as any);
  assert.equal(findings.length, 1);
  assert.match(findings[0].testName, /discovered parameter/i);
  assert.equal(findings[0].validated, true);
  assert.equal(exploits[0].validationStatus, 'validated');
});

test('runParamFuzzing does not fire when the parameter is output-encoded', async () => {
  const crawl: CrawlResult = {
    pages: [{ url: 'http://h.test/search?term=demo', status: 200, contentType: 'text/html', html: '', depth: 1 }],
    forms: [],
    idRefs: [],
  };
  const ff = async (url: string) => {
    const u = new URL(url);
    const term = (u.searchParams.get('term') || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return { status: 200, text: async () => `<div>Results for: ${term}</div>` }; // encoded
  };
  const { findings } = await runParamFuzzing(crawl, {}, ff as any);
  assert.equal(findings.length, 0);
});
