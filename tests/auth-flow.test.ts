import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findLoginForm, parseSessionCookie, establishSession, withCookie } from '../server/auth-flow.ts';
import type { CrawlResult } from '../server/crawler.ts';

test('findLoginForm locates a POST form with username + password fields', () => {
  const crawl: CrawlResult = {
    pages: [],
    forms: [
      { pageUrl: 'http://h.test/login', action: 'http://h.test/login', method: 'POST', fields: ['username', 'password'] },
      { pageUrl: 'http://h.test/search', action: 'http://h.test/search', method: 'GET', fields: ['q'] },
    ],
    idRefs: [],
  };
  const lf = findLoginForm(crawl);
  assert.ok(lf);
  assert.equal(lf!.userField, 'username');
  assert.equal(lf!.passField, 'password');

  // No password field -> not a login form.
  assert.equal(findLoginForm({ pages: [], forms: [{ pageUrl: 'x', action: 'x', method: 'POST', fields: ['q'] }], idRefs: [] }), null);
});

test('parseSessionCookie extracts the first name=value pair, dropping attributes', () => {
  assert.equal(parseSessionCookie('session=valid; HttpOnly; Path=/'), 'session=valid');
  assert.equal(parseSessionCookie('a=1; Path=/, b=2; Path=/'), 'a=1');
  assert.equal(parseSessionCookie(null), null);
  assert.equal(parseSessionCookie('not-a-cookie'), null);
});

test('withCookie merges into existing Cookie header', () => {
  assert.deepEqual(withCookie({}, 'session=1'), { Cookie: 'session=1' });
  assert.deepEqual(withCookie({ Cookie: 'a=1' }, 'b=2'), { Cookie: 'a=1; b=2' });
});

test('establishSession posts credentials and returns the session cookie', async () => {
  const login = {
    form: { pageUrl: 'http://h.test/login', action: 'http://h.test/login', method: 'POST', fields: ['username', 'password'] },
    userField: 'username',
    passField: 'password',
  };
  let received = '';
  const ff = async (_url: string, init?: any) => {
    received = init.body;
    return {
      status: 200,
      headers: { get: (n: string) => (n.toLowerCase() === 'set-cookie' ? 'session=valid; HttpOnly' : null) },
      text: async () => 'ok',
    };
  };
  const cookie = await establishSession(login, { username: 'admin', password: 'pw' }, {}, ff as any);
  assert.equal(cookie, 'session=valid');
  assert.match(received, /username=admin/);
  assert.match(received, /password=pw/);

  // No cookie issued -> null.
  const ffNone = async () => ({ status: 401, headers: { get: () => null }, text: async () => 'no' });
  assert.equal(await establishSession(login, { username: 'x', password: 'y' }, {}, ffNone as any), null);
});
