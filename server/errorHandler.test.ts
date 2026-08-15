import { test } from 'node:test';
import assert from 'node:assert/strict';
import { jsonErrorHandler } from './http/errorHandler.js';

function mockRes() {
  const res: any = {
    headersSent: false,
    statusCode: 0,
    body: null,
    status(c: number) { this.statusCode = c; return this; },
    json(b: any) { this.body = b; return this; },
  };
  return res;
}

test('malformed JSON body is a client error (400), not a server fault', () => {
  const res = mockRes();
  const err: any = new SyntaxError('Unexpected token'); err.body = '{bad}'; err.type = 'entity.parse.failed';
  jsonErrorHandler(err, {} as any, res, () => {});
  assert.equal(res.statusCode, 400);
  assert.match(res.body.message, /not valid JSON/i);
});

test('oversized body maps to 413', () => {
  const res = mockRes();
  jsonErrorHandler({ type: 'entity.too.large' }, {} as any, res, () => {});
  assert.equal(res.statusCode, 413);
});

test('a genuine server fault still returns 500 without leaking details', () => {
  const res = mockRes();
  jsonErrorHandler(new Error('db exploded: /secret/path'), {} as any, res, () => {});
  assert.equal(res.statusCode, 500);
  assert.doesNotMatch(res.body.message, /secret|exploded/i, 'must not leak internals');
});

test('delegates to next() when headers were already sent', () => {
  const res = mockRes(); res.headersSent = true;
  let delegated = false;
  jsonErrorHandler(new Error('late'), {} as any, res, () => { delegated = true; });
  assert.equal(delegated, true);
  assert.equal(res.statusCode, 0, 'must not attempt a second response');
});
