import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  fingerprintBody,
  signature,
  buildBaseline,
  matchesAnyBaseline,
  looksLikeEnvFile,
  looksLikeGitConfig,
  looksLikePhpInfo,
  isPathGenuinelyExposed,
  isGraphqlIntrospection,
  isUserObjectLeak,
  isSqlInjectionEvidence,
  isCommandInjectionEvidence,
  isSsrfEvidence,
} from '../server/scan-calibration.ts';

const SPA_SHELL = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script src="/assets/index-abc12345.js"></script></body></html>';

test('fingerprintBody ignores volatile digits and hex tokens', () => {
  const a = '<html>build 20260101 token=deadbeefcafe1234</html>';
  const b = '<html>build 20991231 token=0011223344556677</html>';
  assert.equal(fingerprintBody(a), fingerprintBody(b));
});

test('matchesAnyBaseline treats the SPA shell / soft-404 as not-found', () => {
  const baseline = buildBaseline(signature(200, SPA_SHELL), signature(200, SPA_SHELL.replace('index-abc12345', 'index-99887766')));
  // A probe that returns the same shell is a soft match.
  assert.equal(matchesAnyBaseline(signature(200, SPA_SHELL), baseline), true);
  // A genuinely different page is not.
  assert.equal(matchesAnyBaseline(signature(200, 'DB_PASSWORD=hunter2\nAPI_KEY=abc'.repeat(5)), baseline), false);
});

test('isPathGenuinelyExposed rejects soft-404 200s and requires real artifacts', () => {
  const baseline = buildBaseline(signature(200, SPA_SHELL));

  // SPA shell served for /admin -> NOT exposed despite HTTP 200.
  assert.equal(isPathGenuinelyExposed('/admin', 200, SPA_SHELL, baseline), false);
  // 404 -> never exposed.
  assert.equal(isPathGenuinelyExposed('/.env', 404, 'Not Found', baseline), false);
  // A real .env body -> exposed.
  assert.equal(
    isPathGenuinelyExposed('/.env', 200, 'NODE_ENV=production\nDB_PASSWORD=s3cr3t\nSTRIPE_KEY=sk_live_x', baseline),
    true,
  );
  // /.env that actually returns the HTML shell -> NOT exposed.
  assert.equal(isPathGenuinelyExposed('/.env', 200, SPA_SHELL, baseline), false);
  // A distinct admin login page (not the shell) -> exposed.
  assert.equal(
    isPathGenuinelyExposed('/admin', 200, '<html><body><h1>Admin Login</h1><form method=post><input name=pw></form></body></html>', baseline),
    true,
  );
});

test('sensitive-file validators require real content', () => {
  assert.equal(looksLikeEnvFile('FOO=1\nBAR=2'), true);
  assert.equal(looksLikeEnvFile('<html>FOO=1 BAR=2</html>'), false);
  assert.equal(looksLikeGitConfig('[core]\n\trepositoryformatversion = 0'), true);
  assert.equal(looksLikeGitConfig('<html>git config</html>'), false);
  assert.equal(looksLikePhpInfo('<title>phpinfo()</title>'), true);
  assert.equal(looksLikePhpInfo('<html>welcome</html>'), false);
});

test('isGraphqlIntrospection ignores echoed queries, accepts real schema dumps', () => {
  // Server echoed the request (which itself contains "__schema") in an error.
  assert.equal(isGraphqlIntrospection('{"errors":[{"message":"Cannot query {__schema{types{name}}}"}]}'), false);
  // SPA shell.
  assert.equal(isGraphqlIntrospection(SPA_SHELL), false);
  // A genuine introspection response.
  assert.equal(isGraphqlIntrospection('{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"}]}}}'), true);
});

test('isUserObjectLeak requires a JSON user object, not HTML with the word email', () => {
  const baseline = buildBaseline(signature(200, SPA_SHELL));
  // HTML shell that merely contains the word "email".
  assert.equal(isUserObjectLeak('text/html', 200, '<html>contact: email us</html>', baseline), false);
  // Real JSON user object.
  assert.equal(isUserObjectLeak('application/json', 200, '{"id":1,"email":"a@b.com","role":"admin"}', baseline), true);
  // Right shape but non-200.
  assert.equal(isUserObjectLeak('application/json', 404, '{"id":1,"email":"a@b.com"}', baseline), false);
});

test('injection evidence requires a control-relative signal', () => {
  // SQL error present only in the injected response.
  assert.equal(isSqlInjectionEvidence('You have an error in your SQL syntax near', 'normal page'), true);
  // SQL error string present in BOTH (e.g. a static docs page) -> not evidence.
  assert.equal(isSqlInjectionEvidence('about SQL syntax', 'about SQL syntax'), false);

  // `id` command output only in injected response.
  assert.equal(isCommandInjectionEvidence('uid=33(www-data) gid=33(www-data) groups=33', 'pong'), true);
  // Literal "uid= gid=" text without the real pattern -> not evidence.
  assert.equal(isCommandInjectionEvidence('form fields: uid= and gid=', 'control'), false);

  // SSRF banner only in injected response.
  assert.equal(isSsrfEvidence('SSH-2.0-OpenSSH_8.9', 'home'), true);
  assert.equal(isSsrfEvidence('home', 'home'), false);
});
