#!/usr/bin/env node
// Post-build smoke test: boots the production bundle and asserts the app
// actually serves. Catches the class of regression where everything compiles
// but the server fails to start or the routes/static assets are misconfigured.
//
// Deliberately makes no outbound network calls, so it is deterministic in CI.

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PORT = process.env.SMOKE_PORT || '8181';
const BASE = `http://127.0.0.1:${PORT}`;
const dataDir = mkdtempSync(join(tmpdir(), 'seclayer-smoke-'));

let pass = 0, fail = 0;
const chk = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}`);
  ok ? pass++ : fail++;
};

const server = spawn(process.execPath, ['dist/server.cjs'], {
  env: {
    ...process.env,
    NODE_ENV: 'production',
    PORT,
    APP_URL: BASE,
    // Boot-time config validation requires an email provider in production.
    RESEND_API_KEY: 're_smoke_test_placeholder',
    DB_PATH: join(dataDir, 'smoke.sqlite'),
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let serverLog = '';
server.stdout.on('data', (d) => { serverLog += d; });
server.stderr.on('data', (d) => { serverLog += d; });

const cleanup = () => {
  server.kill('SIGTERM');
  try { rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
};

async function waitForBoot(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) return false;
    try {
      const r = await fetch(`${BASE}/api/system/health`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  return false;
}

const status = async (path, init) => (await fetch(`${BASE}${path}`, init)).status;

try {
  const booted = await waitForBoot();
  chk('production bundle boots and answers /api/system/health', booted);
  if (!booted) {
    console.error('\n--- server output ---\n' + serverLog);
    cleanup();
    process.exit(1);
  }

  chk('serves the SPA at /', (await status('/')) === 200);
  chk('serves SPA deep links (client routing)', (await status('/dashboard')) === 200);
  chk('unknown /api route returns JSON 404', (await status('/api/does-not-exist')) === 404);
  chk('protected route requires auth (401)', (await status('/api/auth/me')) === 401);

  const malformed = await status('/api/auth/request-link', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{not json}',
  });
  chk('malformed JSON body returns 400, not 500', malformed === 400, `got ${malformed}`);

  const headers = (await fetch(`${BASE}/api/system/health`)).headers;
  for (const h of ['x-frame-options', 'x-content-type-options', 'referrer-policy', 'strict-transport-security']) {
    chk(`security header ${h}`, headers.has(h));
  }

  const html = await (await fetch(`${BASE}/`)).text();
  const asset = html.match(/\/assets\/[^"']+\.js/)?.[0];
  chk('built JS asset is referenced', !!asset, asset || 'none found');
  if (asset) chk('built JS asset is served', (await status(asset)) === 200);
} finally {
  cleanup();
}

console.log(`\nSmoke: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
