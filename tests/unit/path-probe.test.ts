import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import { probeSensitivePaths } from '../../server/scanner/path-probe.js';

function listen(server: http.Server): Promise<number> {
  return new Promise(resolve =>
    server.listen(0, '127.0.0.1', () => resolve((server.address() as any).port)),
  );
}

// A genuinely vulnerable server: serves real sensitive resources, returns a
// proper 404 for anything it doesn't have.
const vuln = http.createServer((req, res) => {
  switch (req.url) {
    case '/.env':
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end('SECRET_KEY=abc123\nDB_PASSWORD=hunter2\n');
    case '/.git/config':
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end('[core]\n\trepositoryformatversion = 0\n');
    case '/actuator':
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{"_links":{"health":{"href":"/actuator/health"}}}');
    case '/swagger.json':
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{"openapi":"3.0.0","paths":{"/x":{}}}');
    case '/admin':
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end('<html><body>Admin Console</body></html>');
    default:
      res.writeHead(404);
      return res.end('Not Found');
  }
});

// A catch-all SPA: returns 200 + the same app shell for EVERY path, including
// /wp-admin, /actuator, /.env, etc. None of these are real exposures.
const SHELL =
  '<!doctype html><html><head><title>My App</title></head><body><div id="root"></div></body></html>';
const spa = http.createServer((_req, res) => {
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(SHELL);
});

let vulnPort = 0;
let spaPort = 0;

beforeAll(async () => {
  vulnPort = await listen(vuln);
  spaPort = await listen(spa);
});

afterAll(() => {
  vuln.close();
  spa.close();
});

describe('probeSensitivePaths', () => {
  it('detects genuinely exposed sensitive files (true positives preserved)', async () => {
    const results = await probeSensitivePaths(`http://127.0.0.1:${vulnPort}`);
    const exposed = results.filter(r => r.exposed).map(r => r.path);
    for (const p of ['/.env', '/.git/config', '/actuator', '/swagger.json', '/admin']) {
      expect(exposed).toContain(p);
    }
  });

  it('suppresses false positives on a catch-all 200 server', async () => {
    const results = await probeSensitivePaths(`http://127.0.0.1:${spaPort}`);
    const exposed = results.filter(r => r.exposed).map(r => r.path);
    expect(exposed).toEqual([]);
  });

  it('still records the real HTTP status for every probed path', async () => {
    const results = await probeSensitivePaths(`http://127.0.0.1:${vulnPort}`);
    const env = results.find(r => r.path === '/.env');
    const missing = results.find(r => r.path === '/phpinfo.php');
    expect(env?.status).toBe(200);
    expect(missing?.status).toBe(404);
    expect(missing?.exposed).toBe(false);
  });
});
