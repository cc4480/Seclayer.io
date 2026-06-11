import http from 'http';

/**
 * Benchmark fixture targets.
 *
 * Local HTTP servers with a known ground truth so the scanner's accuracy can be
 * measured reproducibly (no external dependency on DVWA/Juice Shop being
 * reachable):
 *
 *   - The VULNERABLE target exposes one genuine instance of each detectable
 *     vulnerability class, shaped to match exactly what the scanner sends.
 *   - The CLEAN target is a false-positive trap: it answers 200 for every path
 *     with the same shell (soft-404) and embeds every decoy a naive scanner
 *     keys on, including near-miss secrets and a *patched* library version.
 *   - The AUTHENTICATED target gates a finding behind a Bearer token, so a scan
 *     run with credentials surfaces a vulnerability an unauthenticated scan
 *     cannot reach.
 */

export interface BenchTarget {
  url: string;
  close: () => Promise<void>;
}

function normalizePath(rawUrl: string): string {
  const path = rawUrl.split('?')[0] || '/';
  return path.replace(/\/+/g, '/'); // collapse the scanner's "//" probe paths
}

function query(rawUrl: string): URLSearchParams {
  const i = rawUrl.indexOf('?');
  return new URLSearchParams(i >= 0 ? rawUrl.slice(i + 1) : '');
}

function listen(handler: http.RequestListener): Promise<BenchTarget> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}

// A well-known dummy AWS key shape (matches the scanner's AKIA[A-Z0-9]{16} rule).
const PLANTED_AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

/** A target with one genuine instance of each detectable vulnerability class. */
export function startVulnerableTarget(): Promise<BenchTarget> {
  return listen((req, res) => {
    const path = normalizePath(req.url || '/');
    const q = query(req.url || '');

    // GraphQL introspection exposed (real, parseable schema result).
    if (path === '/graphql' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: { __schema: { types: [{ name: 'Query' }, { name: 'User' }, { name: 'Order' }] } } }));
      return;
    }
    // BOLA: protected user object returned to an unauthenticated request.
    if (path === '/api/v1/users/admin') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id: 1, email: 'admin@vuln.test', role: 'admin', username: 'admin' }));
      return;
    }
    // Exposed .env with genuine key=value content.
    if (path === '/.env') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('NODE_ENV=production\nDB_PASSWORD=s3cr3t-prod-pw\nSTRIPE_SECRET_KEY=sk_live_abc123\nJWT_SECRET=hunter2hunter2\n');
      return;
    }
    // Exposed .git/config (real VCS metadata signature).
    if (path === '/.git/config') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:acme/shop.git\n');
      return;
    }
    // Exposed phpinfo() dump.
    if (path === '/phpinfo.php') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><head><title>phpinfo()</title></head><body><h1>PHP Version 7.4.3</h1><table><tr><td>System</td></tr></table>phpinfo()</body></html>');
      return;
    }
    // Homepage / search endpoint: reflects input, is injectable, leaks a secret,
    // loads an outdated library, and posts a form without a CSRF token.
    if (path === '/' || path === '') {
      const search = q.get('q') || '';
      const id = q.get('id') || '';
      const ping = q.get('ping') || '';
      const url = q.get('url') || '';

      let body = '<html><head><title>Vuln Shop</title>';
      body += '<script src="/static/jquery-1.12.4.min.js"></script></head><body>'; // SCA: outdated jQuery
      body += '<h1>Vulnerable Demo Shop</h1>';
      body += `<!-- deploy key aws_access_key_id=${PLANTED_AWS_KEY} -->`; // SAST: hardcoded secret
      if (search) body += `<div class="results">Results for: ${search}</div>`; // reflected XSS (unencoded)
      if (id.includes("'")) body += `<pre>SQL Error: You have an error in your SQL syntax near '${id}'</pre>`; // SQLi
      if (/;\s*id/.test(ping) || ping.includes('id')) body += '<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)</pre>'; // cmd injection
      if (url.includes('127.0.0.1:22')) body += '<pre>SSH-2.0-OpenSSH_8.9p1 Ubuntu</pre>'; // SSRF
      body += '<form method="post" action="/transfer"><input name="amount"><button>Send</button></form>'; // CSRF (no token)
      body += '</body></html>';

      // Verbose, version-leaking server headers; missing security headers.
      res.writeHead(200, { 'Content-Type': 'text/html', Server: 'Apache/2.4.49', 'X-Powered-By': 'PHP/7.4.3' });
      res.end(body);
      return;
    }
    // Everything else genuinely does not exist (clean soft-404 baseline).
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });
}

/**
 * A hardened target that returns the same shell for every path (soft-404) and
 * embeds every decoy a substring-based scanner would trip on, including a
 * near-miss secret, a *patched* library, and a CSRF-protected form. The correct
 * result is zero false positives across every check.
 */
export function startCleanTarget(): Promise<BenchTarget> {
  return listen((req, res) => {
    const path = normalizePath(req.url || '/');
    const q = query(req.url || '');

    // /graphql echoes the query in an error (contains "__schema" but is NOT a
    // valid introspection result) — the classic echoed-query false positive.
    if (path === '/graphql' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ errors: [{ message: 'Introspection is disabled for query {__schema{types{name}}}' }] }));
      return;
    }

    // Every other path returns the same hardened HTML shell with decoys embedded
    // and any reflection HTML-encoded.
    const encoded = (q.get('q') || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const shell =
      '<html><head><title>Hardened App</title>' +
      '<script src="/static/jquery-3.7.1.min.js"></script></head><body><div id="root">' + // patched lib (not vulnerable)
      '<p>Welcome. Contact us by email for support.</p>' + // decoy: "email"
      '<!-- diagnostics: SQL syntax checker ok; uid=0(root) gid=0(root); __schema cached; Protocol mismatch guard; [core] repositoryformatversion ok; key=AKIA_PLACEHOLDER_KEY -->' + // decoys + near-miss secret
      (encoded ? `<div>Search: ${encoded}</div>` : '') + // reflected but encoded (no XSS)
      '<form method="post" action="/profile"><input type="hidden" name="csrf_token" value="abc123"><input name="bio"><button>Save</button></form>' + // CSRF-protected form
      '</div></body></html>';

    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Content-Security-Policy': "default-src 'self'",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    res.end(shell);
  });
}

/**
 * A target whose BOLA endpoint is reachable only with a valid Bearer token, so
 * an authenticated scan surfaces a finding an unauthenticated scan cannot.
 */
export function startAuthenticatedTarget(token: string): Promise<BenchTarget> {
  return listen((req, res) => {
    const path = normalizePath(req.url || '/');
    const authed = (req.headers['authorization'] || '') === `Bearer ${token}`;

    if (path === '/api/v1/users/admin') {
      if (authed) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 1, email: 'admin@auth.test', role: 'admin', username: 'admin' }));
      } else {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
      }
      return;
    }
    if (path === '/' || path === '') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>Members Area</h1></body></html>');
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });
}
