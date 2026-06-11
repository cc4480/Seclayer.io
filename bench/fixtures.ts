import http from 'http';

/**
 * Benchmark fixture targets.
 *
 * Two local HTTP servers with a known ground truth so the scanner's accuracy can
 * be measured reproducibly (no external dependency on DVWA/Juice Shop being
 * reachable):
 *
 *   - The VULNERABLE target exposes one genuine instance of each active-probe
 *     vulnerability, shaped to match exactly what the scanner sends.
 *   - The CLEAN target is a false-positive trap: it answers 200 for every path
 *     with the same shell (soft-404) and statically embeds every decoy string a
 *     naive scanner keys on ("SQL syntax", "uid=…", "__schema", "email", and a
 *     reflected — but HTML-encoded — parameter). A correct scanner reports zero
 *     active-probe findings here.
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

/** A target with exactly one genuine instance of each active-probe vulnerability. */
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
    // Homepage / search endpoint: reflects input and is injectable.
    if (path === '/' || path === '') {
      const search = q.get('q') || '';
      const id = q.get('id') || '';
      const ping = q.get('ping') || '';
      const url = q.get('url') || '';

      let body = '<html><head><title>Vuln Shop</title></head><body><h1>Vulnerable Demo Shop</h1>';
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
 * embeds every decoy a substring-based scanner would trip on. The correct
 * result is zero active-probe findings.
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

    // Every other path (including /.env, /admin, /api/v1/users/admin) returns the
    // same hardened HTML shell, with decoys embedded and any reflection encoded.
    const encoded = (q.get('q') || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const shell =
      '<html><head><title>Hardened App</title></head><body><div id="root">' +
      '<p>Welcome. Contact us by email for support.</p>' + // decoy: "email"
      '<!-- diagnostics: SQL syntax checker ok; uid=0(root) gid=0(root); schema __schema cached; Protocol mismatch guard active -->' + // decoys
      (encoded ? `<div>Search: ${encoded}</div>` : '') + // reflected but encoded (no XSS)
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
