import crypto from 'crypto';
import { Finding, Severity, CrawlResult, CrawlPage, CrawlForm } from '../src/types.js';

// Defense-in-depth: the scan endpoint already validates the target, but the
// crawler discovers new URLs at runtime, so re-check every host it follows.
const PRIVATE_IP_RE = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|0\.0\.0\.0)/i;

interface CrawlOptions {
  authHeader?: string;
  maxPages?: number;
  maxDepth?: number;
  concurrency?: number;
  budgetMs?: number;
  onLog?: (msg: string) => void;
  /** Test-only escape hatch to crawl loopback fixture servers. Never set in production. */
  allowPrivateHosts?: boolean;
}

const USER_AGENT = 'Seclayer-Security-Scanner/2.0 (seclayer.io; scanner@seclayer.io)';

function newId() {
  return `f_crawl_${crypto.randomBytes(4).toString('hex')}`;
}

/** Normalize a URL for dedup: drop fragment, sort nothing, keep path+search. */
function canonical(u: URL): string {
  return `${u.origin}${u.pathname}${u.search}`.replace(/\/$/, '') || u.origin;
}

/** Pull href/src targets and resolve them against the page URL. */
function extractLinks(html: string, base: URL): URL[] {
  const out: URL[] = [];
  const re = /(?:href|src)\s*=\s*["']([^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const raw = m[1].trim();
    if (!raw || raw.startsWith('javascript:') || raw.startsWith('mailto:') ||
        raw.startsWith('tel:') || raw.startsWith('data:')) continue;
    try {
      out.push(new URL(raw, base));
    } catch { /* skip malformed */ }
  }
  return out;
}

/** Collect external resource references (for mixed-content detection). */
function extractResources(html: string, base: URL): URL[] {
  const out: URL[] = [];
  const re = /<(?:script|img|iframe|link|source|audio|video)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    try { out.push(new URL(m[1], base)); } catch { /* skip */ }
  }
  return out;
}

function extractTitle(html: string): string | undefined {
  const m = /<title[^>]*>([^<]{0,200})<\/title>/i.exec(html);
  return m ? m[1].trim() : undefined;
}

/** Parse <form> blocks with their inputs from page HTML. */
function extractForms(html: string, pageUrl: URL): CrawlForm[] {
  const forms: CrawlForm[] = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm: RegExpExecArray | null;
  while ((fm = formRe.exec(html)) !== null) {
    const attrs = fm[1] || '';
    const body = fm[2] || '';
    const actionMatch = /\baction\s*=\s*["']([^"']*)["']/i.exec(attrs);
    const methodMatch = /\bmethod\s*=\s*["']([^"']*)["']/i.exec(attrs);
    let action = actionMatch ? actionMatch[1] : pageUrl.href;
    let resolvedAction: URL | null = null;
    try { resolvedAction = new URL(action || pageUrl.href, pageUrl); action = resolvedAction.href; } catch { /* keep raw */ }
    const method = (methodMatch ? methodMatch[1] : 'GET').toUpperCase();

    const inputs: string[] = [];
    let hasPassword = false;
    let hasCsrfToken = false;
    const inputRe = /<(?:input|textarea|select)\b([^>]*)>/gi;
    let im: RegExpExecArray | null;
    while ((im = inputRe.exec(body)) !== null) {
      const ia = im[1] || '';
      const nameMatch = /\bname\s*=\s*["']([^"']*)["']/i.exec(ia);
      const typeMatch = /\btype\s*=\s*["']([^"']*)["']/i.exec(ia);
      const name = nameMatch ? nameMatch[1] : '';
      const type = typeMatch ? typeMatch[1].toLowerCase() : 'text';
      if (name) inputs.push(name);
      if (type === 'password') hasPassword = true;
      if (/csrf|xsrf|token|authenticity|nonce/i.test(name)) hasCsrfToken = true;
    }
    // Some frameworks expose the CSRF token via a meta tag rather than a hidden input.
    if (!hasCsrfToken && /<meta[^>]+name\s*=\s*["'][^"']*(?:csrf|xsrf)[^"']*["']/i.test(html)) {
      hasCsrfToken = true;
    }

    const insecure = !!resolvedAction && resolvedAction.protocol === 'http:';
    forms.push({ pageUrl: pageUrl.href, action, method, inputs, hasPassword, hasCsrfToken, insecure });
  }
  return forms;
}

/**
 * Same-origin authenticated crawler. Bounded BFS that builds a site map and
 * harvests forms + parameterized endpoints, then derives business-logic
 * findings (insecure credential forms, missing CSRF, mixed content, IDOR-style
 * object references) from the real evidence it gathered.
 */
export async function runCrawl(targetUrl: string, opts: CrawlOptions = {}): Promise<{ result: CrawlResult; findings: Finding[] }> {
  const maxPages = opts.maxPages ?? 25;
  const maxDepth = opts.maxDepth ?? 3;
  const concurrency = opts.concurrency ?? 5;
  const budgetMs = opts.budgetMs ?? 45000;
  const log = opts.onLog ?? (() => {});
  const startedAt = Date.now();

  let start: URL;
  try {
    start = new URL(/^https?:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`);
  } catch {
    const empty: CrawlResult = { startUrl: targetUrl, pagesCrawled: 0, maxDepthReached: 0, durationMs: 0, authenticated: false, pages: [], forms: [], discoveredParams: [] };
    return { result: empty, findings: [] };
  }

  const origin = start.origin;
  const visited = new Set<string>();
  const pages: CrawlPage[] = [];
  const forms: CrawlForm[] = [];
  const params = new Set<string>();
  const idEndpoints = new Set<string>();
  const mixedContent = new Set<string>();
  let maxDepthReached = 0;

  const sameOrigin = (u: URL) => u.origin === origin && (opts.allowPrivateHosts || !PRIVATE_IP_RE.test(u.hostname));

  const reqHeaders: Record<string, string> = { 'User-Agent': USER_AGENT, Accept: 'text/html,application/xhtml+xml,*/*;q=0.8' };
  if (opts.authHeader) reqHeaders['Authorization'] = opts.authHeader;

  // Numeric / object-reference detection in discovered URLs (IDOR/BOLA signal)
  const recordObjectRefs = (u: URL) => {
    for (const [k, v] of u.searchParams) {
      params.add(k);
      if (/^\d{1,12}$/.test(v) && /(^|_|-)(id|uid|user|account|order|invoice|doc|file|num)s?$/i.test(k)) {
        idEndpoints.add(`${u.pathname}?${k}=${v}`);
      }
    }
    // /users/123, /invoice/45, /api/orders/9
    if (/\/(users?|accounts?|orders?|invoices?|documents?|files?|profiles?|tickets?)\/\d{1,12}(\/|$)/i.test(u.pathname)) {
      idEndpoints.add(u.pathname);
    }
  };

  let queue: Array<{ url: URL; depth: number }> = [{ url: start, depth: 0 }];
  visited.add(canonical(start));

  const fetchPage = async (item: { url: URL; depth: number }): Promise<Array<{ url: URL; depth: number }>> => {
    const next: Array<{ url: URL; depth: number }> = [];
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 6000);
    try {
      const res = await fetch(item.url.href, { method: 'GET', headers: reqHeaders, redirect: 'follow', signal: controller.signal });
      const ct = res.headers.get('content-type') || '';
      const page: CrawlPage = { url: item.url.href, status: res.status, depth: item.depth, contentType: ct.split(';')[0] || undefined };
      maxDepthReached = Math.max(maxDepthReached, item.depth);

      if (!ct.includes('html')) { pages.push(page); return next; }

      const html = (await res.text().catch(() => '')).slice(0, 600000); // cap parse size
      page.title = extractTitle(html);
      pages.push(page);

      for (const f of extractForms(html, item.url)) forms.push(f);

      // Mixed content: secure page pulling insecure resources
      if (item.url.protocol === 'https:') {
        for (const r of extractResources(html, item.url)) {
          if (r.protocol === 'http:') mixedContent.add(r.origin + r.pathname);
        }
      }

      if (item.depth < maxDepth) {
        for (const link of extractLinks(html, item.url)) {
          if (!sameOrigin(link)) continue;
          recordObjectRefs(link);
          const key = canonical(link);
          if (visited.has(key)) continue;
          // Skip obvious binary/asset endpoints from the BFS frontier
          if (/\.(png|jpe?g|gif|svg|ico|css|js|woff2?|ttf|map|pdf|zip|mp4|webp)(\?|$)/i.test(link.pathname)) continue;
          visited.add(key);
          next.push({ url: link, depth: item.depth + 1 });
        }
      }
    } catch {
      pages.push({ url: item.url.href, status: 0, depth: item.depth });
    } finally {
      clearTimeout(t);
    }
    return next;
  };

  // Level-by-level BFS with a bounded concurrency pool and a global time budget.
  while (queue.length > 0 && pages.length < maxPages && Date.now() - startedAt < budgetMs) {
    const batch = queue.splice(0, Math.min(concurrency, maxPages - pages.length));
    const results = await Promise.all(batch.map(fetchPage));
    const discovered = results.flat();
    queue = queue.concat(discovered);
  }

  const result: CrawlResult = {
    startUrl: start.href,
    pagesCrawled: pages.length,
    maxDepthReached,
    durationMs: Date.now() - startedAt,
    authenticated: !!opts.authHeader,
    pages,
    forms,
    discoveredParams: [...params].sort(),
  };

  log(`[CRAWL] Mapped ${pages.length} page(s), ${forms.length} form(s), ${params.size} unique parameter(s)`);

  return { result, findings: deriveFindings(result, [...idEndpoints], [...mixedContent], start) };
}

function deriveFindings(result: CrawlResult, idEndpoints: string[], mixedContent: string[], start: URL): Finding[] {
  const findings: Finding[] = [];
  const host = start.hostname;

  // 1. Credential forms over plain HTTP — critical
  const insecureCredForms = result.forms.filter(f => f.hasPassword && f.insecure);
  if (insecureCredForms.length > 0) {
    const sample = insecureCredForms.slice(0, 5).map(f => f.action).join('\n');
    findings.push({
      id: newId(),
      title: 'Credentials Submitted Over Unencrypted HTTP',
      description: `A login/password form on this site submits to an http:// endpoint, so usernames and passwords travel in cleartext and can be read by anyone on the network path.\nAffected form action(s):\n${sample}`,
      severity: 'critical',
      confidence: 'high',
      category: 'DAST',
      endpoint: insecureCredForms[0].action,
      fix: 'Serve the entire site over HTTPS and point every form action at an https:// URL. Add an HTTP→HTTPS redirect and an HSTS header so browsers never use plaintext.',
      plainEnglish: 'Anyone sharing the same WiFi or network as your user can literally read the password they type in, because it is sent without encryption. This is one of the most serious things to fix.',
      codeFixExample: `// Express: force HTTPS for every request\napp.use((req, res, next) => {\n  if (req.headers['x-forwarded-proto'] !== 'https') {\n    return res.redirect('https://' + req.headers.host + req.url);\n  }\n  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');\n  next();\n});`,
    });
  }

  // 2. State-changing forms without an anti-CSRF token — high (one consolidated finding)
  const csrfMissing = result.forms.filter(f => f.method === 'POST' && !f.hasCsrfToken);
  if (csrfMissing.length > 0) {
    const sample = csrfMissing.slice(0, 6).map(f => `${f.method} ${f.action}`).join('\n');
    findings.push({
      id: newId(),
      title: 'Form Missing Anti-CSRF Protection',
      description: `${csrfMissing.length} POST form(s) were discovered without a CSRF token field. A malicious site could trick a logged-in user's browser into submitting these forms without their consent.\nAffected form(s):\n${sample}`,
      severity: 'high',
      confidence: 'medium',
      category: 'DAST',
      endpoint: csrfMissing[0].action,
      fix: 'Add a per-session CSRF token to every state-changing form and verify it server-side. Most frameworks ship CSRF middleware you can enable in one line.',
      plainEnglish: 'Without a CSRF token, another website could quietly make your logged-in users perform actions (change email, make a purchase, delete data) just by visiting a booby-trapped page.',
      codeFixExample: `// Express + csrf-csrf (or csurf)\nimport { doubleCsrf } from 'csrf-csrf';\nconst { doubleCsrfProtection } = doubleCsrf({ getSecret: () => process.env.CSRF_SECRET });\napp.use(doubleCsrfProtection);\n// In your form template, include the token:\n// <input type="hidden" name="_csrf" value="<%= req.csrfToken() %>">`,
    });
  }

  // 3. Mixed content — medium
  if (mixedContent.length > 0) {
    findings.push({
      id: newId(),
      title: 'Mixed Content: Insecure Resources on a Secure Page',
      description: `Pages served over HTTPS load ${mixedContent.length} resource(s) over plain HTTP. Browsers may block these or warn users, and attackers can tamper with the insecure resources.\nExamples:\n${mixedContent.slice(0, 6).join('\n')}`,
      severity: 'medium',
      confidence: 'high',
      category: 'DAST',
      fix: 'Update every script/style/image/iframe reference to use https:// (or protocol-relative URLs served over HTTPS).',
      plainEnglish: 'Your secure page is pulling in some files over an insecure connection. That weakens the padlock — an attacker could swap those files out, and some browsers will show a "not fully secure" warning to your users.',
      codeFixExample: `<!-- Before -->\n<script src="http://cdn.example.com/app.js"></script>\n<!-- After -->\n<script src="https://cdn.example.com/app.js"></script>`,
    });
  }

  // 4. Object references in URLs — IDOR/BOLA signal (medium, low confidence — needs manual review)
  if (idEndpoints.length > 0) {
    findings.push({
      id: newId(),
      title: 'Object References Exposed in URLs (Possible IDOR)',
      description: `The crawl found ${idEndpoints.length} URL(s) that reference objects by sequential/numeric IDs. If the server does not check that the logged-in user owns the requested object, an attacker can change the number to read or modify other users' data (IDOR/BOLA).\nExamples:\n${idEndpoints.slice(0, 8).join('\n')}`,
      severity: 'medium',
      confidence: 'low',
      category: 'API_SEC',
      endpoint: idEndpoints[0],
      fix: 'For every endpoint that takes an object ID, verify on the server that the current user is authorized to access that specific object before returning or modifying it.',
      plainEnglish: 'Your app puts things like ?id=123 in the URL. If you are not careful, a user could just change 123 to 124 and see someone else\'s data. Always double-check on the server that the logged-in person is allowed to see what they asked for.',
      codeFixExample: `// Before: trusts the id blindly\napp.get('/api/orders/:id', async (req, res) => {\n  res.json(await db.getOrder(req.params.id));\n});\n// After: enforce ownership\napp.get('/api/orders/:id', async (req, res) => {\n  const order = await db.getOrder(req.params.id);\n  if (!order || order.userId !== req.user.id) return res.status(404).end();\n  res.json(order);\n});`,
    });
  }

  // 5. Password autocomplete — low/informational (one consolidated note)
  const autoCompleteForms = result.forms.filter(f => f.hasPassword && !f.insecure);
  if (autoCompleteForms.length > 0 && insecureCredForms.length === 0) {
    findings.push({
      id: newId(),
      title: 'Login Surface Discovered',
      description: `An authentication form was discovered at ${autoCompleteForms[0].action}. It is served over HTTPS (good). Ensure rate-limiting and account-lockout protect it against credential stuffing.`,
      severity: 'info',
      confidence: 'medium',
      category: 'DAST',
      endpoint: autoCompleteForms[0].action,
      fix: 'Add rate limiting and brute-force lockout to the login endpoint, and consider offering MFA.',
      plainEnglish: `We found your login form for ${host}. It uses HTTPS, which is what you want. Just make sure attackers can't try thousands of password guesses — add rate limiting.`,
      codeFixExample: `import rateLimit from 'express-rate-limit';\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });\napp.post('/login', loginLimiter, loginHandler);`,
    });
  }

  return findings;
}
