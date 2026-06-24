import { Finding, CrawlResult } from '../../src/types.js';
import { newId } from './html-parsing.js';

export function deriveFindings(result: CrawlResult, idEndpoints: string[], mixedContent: string[], start: URL): Finding[] {
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
