import { probePort, getSslCertInfo, testTlsVersion, attemptAxfr } from './network-probes.js';
import type { PentagiContext } from './context.js';

/** Stage 1a–1d: DNS enumeration, IPv6, zone transfer, TCP port scan, TLS inspection. */
export async function reconDns(ctx: PentagiContext): Promise<void> {
  const { log, findings, hostname, isHttps } = ctx;

  log('Scout Agent', `Initiating active reconnaissance against ${ctx.targetUrl}`);

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

    // DKIM selector probe (common selectors)
    const dkimSelectors = ['default', 'google', 'mail', 'smtp', 'k1', 'selector1', 'selector2'];
    let dkimFound = false;
    await Promise.all(dkimSelectors.map(async sel => {
      if (dkimFound) return;
      try {
        const r = await (await import('dns/promises')).resolveTxt(`${sel}._domainkey.${hostname}`);
        if (r.length > 0 && r.some(t => t.join('').startsWith('v=DKIM1'))) {
          log('Scout Agent', `DKIM record found: selector "${sel}" — email signing configured`);
          dkimFound = true;
        }
      } catch {}
    }));
    if (!dkimFound) {
      log('Scout Agent', 'No DKIM record found on common selectors — email authenticity unverifiable');
      findings.push({ severity: 'low', title: 'Missing DKIM Record (Email Authentication Gap)' });
    }

    // CAA (Certificate Authority Authorization) record
    try {
      const caaRecs = await (await import('dns/promises')).resolveCaa(hostname);
      if (caaRecs.length > 0) {
        const issuers = caaRecs.map(r => (r as any).issue || (r as any).issuewild || '?');
        log('Scout Agent', `CAA record present: authorized CAs: ${issuers.join(', ')}`);
      } else {
        log('Scout Agent', 'CAA record empty — any CA can issue certificates for this domain');
        findings.push({ severity: 'low', title: 'Missing CAA Record (Any CA Can Issue Certificates)' });
      }
    } catch {
      log('Scout Agent', 'No CAA record — certificate issuance not restricted to specific CAs');
      findings.push({ severity: 'low', title: 'Missing CAA Record (Any CA Can Issue Certificates)' });
    }
  } catch (e: any) {
    log('Scout Agent', `DNS enumeration failed: ${e.message}`);
  }

  // IPv6 surface detection
  try {
    const ipv6Recs = await (await import('dns/promises')).resolve6(hostname);
    if (ipv6Recs.length > 0) {
      log('Scout Agent', `IPv6 address detected: ${ipv6Recs[0]} — verify IPv6 surface has equivalent security controls to IPv4`);
      findings.push({ severity: 'low', title: `IPv6 Exposure Detected (${ipv6Recs[0]}) — Firewall Parity Required` });
    }
  } catch {
    log('Scout Agent', 'IPv6: no AAAA record found');
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

    // TLS version weakness — test for TLS 1.0 and 1.1 acceptance
    log('Scout Agent', 'Testing for deprecated TLS 1.0 / TLS 1.1 protocol acceptance...');
    const [tls10, tls11] = await Promise.all([
      testTlsVersion(hostname, 'TLSv1'),
      testTlsVersion(hostname, 'TLSv1.1'),
    ]);
    if (tls10) {
      log('Scout Agent', 'CRITICAL: TLS 1.0 accepted — POODLE/BEAST vulnerable, PCI-DSS non-compliant');
      findings.push({ severity: 'critical', title: 'TLS 1.0 Accepted (POODLE / BEAST Vulnerable)' });
    }
    if (tls11) {
      log('Scout Agent', `${tls10 ? 'Also: ' : ''}TLS 1.1 accepted — deprecated protocol, cipher weaknesses (RC4, 3DES)'`);
      findings.push({ severity: 'high', title: 'TLS 1.1 Accepted (Deprecated Protocol)' });
    }
    if (!tls10 && !tls11) {
      log('Scout Agent', 'TLS version check: only TLS 1.2+ accepted (correctly configured)');
    }
  }
}
