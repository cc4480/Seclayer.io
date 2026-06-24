import type { FindingEntry, PentagiContext } from './context.js';

/** Stage 1e–1i: robots/security.txt, crt.sh subdomain takeover, crawler, tech fingerprinting. */
export async function reconWeb(ctx: PentagiContext): Promise<void> {
  const { log, findings, httpProbe, origin, hostname, targetUrl } = ctx;

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

  // 1h. Link crawler — discover pages to broaden probe surface
  log('Scout Agent', `Crawling ${targetUrl} for linked pages (depth 2, max 25 pages)...`);
  const crawledUrls = new Set<string>([targetUrl]);
  const crawlQueue: Array<{ url: string; depth: number }> = [{ url: targetUrl, depth: 0 }];
  while (crawlQueue.length > 0 && crawledUrls.size < 25) {
    const { url: cUrl, depth } = crawlQueue.shift()!;
    if (depth >= 2) continue;
    const cRes = await httpProbe(cUrl, {}, 4000);
    if (!cRes || cRes.status !== 200) continue;
    const links = [...cRes.body.matchAll(/href=["']([^"'#?]+)["']/gi)]
      .map(m => { try { return new URL(m[1], cUrl).href; } catch { return null; } })
      .filter((l): l is string => l !== null && l.startsWith(origin) && !crawledUrls.has(l));
    for (const link of [...new Set(links)].slice(0, 8)) {
      crawledUrls.add(link);
      crawlQueue.push({ url: link, depth: depth + 1 });
    }
  }
  const crawledPages = [...crawledUrls].filter(u => u !== targetUrl);
  if (crawledPages.length > 0) {
    log('Scout Agent', `Crawler found ${crawledPages.length} additional pages: ${crawledPages.slice(0, 4).map(u => new URL(u).pathname).join(', ')}${crawledPages.length > 4 ? '...' : ''}`);
  } else {
    log('Scout Agent', 'Crawler: no additional same-origin pages found from homepage links');
  }

  // 1i. Technology fingerprinting + CVE detection
  log('Scout Agent', 'Fingerprinting technology stack from HTTP headers and page content...');
  const fpRes = await httpProbe(targetUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } });
  if (fpRes) {
    const serverH = fpRes.headers['server'] || '';
    const poweredBy = fpRes.headers['x-powered-by'] || '';
    const body = fpRes.body;

    interface CveEntry { pattern: RegExp; cve: string; desc: string; severity: FindingEntry['severity'] }
    const TECH_CVE_MAP: Array<{ name: string; detect: RegExp; source: string; cves?: CveEntry[] }> = [
      { name: 'Apache', source: serverH, detect: /Apache\//i, cves: [
        { pattern: /Apache\/2\.4\.4[89]\b/i, cve: 'CVE-2021-41773', desc: 'Path traversal + unauthenticated RCE', severity: 'critical' },
        { pattern: /Apache\/2\.4\.50\b/i, cve: 'CVE-2021-42013', desc: 'Path traversal RCE (41773 bypass)', severity: 'critical' },
        { pattern: /Apache\/2\.4\.(1[0-9]|2[0-9]|3\d|4[01234567])\b/i, cve: 'CVE-2022-31813', desc: 'mod_proxy header forwarding bypass', severity: 'high' },
      ]},
      { name: 'nginx', source: serverH, detect: /nginx\//i, cves: [
        { pattern: /nginx\/1\.(1[0-3])\./i, cve: 'CVE-2019-9511', desc: 'HTTP/2 DoS via window size manipulation', severity: 'high' },
        { pattern: /nginx\/0\./i, cve: 'CVE-legacy', desc: 'nginx 0.x — end-of-life, multiple critical CVEs', severity: 'critical' },
      ]},
      { name: 'PHP', source: poweredBy, detect: /PHP\//i, cves: [
        { pattern: /PHP\/[45]\./i, cve: 'CVE-EOL', desc: 'PHP 5/4 end-of-life — hundreds of unpatched CVEs', severity: 'critical' },
        { pattern: /PHP\/7\.[012]\./i, cve: 'CVE-EOL', desc: 'PHP 7.0-7.2 end-of-life — no security updates', severity: 'high' },
        { pattern: /PHP\/8\.0\.\d\b/i, cve: 'CVE-2023-3824', desc: 'PHP 8.0 heap buffer overflow in PHAR', severity: 'high' },
      ]},
      { name: 'IIS', source: serverH, detect: /Microsoft-IIS\//i, cves: [
        { pattern: /Microsoft-IIS\/10\.0/i, cve: 'CVE-2021-31166', desc: 'HTTP protocol stack RCE in IIS 10', severity: 'critical' },
        { pattern: /Microsoft-IIS\/[0-9]\./i, cve: 'CVE-EOL', desc: 'IIS version below 10 — end-of-life', severity: 'high' },
      ]},
      { name: 'OpenSSL', source: serverH + ' ' + body, detect: /OpenSSL\/[12]\./i, cves: [
        { pattern: /OpenSSL\/1\.0\.[012]/i, cve: 'CVE-EOL', desc: 'OpenSSL 1.0.x end-of-life — Heartbleed era vulnerabilities', severity: 'critical' },
        { pattern: /OpenSSL\/1\.1\.1[a-q]\b/i, cve: 'CVE-2022-0778', desc: 'OpenSSL infinite loop in BN_mod_sqrt()', severity: 'high' },
      ]},
      { name: 'WordPress', source: body, detect: /wp-content|wp-includes/i },
      { name: 'Drupal', source: body, detect: /drupal/i },
      { name: 'Joomla', source: body, detect: /Joomla!/i },
      { name: 'Laravel', source: poweredBy, detect: /Laravel/i },
      { name: 'Express.js', source: poweredBy, detect: /Express/i },
      { name: 'ASP.NET', source: poweredBy + ' ' + serverH, detect: /ASP\.NET/i },
      { name: 'Tomcat', source: serverH, detect: /Apache-Coyote|Tomcat/i },
    ];

    const detectedTech: string[] = [];
    for (const entry of TECH_CVE_MAP) {
      if (!entry.detect.test(entry.source)) continue;
      detectedTech.push(entry.name);
      if (entry.cves) {
        for (const { pattern, cve, desc, severity } of entry.cves) {
          if (pattern.test(entry.source)) {
            log('Scout Agent', `CVE match: ${cve} — ${entry.name} version is vulnerable: ${desc}`);
            findings.push({ severity, title: `${entry.name} Vulnerable Version (${cve}): ${desc}` });
          }
        }
      }
    }
    if (detectedTech.length > 0) {
      log('Scout Agent', `Tech stack detected: ${detectedTech.join(', ')}`);
    } else {
      log('Scout Agent', 'Tech fingerprinting: no identifiable server/framework in response headers');
    }
  }
}
