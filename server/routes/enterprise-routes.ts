import { Express } from 'express';
import { LocalFileDb } from '../db.js';
import { requireAuth } from '../middleware.js';

/** Enterprise endpoints: ASPM correlation across past scans, and EASM (DNS + certificate transparency) recon. */
export function registerEnterpriseRoutes(app: Express, dbInstance: LocalFileDb) {
  // 1. ASPM — correlate findings across user's completed scans
  app.post('/api/enterprise/aspm/correlate', requireAuth, (req, res) => {
    const { url } = req.body;
    const userScans = dbInstance.listScans(req.userId!).filter(s => {
      if (s.status !== 'complete') return false;
      if (url) return s.url.toLowerCase().includes(url.toLowerCase().replace(/https?:\/\//i, ''));
      return true;
    });

    if (userScans.length === 0) {
      return res.json({
        success: true,
        targetUrl: url || 'all targets',
        scansAnalyzed: 0,
        message: 'No completed scans found for correlation. Run scans first.',
        correlatedFindings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      });
    }

    const findingMap = new Map<string, {
      title: string; severity: string; category: string;
      occurrences: number; seenIn: string[]; description: string; fix: string;
    }>();

    userScans.forEach(scan => {
      (scan.findings || []).forEach(f => {
        if (f.isFalsePositive) return;
        const existing = findingMap.get(f.title);
        if (existing) {
          existing.occurrences++;
          if (!existing.seenIn.includes(scan.url)) existing.seenIn.push(scan.url);
        } else {
          findingMap.set(f.title, {
            title: f.title, severity: f.severity, category: f.category,
            description: f.description, fix: f.fix,
            occurrences: 1, seenIn: [scan.url],
          });
        }
      });
    });

    const all = Array.from(findingMap.values()).sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity as keyof typeof order] ?? 5) - (order[b.severity as keyof typeof order] ?? 5);
    });

    const summary = { total: all.length, critical: 0, high: 0, medium: 0, low: 0 };
    all.forEach(f => { if (f.severity in summary) (summary as any)[f.severity]++; });

    res.json({
      success: true,
      targetUrl: url || 'all targets',
      scansAnalyzed: userScans.length,
      correlatedFindings: all,
      summary,
    });
  });

  // 2. EASM — real DNS + certificate transparency via crt.sh
  app.post('/api/enterprise/easm/recon', requireAuth, async (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain is required.' });

    const cleanDomain = domain.replace(/https?:\/\//i, '').split('/')[0].trim();

    try {
      const dns = await import('dns/promises');

      const [ipResult, nsResult, mxResult] = await Promise.allSettled([
        dns.resolve4(cleanDomain),
        dns.resolveNs(cleanDomain),
        dns.resolveMx(cleanDomain),
      ]);

      const ip = ipResult.status === 'fulfilled' ? ipResult.value[0] : 'N/A';
      const nameservers = nsResult.status === 'fulfilled' ? nsResult.value : [];
      const mxRecords = mxResult.status === 'fulfilled'
        ? mxResult.value.map(r => ({ exchange: r.exchange, priority: r.priority }))
        : [];

      let ctSubdomains: string[] = [];
      try {
        const ctController = new AbortController();
        const ctTimeout = setTimeout(() => ctController.abort(), 8000);
        const ctRes = await fetch(
          `https://crt.sh/?q=%.${cleanDomain}&output=json`,
          { signal: ctController.signal }
        );
        clearTimeout(ctTimeout);
        if (ctRes.ok) {
          const ctData = await ctRes.json() as Array<{ name_value: string }>;
          const names = new Set<string>();
          ctData.forEach(entry => {
            if (entry.name_value) {
              entry.name_value.split('\n').forEach(name => {
                const clean = name.trim().toLowerCase().replace(/^\*\./, '');
                if (clean.endsWith(`.${cleanDomain}`) && clean !== cleanDomain) {
                  names.add(clean);
                }
              });
            }
          });
          ctSubdomains = Array.from(names).slice(0, 30);
        }
      } catch (e) {
        console.warn('crt.sh lookup failed:', e);
      }

      const subdomainResults = await Promise.all(
        ctSubdomains.map(async sub => {
          try {
            const records = await dns.resolve4(sub);
            return { subdomain: sub, ip: records[0], status: 'live' };
          } catch {
            return { subdomain: sub, ip: 'N/A', status: 'inactive' };
          }
        })
      );

      res.json({
        success: true,
        domain: cleanDomain,
        scannedAt: new Date().toISOString(),
        ip,
        nameservers,
        mxRecords,
        subdomains: subdomainResults,
        summary: {
          totalDiscovered: ctSubdomains.length,
          live: subdomainResults.filter(s => s.status === 'live').length,
        },
      });
    } catch (err: any) {
      res.status(500).json({ error: 'EASM recon failed.', details: err.message });
    }
  });
}
