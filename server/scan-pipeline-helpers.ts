import type { AuthProfile } from '../src/types.js';
import { recalculateScore } from './db.js';

export const PRIVATE_IP_RE = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|0\.0\.0\.0)/i;

/** Returns null when the URL is valid, or an error message string when it should be rejected. */
export function validateTargetUrl(raw: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(raw.startsWith('http') ? raw : `https://${raw}`);
  } catch {
    return 'Invalid URL format.';
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return 'Only http and https targets are allowed.';
  }
  if (PRIVATE_IP_RE.test(parsed.hostname)) {
    return 'Scanning private/local addresses is not allowed.';
  }
  return null;
}

/** Resolve an AuthProfile into a concrete headers map. For form type, performs actual login. */
export async function resolveAuthProfile(profile: AuthProfile): Promise<Record<string, string>> {
  switch (profile.type) {
    case 'bearer':
      return { Authorization: `Bearer ${profile.headerValue ?? ''}` };
    case 'cookie':
      return { Cookie: profile.headerValue ?? '' };
    case 'header':
      if (!profile.headerName) return {};
      return { [profile.headerName]: profile.headerValue ?? '' };
    case 'basic': {
      const creds = Buffer.from(`${profile.username ?? ''}:${profile.password ?? ''}`).toString('base64');
      return { Authorization: `Basic ${creds}` };
    }
    case 'form': {
      const {
        loginUrl, loginUsername = '', loginPassword = '',
        loginUsernameField = 'username', loginPasswordField = 'password',
      } = profile;
      if (!loginUrl || !loginUsername) return {};

      // Try JSON body login first (most modern apps)
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 8000);
        const res = await fetch(loginUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0' },
          body: JSON.stringify({ [loginUsernameField]: loginUsername, [loginPasswordField]: loginPassword }),
          redirect: 'manual',
          signal: ctrl.signal,
        });
        const body = await res.text().catch(() => '');
        try {
          const json = JSON.parse(body);
          const token = json.token || json.access_token || json.accessToken || json.jwt || json.id_token || json.authToken;
          if (token && typeof token === 'string') return { Authorization: `Bearer ${token}` };
        } catch {}
        const setCookie = res.headers.get('set-cookie');
        if (setCookie && [200, 201, 302, 301].includes(res.status)) {
          return { Cookie: setCookie.split(';')[0] };
        }
      } catch {}

      // Fallback: form-encoded login
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 8000);
        const res = await fetch(loginUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0' },
          body: new URLSearchParams({ [loginUsernameField]: loginUsername, [loginPasswordField]: loginPassword }).toString(),
          redirect: 'manual',
          signal: ctrl.signal,
        });
        const setCookie = res.headers.get('set-cookie');
        if (setCookie && [200, 201, 302, 301].includes(res.status)) {
          return { Cookie: setCookie.split(';')[0] };
        }
      } catch {}

      return {};
    }
    default:
      return {};
  }
}

/** Distil the full DiagnosticResult into the compact real data surfaced in the report's raw drawer. */
export function buildScanDiagnostics(diag: import('./scanner.js').DiagnosticResult): import('../src/types.js').ScanDiagnostics {
  return {
    responseStatus: diag.responseStatus,
    requestHeaders: {
      'User-Agent': 'Seclayer-Security-Scanner/2.0 (seclayer.io; scanner@seclayer.io)',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    },
    responseHeaders: diag.headers,
    ip: diag.easmPerimeter.ip,
    nameserver: diag.easmPerimeter.nameserver,
    protocol: diag.easmPerimeter.protocol,
    probedPaths: diag.probedPaths,
    techLeaked: diag.techLeaked,
    missingHeaders: diag.missingHeaders,
    liveSubdomains: diag.easmPerimeter.subdomains.filter(s => s.status === 'live').length,
  };
}

// Merge crawl-derived findings into the static set and re-score so the AI
// stage and the final report account for the deep-crawl evidence.
export function mergeCrawl(
  staticCompiled: { score: number; severity: import('../src/types.js').Severity; findings: import('../src/types.js').Finding[] },
  crawlFindings: import('../src/types.js').Finding[],
): void {
  if (!crawlFindings.length) return;
  staticCompiled.findings = staticCompiled.findings.concat(crawlFindings);
  const rescored = recalculateScore(staticCompiled.findings);
  staticCompiled.score = rescored.score;
  staticCompiled.severity = rescored.severity;
}
