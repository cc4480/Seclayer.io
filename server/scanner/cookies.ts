// Cookie flag analysis with false-positive scoping. The insecure-cookie checks
// (HttpOnly / Secure / SameSite) only matter for cookies that actually carry a
// session or auth token — flagging analytics, consent, or CDN cookies for a
// missing HttpOnly flag is noise, not a vulnerability. We therefore evaluate
// each Set-Cookie individually and only report session/auth-like cookies, while
// skipping a known-benign allowlist.

const SESSION_COOKIE_RE = /(sess(ion)?|sid|auth|token|jwt|csrf|xsrf|login|remember|identity|phpsessid|jsessionid|connect\.sid|laravel_session|asp\.?net)/i;

const BENIGN_COOKIE_RE = /^(_ga|_gid|_gat|_gcl_|_fbp|_fbc|__cf_bm|__cfruid|cf_clearance|awsalb|awsalbcors|_hj|ajs_|amplitude|mp_|optimizely|__utm|_utm|_pk_|intercom|_clck|_clsk|didomi|euconsent|optanonconsent|_hp2)/i;

// Extracts the per-cookie Set-Cookie array from a fetch Response's headers.
// undici exposes getSetCookie(); response.headers.forEach() otherwise collapses
// multiple Set-Cookie headers into a single comma-joined value.
export function extractSetCookies(headers: Headers): string[] {
  const getSetCookie = (headers as any).getSetCookie;
  if (typeof getSetCookie === "function") return getSetCookie.call(headers);
  const joined = headers.get("set-cookie");
  return joined ? [joined] : [];
}

// Returns the deduped set of cookie flag issues across all Set-Cookie headers.
// `setCookies` should be the per-cookie array (undici's getSetCookie()), not the
// comma-joined blob, so multi-cookie responses are analyzed correctly.
export function analyzeCookies(setCookies: string[], isHttps: boolean): string[] {
  const issues = new Set<string>();

  for (const raw of setCookies) {
    const name = (raw.split('=')[0] || '').trim();
    if (!name || BENIGN_COOKIE_RE.test(name)) continue;
    // Only session/auth-carrying cookies materially matter for these flags.
    if (!SESSION_COOKIE_RE.test(name)) continue;

    const lower = raw.toLowerCase();
    if (!/;\s*httponly\b/.test(lower)) {
      issues.add('Session cookie lacks HttpOnly flag');
    }
    // The __Host-/__Secure- name prefixes require the Secure attribute by spec,
    // so a cookie using them cannot lack it.
    const impliesSecure = /^__(host|secure)-/i.test(name);
    if (isHttps && !impliesSecure && !/;\s*secure\b/.test(lower)) {
      issues.add('Session cookie lacks Secure directive');
    }
    if (!/;\s*samesite\b/.test(lower)) {
      issues.add('Session cookie lacks SameSite policy');
    }
  }

  return [...issues];
}
