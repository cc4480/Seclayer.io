import crypto from 'crypto';

/**
 * False-positive suppression for the active scanner.
 *
 * Modern sites routinely answer unknown paths with HTTP 200 (SPA shells,
 * soft-404 templates, WAF interstitials) and echo request data back in error
 * pages. A naive "status === 200" or substring check therefore produces a flood
 * of false positives. The helpers here calibrate a baseline of how the target
 * responds to content that does NOT exist, then confirm each finding by showing
 * the probe response genuinely differs from that baseline (or matches the exact
 * signature of the artifact being looked for).
 */

export interface ResponseSignature {
  status: number;
  length: number;
  /** Hash of the body with volatile content (digits, hex tokens) normalized out. */
  fingerprint: string;
}

/** A set of "this is what 'not found' / a generic template looks like" signatures. */
export interface SoftNotFoundBaseline {
  signatures: ResponseSignature[];
}

/** Normalize a body so two renders of the same template hash identically. */
export function fingerprintBody(body: string): string {
  const normalized = (body || '')
    .toLowerCase()
    .replace(/[0-9a-f]{8,}/g, '') // hex nonces / hashes / asset digests
    .replace(/\d+/g, '') // timestamps, counts, ids
    .replace(/\s+/g, ' ')
    .trim();
  return crypto.createHash('sha1').update(normalized).digest('hex');
}

export function signature(status: number, body: string): ResponseSignature {
  return { status, length: (body || '').length, fingerprint: fingerprintBody(body) };
}

export function buildBaseline(...sigs: Array<ResponseSignature | null | undefined>): SoftNotFoundBaseline {
  return { signatures: sigs.filter((s): s is ResponseSignature => !!s) };
}

/** True when a probe response is effectively the same page as a known template. */
export function matchesAnyBaseline(probe: ResponseSignature, baseline: SoftNotFoundBaseline): boolean {
  return baseline.signatures.some((b) => {
    if (probe.fingerprint === b.fingerprint) return true;
    // Same status and near-identical length => same template with volatile bits.
    if (probe.status === b.status) {
      const diff = Math.abs(probe.length - b.length);
      const rel = diff / Math.max(1, b.length);
      if (rel <= 0.03) return true;
    }
    return false;
  });
}

// --- Sensitive-file content validators (confirm the body is the real artifact) ---

export function looksLikeEnvFile(body: string): boolean {
  if (!body || /<\s*(html|!doctype|head|body)\b/i.test(body)) return false;
  const kvLines = (body.match(/^\s*[A-Z][A-Z0-9_]{2,}\s*=.*/gm) || []).length;
  return kvLines >= 2;
}

export function looksLikeGitConfig(body: string): boolean {
  if (!body || /<\s*html/i.test(body)) return false;
  return /\[core\]/i.test(body) && /repositoryformatversion/i.test(body);
}

export function looksLikePhpInfo(body: string): boolean {
  return /<title>phpinfo\(\)/i.test(body) || (/PHP Version/i.test(body) && /phpinfo\(\)/i.test(body));
}

/**
 * Decide whether a probed path is genuinely exposed (not a soft-404 / SPA shell).
 * Known sensitive files must additionally match their expected content signature.
 */
export function isPathGenuinelyExposed(
  path: string,
  status: number,
  body: string,
  baseline: SoftNotFoundBaseline,
): boolean {
  if (status !== 200) return false;
  if (matchesAnyBaseline(signature(status, body), baseline)) return false;
  if (path.includes('.env')) return looksLikeEnvFile(body);
  if (path.includes('.git')) return looksLikeGitConfig(body);
  if (path.includes('phpinfo')) return looksLikePhpInfo(body);
  // Generic directories (/admin, /wp-admin): a distinct non-template page is
  // evidence enough, since the soft-404/homepage templates were excluded above.
  return true;
}

// --- API probe validators ---

/** Confirm a real GraphQL introspection result rather than an echoed query/HTML. */
export function isGraphqlIntrospection(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    const types = parsed?.data?.__schema?.types;
    return Array.isArray(types) && types.length > 0;
  } catch {
    return false;
  }
}

/** Confirm a probed object endpoint actually returned a user object (not an HTML shell). */
export function isUserObjectLeak(contentType: string, status: number, body: string, baseline: SoftNotFoundBaseline): boolean {
  if (status !== 200) return false;
  if (!/json/i.test(contentType)) return false;
  if (matchesAnyBaseline(signature(status, body), baseline)) return false;
  try {
    const parsed = JSON.parse(body);
    const obj = Array.isArray(parsed) ? parsed[0] : (parsed?.data ?? parsed);
    if (!obj || typeof obj !== 'object') return false;
    const keys = Object.keys(obj).map((k) => k.toLowerCase());
    return keys.includes('email') || keys.includes('role') || (keys.includes('id') && keys.includes('username'));
  } catch {
    return false;
  }
}

// --- Injection control-comparison validators ---

const SQL_ERROR_SIGNATURES = [
  'sql syntax',
  'syntax error',
  'ora-0',
  'postgresql query failed',
  'mysql_fetch',
  'sqlstate',
  'unclosed quotation mark',
  'pg::syntaxerror',
];

/** A DB error must appear in the injected response but NOT in the benign control. */
export function isSqlInjectionEvidence(injected: string, control: string): boolean {
  const inj = (injected || '').toLowerCase();
  const ctl = (control || '').toLowerCase();
  return SQL_ERROR_SIGNATURES.some((s) => inj.includes(s) && !ctl.includes(s));
}

const ID_OUTPUT_RE = /uid=\d+\([^)]+\)\s+gid=\d+\(/;

/** `id` output must appear because of the payload, not in the benign control. */
export function isCommandInjectionEvidence(injected: string, control: string): boolean {
  return ID_OUTPUT_RE.test(injected || '') && !ID_OUTPUT_RE.test(control || '');
}

const SSRF_BANNER_RE = /SSH-2\.0-OpenSSH|Protocol mismatch/;

/** An internal service banner must appear because of the payload, not in the control. */
export function isSsrfEvidence(injected: string, control: string): boolean {
  return SSRF_BANNER_RE.test(injected || '') && !SSRF_BANNER_RE.test(control || '');
}
