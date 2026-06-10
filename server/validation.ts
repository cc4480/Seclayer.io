import dns from 'dns/promises';
import net from 'net';
import { config } from './config.js';
import { HttpError } from './middleware.js';

/**
 * Input validation and SSRF protection helpers.
 *
 * Because this product fetches arbitrary user-supplied URLs, the scan target is
 * itself an SSRF vector: a user could point the scanner at internal-only
 * infrastructure (cloud metadata endpoints, localhost admin panels, etc.).
 * `assertSafeScanTarget` normalizes the URL and (unless explicitly allowed)
 * rejects targets that resolve to private address space.
 */

const MAX_URL_LENGTH = 2048;
const MAX_EMAIL_LENGTH = 254;
// Pragmatic email shape check — full RFC 5322 validation is intentionally avoided.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateEmail(raw: unknown): string {
  if (typeof raw !== 'string') {
    throw new HttpError(400, 'A valid email address is required.');
  }
  const email = raw.trim().toLowerCase();
  if (email.length === 0 || email.length > MAX_EMAIL_LENGTH || !EMAIL_RE.test(email)) {
    throw new HttpError(400, 'A valid email address is required.');
  }
  return email;
}

/** Validate, normalize, and return a target URL string (adds https:// if missing). */
export function normalizeTargetUrl(raw: unknown): string {
  if (typeof raw !== 'string' || raw.trim() === '') {
    throw new HttpError(400, 'Target URL is required.');
  }
  let value = raw.trim();
  if (value.length > MAX_URL_LENGTH) {
    throw new HttpError(400, 'Target URL is too long.');
  }
  // Detect an explicit scheme. Reject anything that isn't http/https rather
  // than blindly prepending https:// (which would mangle e.g. "ftp://host").
  const schemeMatch = value.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      throw new HttpError(400, 'Only http and https targets are supported.');
    }
  } else if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
    // Scheme-like prefix without "//" (e.g. "javascript:", "file:") — reject.
    throw new HttpError(400, 'Only http and https targets are supported.');
  } else {
    value = 'https://' + value;
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new HttpError(400, 'Target URL is malformed.');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new HttpError(400, 'Only http and https targets are supported.');
  }
  if (!parsed.hostname) {
    throw new HttpError(400, 'Target URL must include a hostname.');
  }
  return parsed.toString();
}

/** Generic non-empty string field validator with a length cap. */
export function requireString(raw: unknown, field: string, maxLength = 1024): string {
  if (typeof raw !== 'string' || raw.trim() === '') {
    throw new HttpError(400, `${field} is required.`);
  }
  if (raw.length > maxLength) {
    throw new HttpError(400, `${field} exceeds the maximum length of ${maxLength}.`);
  }
  return raw.trim();
}

/** Optional string with a length cap; returns undefined when absent. */
export function optionalString(raw: unknown, field: string, maxLength = 4096): string | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw !== 'string') {
    throw new HttpError(400, `${field} must be a string.`);
  }
  if (raw.length > maxLength) {
    throw new HttpError(400, `${field} exceeds the maximum length of ${maxLength}.`);
  }
  return raw;
}

/** True if an IP literal belongs to private / loopback / reserved ranges. */
export function isPrivateAddress(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // loopback
    if (a === 0) return true; // "this" network
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
    if (a >= 224) return true; // multicast / reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true; // loopback / unspecified
    if (lower.startsWith('fe80')) return true; // link-local
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local
    // IPv4-mapped IPv6, e.g. ::ffff:127.0.0.1
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/);
    if (mapped) return isPrivateAddress(mapped[1]);
    return false;
  }
  return false;
}

/**
 * Validate a scan target and guard against SSRF. Returns the normalized URL.
 * Throws HttpError(400) when the host resolves only to private address space
 * and private targets are not explicitly permitted.
 */
export async function assertSafeScanTarget(raw: unknown): Promise<string> {
  const url = normalizeTargetUrl(raw);
  if (config.scanner.allowPrivateTargets) return url;

  const hostname = new URL(url).hostname;

  // Block obvious localhost aliases without a DNS round-trip.
  if (/^(localhost|localhost\.localdomain)$/i.test(hostname)) {
    throw new HttpError(400, 'Scanning internal/loopback hosts is not permitted.');
  }

  // Hostname is already an IP literal.
  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) {
      throw new HttpError(400, 'Scanning private or reserved IP ranges is not permitted.');
    }
    return url;
  }

  // Resolve and reject if every resolved address is private (DNS-rebinding aware).
  try {
    const records = await dns.lookup(hostname, { all: true });
    if (records.length > 0 && records.every((r) => isPrivateAddress(r.address))) {
      throw new HttpError(400, 'Target resolves to a private or reserved address and cannot be scanned.');
    }
  } catch (err) {
    if (err instanceof HttpError) throw err;
    // Resolution failure is surfaced later by the scanner itself; allow through.
  }

  return url;
}
