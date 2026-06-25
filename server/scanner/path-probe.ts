import crypto from "crypto";
import { DiagnosticResult } from "./diagnostic-types.js";

/**
 * Sensitive paths probed during EASM recon. A bare HTTP 200 is NOT sufficient
 * proof of exposure: many modern sites (SPAs, catch-all routers, custom error
 * pages) return 200 with their app shell for ANY path, which would otherwise
 * flag /wp-admin, /actuator, etc. as "exposed" on sites that don't run them.
 *
 * To keep false positives low while preserving real detections we:
 *   1. Establish a soft-200 baseline by probing a random, definitely-absent
 *      path. If the server answers it with 200, it catch-all routes everything.
 *   2. For high-value paths we additionally require a positive CONTENT
 *      signature (the response actually looks like the sensitive resource),
 *      so a real .env / .git / actuator / swagger / SQL dump is still caught
 *      even on a catch-all server, and an HTML app-shell never is.
 *
 * This mirrors the wildcard-DNS false-positive guard already used for
 * subdomain enumeration in easm-recon.ts.
 */
const pathsToProbe = [
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.git/config",
  "/.git/HEAD",
  "/admin",
  "/wp-admin",
  "/phpinfo.php",
  "/server-status",
  "/actuator",
  "/actuator/env",
  "/swagger.json",
  "/openapi.json",
  "/api-docs",
  "/config.php",
  "/backup.sql",
  "/dump.sql",
];

const isHtml = (body: string, ct: string) =>
  ct.includes("text/html") || /^\s*<(?:!doctype|html)\b/i.test(body);

/**
 * Per-path content signatures. A signature returning true means the response
 * body genuinely is the sensitive resource (not a generic page). Paths without
 * a signature fall back to the catch-all heuristic only.
 */
const SIGNATURES: Record<string, (body: string, ct: string) => boolean> = {
  "/.env": (b, ct) => !isHtml(b, ct) && /^[A-Za-z_][A-Za-z0-9_]*=/m.test(b),
  "/.env.local": (b, ct) => !isHtml(b, ct) && /^[A-Za-z_][A-Za-z0-9_]*=/m.test(b),
  "/.env.production": (b, ct) => !isHtml(b, ct) && /^[A-Za-z_][A-Za-z0-9_]*=/m.test(b),
  "/.git/config": (b) => /\[core\]|repositoryformatversion/i.test(b),
  "/.git/HEAD": (b, ct) => !isHtml(b, ct) && /^ref:\s+refs\//m.test(b),
  // Require genuine WordPress login markers, not the reflected path string —
  // e.g. github.com/wp-admin is a user profile that echoes "wp-admin" in meta tags.
  "/wp-admin": (b) => /wp-login\.php|wp-submit|id=["']loginform["']|\/wp-(?:includes|content)\/|name=["']log["'][^>]*>\s*<[^>]*name=["']pwd["']/i.test(b),
  "/phpinfo.php": (b) => /phpinfo\(\)|<title>phpinfo\(\)|PHP Version/i.test(b),
  "/server-status": (b) => /Apache Server Status|mod_status|Server uptime/i.test(b),
  "/actuator": (b) => /"_links"|"(health|env|metrics|beans|mappings)"\s*:/i.test(b),
  "/actuator/env": (b) => /"propertySources"|"activeProfiles"|"_links"/i.test(b),
  "/swagger.json": (b) => /"swagger"\s*:|"openapi"\s*:|"paths"\s*:/i.test(b),
  "/openapi.json": (b) => /"swagger"\s*:|"openapi"\s*:|"paths"\s*:/i.test(b),
  // Match the spec/UI itself, not bare words that a profile page might mention.
  "/api-docs": (b) => /"openapi"\s*:|"swagger"\s*:|"paths"\s*:|swagger-ui|SwaggerUIBundle|redoc\.standalone|<redoc/i.test(b),
  "/config.php": (b) => /<\?php/.test(b),
  "/backup.sql": (b) => /(CREATE TABLE|INSERT INTO|DROP TABLE|MySQL dump|PostgreSQL database dump)/i.test(b),
  "/dump.sql": (b) => /(CREATE TABLE|INSERT INTO|DROP TABLE|MySQL dump|PostgreSQL database dump)/i.test(b),
};

const MAX_BODY = 65536; // cap body read used for signature matching

async function fetchProbe(
  url: string,
): Promise<{ status: number; body: string; contentType: string } | null> {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), 2500); // short timeout
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "User-Agent": "Seclayer-Security-Scanner/2.0 (seclayer.io)" },
      signal: ctrl.signal,
    });
    const contentType = res.headers.get("content-type") || "";
    let body = "";
    try {
      body = (await res.text()).slice(0, MAX_BODY);
    } catch {
      /* body unavailable — signature checks simply won't match */
    }
    return { status: res.status, body, contentType };
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

/**
 * Probe each sensitive path against the live target and decide real exposure.
 * Returns the same {path, status, exposed} shape consumed by compileStaticFindings.
 */
export async function probeSensitivePaths(
  host: string,
): Promise<DiagnosticResult["probedPaths"]> {
  // 1. Soft-200 baseline: a random path that should never exist.
  const randomPath = `/seclayer-probe-${crypto.randomBytes(8).toString("hex")}`;
  const baseline = await fetchProbe(`${host}${randomPath}`);
  const catchAll = baseline?.status === 200;

  const probedPaths: DiagnosticResult["probedPaths"] = [];

  for (const p of pathsToProbe) {
    const r = await fetchProbe(`${host}${p}`);
    if (!r) {
      probedPaths.push({ path: p, status: 0, exposed: false });
      continue;
    }

    let exposed = false;
    if (r.status === 200) {
      const sig = SIGNATURES[p];
      if (sig) {
        // High-value path: trust only a positive content signature, so this
        // holds up even when the server catch-all routes to 200.
        exposed = sig(r.body, r.contentType);
      } else {
        // No signature (e.g. /admin): a 200 is meaningful only if the server
        // returns proper not-found responses for absent paths.
        exposed = !catchAll;
      }
    }

    probedPaths.push({ path: p, status: r.status, exposed });
  }

  return probedPaths;
}
