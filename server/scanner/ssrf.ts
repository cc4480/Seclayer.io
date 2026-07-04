import net from "net";
import * as dns from "dns/promises";

// --- SSRF protection ---------------------------------------------------------
// The scanner issues server-side HTTP requests to user-supplied targets, so it
// must refuse internal/reserved destinations (loopback, RFC1918, link-local,
// cloud metadata, CGNAT, etc.) to avoid being abused as an SSRF proxy.
export function isBlockedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0) return true; // "this" network
    if (a === 127) return true; // loopback
    if (a === 10) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 169 && b === 254) return true; // link-local + cloud metadata
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::") return true; // loopback / unspecified
    if (lower.startsWith("fe80")) return true; // link-local
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/); // IPv4-mapped
    if (mapped) return isBlockedIp(mapped[1]);
    return false;
  }
  return true; // unrecognized format -> block
}

export async function assertTargetIsScannable(parsedUrl: URL): Promise<void> {
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error(
      `Unsupported protocol "${parsedUrl.protocol}". Only http(s) targets can be scanned.`,
    );
  }

  const hostname = parsedUrl.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  const lower = hostname.toLowerCase();

  // Block internal-only hostnames that may resolve via split-horizon DNS.
  if (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    lower.endsWith(".local") ||
    lower.endsWith(".internal")
  ) {
    throw new Error(`Refusing to scan internal hostname "${hostname}".`);
  }

  // Literal IP targets are validated directly.
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) {
      throw new Error(
        `Refusing to scan internal or reserved address "${hostname}".`,
      );
    }
    return;
  }

  // Otherwise resolve and validate every address the host maps to.
  const [v4, v6] = await Promise.all([
    dns.resolve4(hostname).catch(() => [] as string[]),
    dns.resolve6(hostname).catch(() => [] as string[]),
  ]);
  for (const ip of [...v4, ...v6]) {
    if (isBlockedIp(ip)) {
      throw new Error(
        `Target "${hostname}" resolves to a blocked internal address (${ip}); scan refused.`,
      );
    }
  }
}

// Public boundary check: validates a raw target string the same way
// runDiagnostics normalizes it, so callers can reject SSRF/malformed targets
// before spending credits or enqueuing work. Throws with a user-facing message.
export async function assertScanTargetSafe(targetUrl: string): Promise<void> {
  let url = (targetUrl || "").trim();
  if (!/^https?:\/\//i.test(url)) {
    // Reject explicit non-HTTP schemes (e.g. ftp://, file://, gopher://)
    // rather than silently coercing them into a bogus https host.
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
      throw new Error(
        `Unsupported protocol in "${targetUrl}". Only http(s) targets can be scanned.`,
      );
    }
    url = "https://" + url;
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`"${targetUrl}" is not a valid URL.`);
  }
  await assertTargetIsScannable(parsed);
}

// Follows redirects manually, re-validating every hop against the SSRF guard so
// a target cannot 30x-redirect the scanner into internal infrastructure.
export async function safeFetch(targetUrl: string, options: RequestInit, maxRedirects = 4): Promise<Response> {
  let current = targetUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    await assertTargetIsScannable(new URL(current));
    const res = await fetch(current, { ...options, redirect: "manual" });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (loc) {
        current = new URL(loc, current).toString();
        continue;
      }
    }
    return res;
  }
  throw new Error(`Exceeded ${maxRedirects} redirects while scanning ${targetUrl}`);
}
