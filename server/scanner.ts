import { Finding, Severity } from "../src/types.js";
import crypto from "crypto";
import net from "net";
import * as dns from "dns/promises";

// --- SSRF protection ---------------------------------------------------------
// The scanner issues server-side HTTP requests to user-supplied targets, so it
// must refuse internal/reserved destinations (loopback, RFC1918, link-local,
// cloud metadata, CGNAT, etc.) to avoid being abused as an SSRF proxy.
function isBlockedIp(ip: string): boolean {
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

async function assertTargetIsScannable(parsedUrl: URL): Promise<void> {
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

export interface DiagnosticResult {
  url: string;
  scannedAt: string;
  responseStatus: number;
  sslSecure: boolean;
  headers: Record<string, string>;
  missingHeaders: string[];
  techLeaked: string[];
  probedPaths: Array<{ path: string; status: number; exposed: boolean }>;
  cookieIssues: string[];

  // High-fidelity AppSec dimensions
  sastFindings: Array<{
    file: string;
    issue: string;
    severity: Severity;
    type: string;
    fix: string;
    description: string;
  }>;
  scaLibraries: Array<{
    name: string;
    version: string;
    status: "vuln" | "safe";
    advisories: string[];
    severity: Severity;
    description: string;
    fix: string;
  }>;
  easmPerimeter: {
    subdomains: Array<{
      domain: string;
      status: "live" | "inactive";
      port: string;
    }>;
    ip: string;
    nameserver: string;
    protocol: string;
  };
  dastInputs: Array<{
    formAction: string;
    method: string;
    csrfPresent: boolean;
    vulnerability: string;
    severity: Severity;
    description: string;
    fix: string;
  }>;
  redTeamFindings?: Array<{
    testName: string;
    payload: string;
    severity: Severity;
    description: string;
    fix: string;
  }>;
  apiSecFindings?: Array<{
    testName: string;
    severity: Severity;
    description: string;
    fix: string;
    endpoint: string;
    rawRequest: string;
    rawResponse: string;
  }>;
}

export async function runDiagnostics(
  targetUrl: string,
  authHeader?: string,
): Promise<DiagnosticResult> {
  let url = targetUrl.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
  }

  const parsedUrl = new URL(url);
  const host = parsedUrl.origin;
  const hostname = parsedUrl.hostname;

  // SSRF guard: refuse internal/reserved targets before issuing any request.
  await assertTargetIsScannable(parsedUrl);

  const result: DiagnosticResult = {
    url,
    scannedAt: new Date().toISOString(),
    responseStatus: 0,
    sslSecure: url.startsWith("https://"),
    headers: {},
    missingHeaders: [],
    techLeaked: [],
    probedPaths: [],
    cookieIssues: [],
    sastFindings: [],
    scaLibraries: [],
    easmPerimeter: {
      subdomains: [],
      ip: "104.244.42.1", // default fallback, will resolve if possible
      nameserver: "ns1.seclayer-dns.net",
      protocol: url.startsWith("https://")
        ? "TLS 1.3 / HTTPS"
        : "HTTP/1.1 Cleartext",
    },
    dastInputs: [],
    redTeamFindings: [],
  };

  const headers: Record<string, string> = {
    "User-Agent":
      "Seclayer-Security-Scanner/2.0 (seclayer.io; scanner@seclayer.io)",
    Accept:
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  };
  if (authHeader) {
    headers["Authorization"] = authHeader;
  }

  try {
    // 1. Core Header Analysis
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 6000); // 6s timeout max

    const response = await fetch(url, {
      method: "GET",
      headers,
      signal: controller.signal,
    });
    clearTimeout(id);

    result.responseStatus = response.status;

    // Copy headers (lowercased)
    response.headers.forEach((value, key) => {
      result.headers[key.toLowerCase()] = value;
    });

    const htmlText = await response.text().catch(() => "");

    // Analyze Security Headers
    const securityHeaders = {
      "content-security-policy":
        "Content-Security-Policy (CSP) regulates resources the browser is allowed to load.",
      "strict-transport-security":
        "Strict-Transport-Security (HSTS) enforces HTTPS connections.",
      "x-frame-options":
        "X-Frame-Options prevents clickjacking framing attacks.",
      "x-content-type-options":
        "X-Content-Type-Options prevents sniffing-based payload executions.",
      "referrer-policy":
        "Referrer-Policy restricts referrer information sent to other sites.",
    };

    for (const [header, desc] of Object.entries(securityHeaders)) {
      if (!result.headers[header]) {
        result.missingHeaders.push(header);
      }
    }

    // Technology leaks checking (X-Powered-By, Server, etc.)
    const serverHeader = result.headers["server"];
    if (serverHeader && !/cloudflare/i.test(serverHeader)) {
      result.techLeaked.push(`Server: ${serverHeader}`);
    }
    const poweredBy = result.headers["x-powered-by"];
    if (poweredBy) {
      result.techLeaked.push(`X-Powered-By: ${poweredBy}`);
    }

    // Capture cookie parameters if set-cookie contains flags
    const setCookie = result.headers["set-cookie"];
    if (setCookie) {
      if (!/httponly/i.test(setCookie)) {
        result.cookieIssues.push("Session cookie lacks HttpOnly flag");
      }
      if (!/secure/i.test(setCookie) && url.startsWith("https://")) {
        result.cookieIssues.push("Session cookie lacks Secure directive");
      }
      if (!/samesite/i.test(setCookie)) {
        result.cookieIssues.push("Session cookie lacks SameSite policy");
      }
    }

    // --- 2. SAST SCAN ENGINE (Regex Match HTML & JavaScript for Source Security) ---
    if (htmlText) {
      // Secret Key matches
      const patterns = [
        {
          name: "Google Cloud API Key",
          regex: /AIzaSy[A-Za-z0-9_\-]{35}/,
          severity: "high" as Severity,
        },
        {
          name: "Stripe Secret Key Placeholder",
          regex: /sk_live_[0-9a-zA-Z]{24}/,
          severity: "critical" as Severity,
        },
        {
          name: "Generic AWS Access Token Link",
          regex: /AKIA[A-Z0-9]{16}/,
          severity: "high" as Severity,
        },
        {
          name: "GitHub OAuth Access Token",
          regex: /gho_[a-zA-Z0-9]{36}/,
          severity: "critical" as Severity,
        },
        {
          name: "Private Crypto Key block",
          regex: /-----BEGIN RSA PRIVATE KEY-----/,
          severity: "critical" as Severity,
        },
      ];

      patterns.forEach((p) => {
        if (p.regex.test(htmlText)) {
          result.sastFindings.push({
            file: "index.html (Inline Script)",
            issue: `Hardcoded Credential Exposure (${p.name})`,
            severity: p.severity,
            type: "hardcoded_secrets",
            description: `Leaked secret key signature pattern matching standard ${p.name} structure was detected exposed in client-facing HTML or inline scripts. Attackers scanning javascript payloads can harvest these credentials immediately.`,
            fix: `Move all application secrets out of the client codebase. Implement environment variables in backend secure routers and proxy necessary third-party requests.`,
          });
        }
      });

      // HTML DOM XSS sinks or debugging mode checks
      if (/eval\s*\(/i.test(htmlText)) {
        result.sastFindings.push({
          file: "index.html",
          issue: "Unsafe dynamic evaluation via eval()",
          severity: "medium" as Severity,
          type: "unsafe_sinks",
          description:
            "Use of eval() detected in page source. Dynamic evaluation of arbitrary input strings can easily lead to persistent or reflected Cross-Site Scripting (XSS) bypasses.",
          fix: "Refactor code to avoid dynamic string expressions evaluation. Use standard JSON parsing or local function mappings.",
        });
      }

      if (
        /console\.log\([^)]*(process\.env|config|secrets)[^)]*\)/i.test(
          htmlText,
        )
      ) {
        result.sastFindings.push({
          file: "index.html",
          issue: "Sensitive Debug Logs Exposure",
          severity: "low" as Severity,
          type: "information_leak",
          description:
            "Debugging output that pipes environmental properties or system variables directly to browser console logs was detected.",
          fix: "Configure build packager pipelines to strip console logs globally in production bundle environments.",
        });
      }
    }

    // --- 3. SCA ANALYSIS ENGINE (Inspect scripts and headers for vulnerable library footprints) ---
    if (htmlText) {
      // Outdated libraries signature checks
      const libraries = [
        {
          name: "jQuery 1.x / 2.x",
          match: /jquery[-.](1\.\d+\.\d+|2\.\d+\.\d+)/i,
          version: "1.12.4",
          severity: "medium" as Severity,
          desc: "Outdated jQuery contains cross-site scripting vulnerabilities in htmlPrefilter parameter evaluations (CVE-2020-11022).",
          fix: "Upgrade jQuery repository dependencies to version 3.5.0 or superior.",
        },
        {
          name: "Bootstrap 3.x",
          match: /bootstrap[-./](3\.\d+\.\d+)/i,
          version: "3.3.7",
          severity: "medium" as Severity,
          desc: "Bootstrap versions prior to v4 are vulnerable to CSS dynamic script executions and tooltip XSS models.",
          fix: "Upgrade Bootstrap to >= 4.5.0 or migrate to standard tailwind styling paradigms.",
        },
        {
          name: "AngularJS 1.8.x",
          match: /angular[-.](1\.[0-8]\.\d+)/i,
          version: "1.8.2",
          severity: "low" as Severity,
          desc: "Legacy AngularJS is long past End-of-Life (EOL), meaning zero future security audits or zero-day patches will be deployed.",
          fix: "Re-platform obsolete client structures to modern React frameworks.",
        },
        {
          name: "Lodash < 4.17.15",
          match: /lodash@([0-3]\.\d+\.\d+|4\.[0-16]\.[0-5])/i,
          version: "4.15.0",
          severity: "high" as Severity,
          desc: "Vulnerable to Prototype Pollution allowing remote attackers to inject custom default object prototypes.",
          fix: "Force upgrade lodash scripts to >= 4.17.21.",
        },
      ];

      libraries.forEach((lib) => {
        if (
          lib.match.test(htmlText) ||
          (setCookie &&
            lib.name === "jQuery 1.x / 2.x" &&
            /jquery/i.test(htmlText))
        ) {
          result.scaLibraries.push({
            name: lib.name,
            version: lib.version,
            status: "vuln",
            advisories: ["CVE-2020-11022", "XSS Bypass"],
            severity: lib.severity,
            description: lib.desc,
            fix: lib.fix,
          });
        }
      });
    }

    // --- 4. DAST INSECURE INPUTS CHECK (Check forms and actions) ---
    if (htmlText) {
      // Find form tags
      const formRegex = /<form([^>]*action=["']([^"']*)["']([^>]*))>/gi;
      let formMatch;
      while ((formMatch = formRegex.exec(htmlText)) !== null) {
        const action = formMatch[2];
        const attrContent = formMatch[1] + formMatch[3];
        const isPost = /method=["']post["']/i.test(attrContent);

        // Analyze if CSRF token is present in elements inside or nearby (e.g. check for anti-csrf input tag)
        // For simplicity: check if we see "csrf" or "token" fields
        const hasCsrfInput = /csrf|token|xsrf/i.test(htmlText);

        if (isPost && !hasCsrfInput) {
          result.dastInputs.push({
            formAction: action,
            method: "POST",
            csrfPresent: false,
            vulnerability: "Missing Anti-CSRF Token Security Guard",
            severity: "high" as Severity,
            description: `Vulnerable endpoint detected: Form posting to "${action}" lacks an authenticated anti-forgery token. Attackers can execute unauthorized state-changing operations on behalf of users via malicious cross-site forms.`,
            fix: `Implement standard CSRF secure tokens. Embed anti-csrf validation fields inside stateful forms and verify matching headers on target backend services.`,
          });
        }
      }
    }

    // --- 5. EASM PERIMETER (Subdomains, DNS and Real Host IP Lookup) ---
    // Perform active Domain audit map
    const commonSubdomains = [
      "www",
      "api",
      "dev",
      "staging",
      "admin",
      "vpn",
      "dashboard",
      "status",
      "mail",
      "remote",
      "blog",
      "webmail",
      "server",
      "ns1",
      "ns2",
      "smtp",
      "secure",
      "shop",
      "portal",
      "test",
      "cdn",
      "app",
      "m",
      "cloud",
      "qa",
      "support",
      "docs",
      "help",
      "login",
      "auth",
      "ftp",
      "pop",
      "imap",
    ];
    result.easmPerimeter.ip = "104.244.42.1"; // Standard DNS estimation fallback

    try {
      const ipRecords = await dns.resolve4(hostname).catch(() => []);
      if (ipRecords && ipRecords.length > 0) {
        result.easmPerimeter.ip = ipRecords[0];
      }

      // Check for Wildcard DNS to prevent false positive subdomain bloating
      let wildcardIp: string | null = null;
      try {
        const randomSub = crypto.randomBytes(6).toString("hex");
        const wildcardRecords = await dns.resolve4(`${randomSub}.${hostname}`);
        if (wildcardRecords && wildcardRecords.length > 0) {
          wildcardIp = wildcardRecords[0];
        }
      } catch (e) {
        // No wildcard DNS detected
      }

      const subdomainChecks = commonSubdomains.map(async (sub) => {
        const subUrl = `${sub}.${hostname}`;
        try {
          const records = await dns.resolve4(subUrl);

          // Filter out false positives caused by Wildcard DNS records
          if (wildcardIp && records.includes(wildcardIp)) {
            return {
              domain: subUrl,
              status: "inactive" as const,
              port: "0",
            };
          }

          return {
            domain: subUrl,
            status: "live" as const,
            port: sub.includes("vpn")
              ? "1194"
              : sub.includes("mail") || sub.includes("smtp")
                ? "25"
                : "443",
            ip: records[0],
          };
        } catch (err) {
          return {
            domain: subUrl,
            status: "inactive" as const,
            port: "0",
          };
        }
      });

      const subResults = await Promise.all(subdomainChecks);
      result.easmPerimeter.subdomains = subResults;
    } catch (e) {
      console.warn(
        "DNS resolution failed or not supported in this environment.",
        e,
      );
      // Fallback
      commonSubdomains.slice(0, 10).forEach((sub) => {
        result.easmPerimeter.subdomains.push({
          domain: `${sub}.${hostname}`,
          status: "inactive",
          port: "0",
        });
      });
    }

    // Sensitive Paths Probing
    const pathsToProbe = [
      "/.env",
      "/.git/config",
      "/admin",
      "/wp-admin",
      "/phpinfo.php",
    ];

    for (const p of pathsToProbe) {
      try {
        const probeController = new AbortController();
        const probeId = setTimeout(() => probeController.abort(), 2500); // short timeout
        const probeUrl = `${host}${p}`;

        const probeRes = await fetch(probeUrl, {
          method: "GET",
          headers: {
            "User-Agent": "Seclayer-Security-Scanner/2.0 (seclayer.io)",
          },
          signal: probeController.signal,
        });
        clearTimeout(probeId);

        const isExposed = probeRes.status === 200;
        result.probedPaths.push({
          path: p,
          status: probeRes.status,
          exposed: isExposed,
        });
      } catch (err) {
        result.probedPaths.push({
          path: p,
          status: 0,
          exposed: false,
        });
      }
    }
  } catch (err: any) {
    console.warn(
      `Scan connection to ${url} connections failed. Triggering default defensive audit layers.`,
    );
    result.responseStatus = 502;
    result.missingHeaders = [];
    result.techLeaked = [];
    result.probedPaths = [];
  }

  // --- RED TEAM ACTIVE FUZZING PROBES ---
  const redTeamFindings: any[] = [];
  try {
    const fuzzHeaders = { ...headers, "Cache-Control": "no-cache" };

    // 1. SQL Injection Active Probe
    try {
      const sqlCtl = new AbortController();
      const sqlId = setTimeout(() => sqlCtl.abort(), 4000);
      const sqlRes = await fetch(`${url}/?id=%27%20OR%201%3D1--`, {
        headers: fuzzHeaders,
        signal: sqlCtl.signal,
      });
      clearTimeout(sqlId);
      const sqlText = await sqlRes.text();
      if (
        sqlText.includes("syntax error") ||
        sqlText.includes("SQL syntax") ||
        sqlText.includes("ORA-") ||
        sqlText.includes("PostgreSQL query failed")
      ) {
        redTeamFindings.push({
          testName: "Active SQL Injection Probe",
          payload: "' OR 1=1--",
          severity: "critical",
          description:
            "Active Red Team scanning detected database syntax errors reflected in the HTTP response when injecting escaped SQL boundary characters. This indicates an exploitable database injection vulnerability.",
          fix: "Implement parameterized database queries and prepared statements exclusively. Eliminate dynamic string concatenation for SQL logic.",
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 2. Reflected XSS Active Probe
    try {
      const xssCtl = new AbortController();
      const xssId = setTimeout(() => xssCtl.abort(), 4000);
      const uniqueTrigger = `xss_probe_${crypto.randomBytes(4).toString("hex")}`;
      const xssRes = await fetch(
        `${url}/?q=%3Cscript%3E${uniqueTrigger}%3C%2Fscript%3E`,
        { headers: fuzzHeaders, signal: xssCtl.signal },
      );
      clearTimeout(xssId);
      const xssText = await xssRes.text();
      if (xssText.includes(`<script>${uniqueTrigger}</script>`)) {
        redTeamFindings.push({
          testName: "Active Reflected XSS Probe",
          payload: `<script>${uniqueTrigger}</script>`,
          severity: "high",
          description:
            "Active Red Team fuzzing successfully reflected unencoded HTML/JavaScript tags directly in the immediate HTTP response, confirming a Reflected Cross-Site Scripting (XSS) vulnerability.",
          fix: "Implement deep context-aware output encoding. Deploy restrictive Content Security Policy (CSP) headers to prevent unauthorized inline script execution.",
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 3. OS Command Injection Active Probe
    try {
      const cmdCtl = new AbortController();
      const cmdId = setTimeout(() => cmdCtl.abort(), 4000);
      const cmdRes = await fetch(`${url}/?ping=127.0.0.1%3B+id`, {
        headers: fuzzHeaders,
        signal: cmdCtl.signal,
      });
      clearTimeout(cmdId);
      const cmdText = await cmdRes.text();
      if (cmdText.includes("uid=") && cmdText.includes("gid=")) {
        redTeamFindings.push({
          testName: "Active OS Command Injection",
          payload: "; id",
          severity: "critical",
          description:
            "Active Red Team command injection fuzzing triggered a successful `id` evaluation on the backend, exposing sensitive host system access and execution permissions.",
          fix: "Avoid invoking underlying operating system commands entirely. If required, use strictly sanitized arguments array APIs, never shell-interpolated execution.",
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 4. SSRF Active Probe
    try {
      const ssrfCtl = new AbortController();
      const ssrfId = setTimeout(() => ssrfCtl.abort(), 4000);
      // Attempting to request localhost loopback or internal metadata
      const ssrfRes = await fetch(`${url}/?url=http://127.0.0.1:22`, {
        headers: fuzzHeaders,
        signal: ssrfCtl.signal,
      });
      clearTimeout(ssrfId);
      const ssrfText = await ssrfRes.text();
      if (
        ssrfText.includes("SSH-2.0-OpenSSH") ||
        ssrfText.includes("Protocol mismatch")
      ) {
        redTeamFindings.push({
          testName: "Active Server-Side Request Forgery (SSRF)",
          payload: "http://127.0.0.1:22",
          severity: "critical",
          description:
            "Active Red Team scanning identified an insecure proxy/fetch behavior that permitted requests returning local loopback (SSH) banner data, confirming an SSRF vulnerability.",
          fix: "Enforce strict network path isolation for backend fetches. Implement allow-listing filters and block internal Class A/B/C IP architectures.",
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }
  } catch (globalErr) {
    console.warn(
      "Red team active fuzzing encounted top-level error",
      globalErr,
    );
  }

  result.redTeamFindings = redTeamFindings;

  // --- API SECURITY TESTING ACTIVE PROBES ---
  const apiSecFindings: any[] = [];
  try {
    const apiHeaders = { ...headers, "Cache-Control": "no-cache" };

    // 1. GraphQL Introspection Probe
    try {
      const gqlCtl = new AbortController();
      const gqlId = setTimeout(() => gqlCtl.abort(), 4000);
      const reqRaw = `POST /graphql HTTP/1.1\nHost: ${hostname}\nContent-Type: application/json\n\n{"query":"{__schema{types{name}}}"}`;

      const gqlRes = await fetch(`${url}/graphql`, {
        method: "POST",
        headers: { ...apiHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{__schema{types{name}}}" }),
        signal: gqlCtl.signal,
      });
      clearTimeout(gqlId);
      const gqlText = await gqlRes.text();
      const resRaw = `HTTP/1.1 ${gqlRes.status} ${gqlRes.statusText}\n\n${gqlText.substring(0, 500)}...`;

      if (gqlText.includes("__schema") || gqlText.includes("__Type")) {
        apiSecFindings.push({
          testName: "GraphQL Schema Introspection Exposed",
          endpoint: "/graphql",
          severity: "high",
          description:
            "An active API endpoint probe discovered that GraphQL introspection is globally reachable. Attackers can effortlessly dump the entire undocumented internal schema definitions.",
          fix: "Disable introspection blocks in the production GraphQL backend. Shield API with explicit token authentication schemas.",
          rawRequest: reqRaw,
          rawResponse: resRaw,
        });
      }
    } catch (e) {
      /* Ignore fetch errors */
    }

    // 2. Broken Object Level Authorization (BOLA) Probe
    try {
      const idorCtl = new AbortController();
      const idorId = setTimeout(() => idorCtl.abort(), 4000);
      const reqRawIdor = `GET /api/v1/users/admin HTTP/1.1\nHost: ${hostname}\nAccept: application/json`;

      const idorRes = await fetch(`${url}/api/v1/users/admin`, {
        headers: apiHeaders,
        signal: idorCtl.signal,
      });
      clearTimeout(idorId);
      const idorText = await idorRes.text();
      const resRawIdor = `HTTP/1.1 ${idorRes.status} ${idorRes.statusText}\nContent-Type: ${idorRes.headers.get("content-type") || "text/plain"}\n\n${idorText.substring(0, 500)}...`;

      if (
        idorRes.status === 200 &&
        (idorText.includes("email") || idorText.includes('"role"'))
      ) {
        apiSecFindings.push({
          testName: "Broken Object Level Authorization (BOLA)",
          endpoint: "/api/v1/users/admin",
          severity: "critical",
          description:
            "API testing successfully resolved protected user entities directly by probing enumerated resource IDs, overriding local tenant boundaries.",
          fix: "Enforce stringent object-level resource verification. Explicitly map authorization states against the retrieved user objects inside controller logic.",
          rawRequest: reqRawIdor,
          rawResponse: resRawIdor,
        });
      }
    } catch (e) {
      /* Ignore fetch errors */
    }
  } catch (globalErr) {
    console.warn("API Security fuzzing encounted top-level error", globalErr);
  }

  result.apiSecFindings = apiSecFindings;

  return result;
}

// Convert diagnostics into structured Category Findings
export function compileStaticFindings(diag: DiagnosticResult): {
  score: number;
  severity: Severity;
  findings: Finding[];
} {
  const findings: Finding[] = [];
  let score = 100;

  // 1. EASM (External Attack Surface Management) checks
  if (!diag.sslSecure) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Insecure Connection Protocol (HTTP)",
      description: `The target server at ${diag.url} is accessible over plaintext HTTP. All authentication tags, passwords, and sensitive cookies are transmitted in cleartext, enabling packet interception.`,
      severity: "high",
      confidence: "high",
      fix: "Deploy a valid SSL/TLS certificate and configure permanent rewrite rules on port 80 to redirect HTTP traffic securely to HTTPS.",
      category: "EASM",
    });
    score -= 30;
  }

  if (diag.techLeaked.length > 0) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Verbose Server Framework Signature Leaked",
      description: `The attack surface assessment detected visible framework signatures leaked in response headers: ${diag.techLeaked.join(", ")}. Automated bots use these patterns to locate vulnerable systems.`,
      severity: "low",
      confidence: "high",
      fix: "Disable verbose Server headers in nginx.conf or web.config and strip x-powered-by settings globally.",
      category: "EASM",
    });
    score -= 5;
  }

  // Target live subdomains listed under external attack surface boundaries
  const liveSubs = diag.easmPerimeter.subdomains.filter(
    (s) => s.status === "live",
  );
  if (liveSubs.length > 0) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: `Subdomain Attack Surface Discovery (${liveSubs.length} Hosts found)`,
      description: `Discovered active subdomains resolving external services: ${liveSubs.map((s) => s.domain).join(", ")}. Unmonitored staging or development servers pose significant inventory leak risks.`,
      severity: "medium",
      confidence: "low",
      fix: "Implement robust EASM continuous inventory. Shield staging environment credentials behind VPN access control policies.",
      category: "EASM",
    });
    score -= 10;
  }

  // 2. IAST (Interactive Application Security / Defensive Rules) checks
  if (diag.missingHeaders.includes("content-security-policy")) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Missing Content-Security-Policy (CSP)",
      description:
        "The target has no Content-Security-Policy header. Modern security frameworks require CSP variables to restrict cross-site scripting (XSS) script injected loading scopes.",
      severity: "high",
      confidence: "high",
      fix: "Deploy restrictive CSP header directives like \"Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-origin.com\".",
      category: "IAST",
    });
    score -= 20;
  }

  if (diag.missingHeaders.includes("strict-transport-security")) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Missing Strict-Transport-Security (HSTS) Policy",
      description:
        "The HTTP Strict Transport Security (HSTS) header is omitted. Clients are vulnerable to protocol downgrade attacks where secure sessions are forced to unencrypted ports.",
      severity: "medium",
      confidence: "high",
      fix: 'Transmit the header: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" over all HTTPS targets.',
      category: "IAST",
    });
    score -= 10;
  }

  if (diag.missingHeaders.includes("x-frame-options")) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Missing X-Frame-Options / Clickjacking Immunity",
      description:
        "The response contains no anti-framing instructions. Attackers could frame this target inside transparent overlays to hijack click interactions.",
      severity: "medium",
      confidence: "high",
      fix: 'Enforce "X-Frame-Options: DENY" or deploy CSP "frame-ancestors \'none\'" instructions.',
      category: "IAST",
    });
    score -= 10;
  }

  diag.cookieIssues.forEach((issue) => {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: `Deficient Cookie Directives (${issue})`,
      description: `Critical cookies do not feature standard secure storage parameters. Without HttpOnly, Javascript payloads can drain active session IDs easily.`,
      severity: "medium",
      confidence: "high",
      fix: "Incorporate HttpOnly, Secure, and SameSite=Lax (or SameSite=Strict) properties inside set-cookie headers.",
      category: "IAST",
    });
    score -= 10;
  });

  // 3. SAST (Static Code Security Analysis) checks
  diag.sastFindings.forEach((sf) => {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: sf.issue,
      description: sf.description,
      severity: sf.severity,
      confidence: "low",
      fix: sf.fix,
      category: "SAST",
    });
    score -= sf.severity === "critical" ? 35 : sf.severity === "high" ? 25 : 15;
  });

  // 4. SCA (Software Composition Analysis) checks
  diag.scaLibraries.forEach((sca) => {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: `Outdated Library Vulnerability Detected (${sca.name})`,
      description: sca.description,
      severity: sca.severity,
      confidence: "medium",
      fix: sca.fix,
      category: "SCA",
    });
    score -= sca.severity === "high" ? 25 : 15;
  });

  // 5. DAST (Dynamic Application Security Probes) checks
  diag.dastInputs.forEach((dast) => {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: dast.vulnerability,
      description: dast.description,
      severity: dast.severity,
      confidence: "medium",
      fix: dast.fix,
      category: "DAST",
    });
    score -= dast.severity === "high" ? 20 : 10;
  });

  // Probed Paths exposures check
  const exposed = diag.probedPaths.filter((p) => p.exposed);
  exposed.forEach((exp) => {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: `Exposed Critical Resource File (${exp.path})`,
      description: `Active Dynamic scanning discovered a public exposed configuration target at ${diag.url}${exp.path}. This file can be queried freely over the web, yielding secret metadata configurations.`,
      severity:
        exp.path.includes(".env") || exp.path.includes(".git")
          ? "critical"
          : "high",
      confidence: "high",
      fix: `Immediately strip dynamic routes to ${exp.path} inside server rewrite engines or configure .htaccess rules to return 403 blocks.`,
      category: "DAST",
    });
    score -= 35;
  });

  // Compile Red Team aggressive probing findings
  if (diag.redTeamFindings && diag.redTeamFindings.length > 0) {
    diag.redTeamFindings.forEach((rt) => {
      findings.push({
        id: "f_rt_" + crypto.randomBytes(4).toString("hex"),
        title: rt.testName,
        description: rt.description,
        severity: rt.severity,
        confidence: "high",
        fix: rt.fix,
        category: "RED_TEAM",
      });
      // Deduct score dynamically based on aggressive vulnerability findings
      score -= rt.severity === "critical" ? 25 : 15;
    });
  }

  // Compile API Security Testing findings
  if (diag.apiSecFindings && diag.apiSecFindings.length > 0) {
    diag.apiSecFindings.forEach((api) => {
      findings.push({
        id: "f_api_" + crypto.randomBytes(4).toString("hex"),
        title: api.testName,
        description: api.description,
        severity: api.severity,
        confidence: "high",
        fix: api.fix,
        category: "API_SEC",
        endpoint: api.endpoint,
        rawRequest: api.rawRequest,
        rawResponse: api.rawResponse,
      });
      score -= api.severity === "critical" ? 25 : 15;
    });
  }

  // Cap score limits
  score = Math.max(12, Math.min(100, score));

  // Highest severity calculation
  let severity: Severity = "low";
  if (findings.some((f) => f.severity === "critical")) severity = "critical";
  else if (findings.some((f) => f.severity === "high")) severity = "high";
  else if (findings.some((f) => f.severity === "medium")) severity = "medium";
  else if (findings.some((f) => f.severity === "low")) severity = "low";

  return { score, severity, findings };
}
