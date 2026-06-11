import { Finding, Severity, ScanDiagnosticsSummary } from "../src/types.js";
import crypto from "crypto";
import {
  signature,
  buildBaseline,
  isPathGenuinelyExposed,
  isGraphqlIntrospection,
  isUserObjectLeak,
  isSqlInjectionEvidence,
  isCommandInjectionEvidence,
  isSsrfEvidence,
  type SoftNotFoundBaseline,
} from "./scan-calibration.js";
import {
  buildPoc,
  revalidate,
  renderPocArtifact,
  type PocAttempt,
  type PocRequest,
  type ValidatedExploit,
} from "./exploit-validation.js";
import { crawl as crawlSite } from "./crawler.js";
import { detectStoredXss, detectIdor } from "./chain-detectors.js";
import { runParamFuzzing } from "./param-fuzzer.js";

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
      ip?: string;
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
    rawRequest?: string;
    rawResponse?: string;
    validated?: boolean;
  }>;
  apiSecFindings?: Array<{
    testName: string;
    severity: Severity;
    description: string;
    fix: string;
    endpoint: string;
    rawRequest: string;
    rawResponse: string;
    validated?: boolean;
  }>;
  /** Bounded, re-confirmed exploit proofs with reproducible PoC artifacts. */
  validatedExploits?: ValidatedExploit[];
  /** Multi-page crawl coverage summary. */
  crawl?: { pagesVisited: number; formsFound: number; idRefsFound: number };
}

/**
 * Phase 1: fetch the target, capture status/headers, and flag missing
 * security headers, leaked technology signatures, and cookie issues.
 * Returns the response body and raw set-cookie header for later phases.
 */
async function probeHeaders(
  url: string,
  headers: Record<string, string>,
  result: DiagnosticResult,
): Promise<{ htmlText: string; setCookie: string }> {
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
  // Only a Server header that discloses a *version* is a real information leak;
  // a bare product name ("nginx", "cloudflare") is not actionable and flagging
  // it produces noise/false positives.
  const serverHeader = result.headers["server"];
  if (serverHeader && /\d/.test(serverHeader) && !/cloudflare/i.test(serverHeader)) {
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

  return { htmlText, setCookie };
}

/** Phase 2: regex-scan HTML/inline scripts for hardcoded secrets and unsafe sinks. */
function runSastScan(htmlText: string, result: DiagnosticResult): void {
  if (!htmlText) return;

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

/** Phase 3: detect outdated/vulnerable client-side library signatures. */
function runScaScan(
  htmlText: string,
  setCookie: string,
  result: DiagnosticResult,
): void {
  if (!htmlText) return;

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
    // Flag only when the actual vulnerable version signature is present. (The
    // previous "page mentions jquery + sets a cookie" heuristic flagged any
    // jQuery version, including patched 3.x, as vulnerable — a false positive.)
    if (lib.match.test(htmlText)) {
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

/** Phase 4: inspect HTML forms for missing CSRF protections. */
function runDastAnalysis(htmlText: string, result: DiagnosticResult): void {
  if (!htmlText) return;

  let targetHost = "";
  try {
    targetHost = new URL(result.url).hostname;
  } catch {
    /* result.url should always parse; ignore */
  }

  // Match each <form>...</form> block so the CSRF-token check is scoped to the
  // individual form rather than the whole page (a token anywhere on the page no
  // longer masks an unprotected form, and vice-versa).
  const formBlockRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let formMatch;
  while ((formMatch = formBlockRegex.exec(htmlText)) !== null) {
    const attrs = formMatch[1] || "";
    const inner = formMatch[2] || "";
    const isPost = /method=["']?\s*post/i.test(attrs);
    if (!isPost) continue; // GET forms are not CSRF-state-changing

    const actionMatch = attrs.match(/action=["']([^"']*)["']/i);
    const action = actionMatch ? actionMatch[1] : "";

    // Skip forms that submit to a different origin — their CSRF posture is the
    // third party's responsibility, not this target's (a common false positive
    // for embedded search, payment, and SSO widgets).
    if (/^https?:\/\//i.test(action)) {
      try {
        if (new URL(action).hostname !== targetHost) continue;
      } catch {
        /* malformed action URL; fall through and evaluate it */
      }
    }

    // A CSRF defense can be a hidden token field or a framework-specific token
    // name inside this form. Only inspect this form's own markup.
    const formMarkup = attrs + inner;
    const hasCsrfToken =
      /name=["'][^"']*(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|nonce)[^"']*["']/i.test(
        formMarkup,
      ) || /csrf[-_]?token|xsrf[-_]?token/i.test(formMarkup);

    if (!hasCsrfToken) {
      result.dastInputs.push({
        formAction: action || "(same document)",
        method: "POST",
        csrfPresent: false,
        vulnerability: "Missing Anti-CSRF Token Security Guard",
        severity: "high" as Severity,
        description: `Vulnerable endpoint detected: Form posting to "${action || "the current document"}" lacks an authenticated anti-forgery token. Attackers can execute unauthorized state-changing operations on behalf of users via malicious cross-site forms.`,
        fix: `Implement standard CSRF secure tokens. Embed anti-csrf validation fields inside stateful forms and verify matching headers on target backend services.`,
      });
    }
  }
}

/** Phase 5: enumerate live subdomains via DNS and probe well-known sensitive paths. */
async function runEasmRecon(
  host: string,
  hostname: string,
  result: DiagnosticResult,
  baseline: SoftNotFoundBaseline,
): Promise<void> {
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
  try {
    // Need dynamic import to avoid altering the top-level imports significantly or we can just require it
    const dns = await import("dns/promises");

    const ipRecords = await dns.resolve4(hostname).catch(() => []);
    if (ipRecords && ipRecords.length > 0) {
      result.easmPerimeter.ip = ipRecords[0];
    }

    // Resolve the authoritative nameserver, when delegated for this hostname.
    try {
      const nsRecords = await dns.resolveNs(hostname);
      if (nsRecords && nsRecords.length > 0) {
        result.easmPerimeter.nameserver = nsRecords[0];
      }
    } catch {
      // No NS records delegated directly to this hostname; leave "unresolved".
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

      const probeBody = await probeRes.text().catch(() => "");
      // Calibrated check: a 200 alone is not exposure. The response must differ
      // from the soft-404/SPA baseline and (for known files) match the artifact.
      const isExposed = isPathGenuinelyExposed(p, probeRes.status, probeBody, baseline);
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
}

interface RedTeamProbeResult {
  findings: NonNullable<DiagnosticResult["redTeamFindings"]>;
  exploits: ValidatedExploit[];
}

/**
 * Phase 6: active fuzzing probes for SQLi, reflected XSS, command injection, and
 * SSRF. Each confirmed signal is re-issued once to confirm reproducibility and
 * captured as a bounded, reproducible PoC artifact.
 */
async function runRedTeamProbes(
  url: string,
  headers: Record<string, string>,
): Promise<RedTeamProbeResult> {
  const findings: NonNullable<DiagnosticResult["redTeamFindings"]> = [];
  const exploits: ValidatedExploit[] = [];
  try {
    const fuzzHeaders = { ...headers, "Cache-Control": "no-cache" };

    // Benign control response for the same parameter shape. Injection findings
    // are only reported when an error/output signature appears under the payload
    // that the control did NOT contain — eliminating pages that statically
    // include the signature strings (docs, tutorials, generic error templates).
    let controlText = "";
    try {
      const ctlCtl = new AbortController();
      const ctlId = setTimeout(() => ctlCtl.abort(), 4000);
      const ctlRes = await fetch(`${url}/?id=seclayer_control_1`, {
        headers: fuzzHeaders,
        signal: ctlCtl.signal,
      });
      clearTimeout(ctlId);
      controlText = await ctlRes.text().catch(() => "");
    } catch (e) {
      /* Control unavailable; injection checks below stay conservative. */
    }

    const xssTrigger = `xss_probe_${crypto.randomBytes(4).toString("hex")}`;

    // Each descriptor is a read-only probe. `matcher` returns true only when the
    // response exhibits the payload-dependent evidence signal.
    const descriptors: Array<{
      vector: string;
      endpoint: string;
      payload: string;
      path: string;
      severity: Severity;
      signal: string;
      description: string;
      fix: string;
      matcher: (body: string) => boolean;
    }> = [
      {
        vector: "Active SQL Injection Probe",
        endpoint: "/?id=",
        payload: "' OR 1=1--",
        path: "/?id=%27%20OR%201%3D1--",
        severity: "critical",
        signal: "Database error string present under injection but absent in the benign control",
        description:
          "Active Red Team scanning detected database syntax errors reflected in the HTTP response when injecting escaped SQL boundary characters. This indicates an exploitable database injection vulnerability.",
        fix: "Implement parameterized database queries and prepared statements exclusively. Eliminate dynamic string concatenation for SQL logic.",
        matcher: (body) => isSqlInjectionEvidence(body, controlText),
      },
      {
        vector: "Active Reflected XSS Probe",
        endpoint: "/?q=",
        payload: `<script>${xssTrigger}</script>`,
        path: `/?q=%3Cscript%3E${xssTrigger}%3C%2Fscript%3E`,
        severity: "high",
        signal: "Unique, unguessable script payload reflected unencoded in the response",
        description:
          "Active Red Team fuzzing successfully reflected unencoded HTML/JavaScript tags directly in the immediate HTTP response, confirming a Reflected Cross-Site Scripting (XSS) vulnerability.",
        fix: "Implement deep context-aware output encoding. Deploy restrictive Content Security Policy (CSP) headers to prevent unauthorized inline script execution.",
        matcher: (body) => body.includes(`<script>${xssTrigger}</script>`),
      },
      {
        vector: "Active OS Command Injection",
        endpoint: "/?ping=",
        payload: "127.0.0.1; id",
        path: "/?ping=127.0.0.1%3B+id",
        severity: "critical",
        signal: "`id` command output (uid=/gid=) present under injection but absent in the control",
        description:
          "Active Red Team command injection fuzzing triggered a successful `id` evaluation on the backend, exposing sensitive host system access and execution permissions.",
        fix: "Avoid invoking underlying operating system commands entirely. If required, use strictly sanitized arguments array APIs, never shell-interpolated execution.",
        matcher: (body) => isCommandInjectionEvidence(body, controlText),
      },
      {
        vector: "Active Server-Side Request Forgery (SSRF)",
        endpoint: "/?url=",
        payload: "http://127.0.0.1:22",
        path: "/?url=http://127.0.0.1:22",
        severity: "critical",
        signal: "Internal service (SSH) banner returned under injection but absent in the control",
        description:
          "Active Red Team scanning identified an insecure proxy/fetch behavior that permitted requests returning local loopback (SSH) banner data, confirming an SSRF vulnerability.",
        fix: "Enforce strict network path isolation for backend fetches. Implement allow-listing filters and block internal Class A/B/C IP architectures.",
        matcher: (body) => isSsrfEvidence(body, controlText),
      },
    ];

    for (const d of descriptors) {
      try {
        const reqUrl = `${url}${d.path}`;
        const req: PocRequest = {
          method: "GET",
          url: reqUrl,
          headers: fuzzHeaders,
          payload: d.payload,
        };

        const ctl = new AbortController();
        const id = setTimeout(() => ctl.abort(), 4000);
        const res = await fetch(reqUrl, { headers: fuzzHeaders, signal: ctl.signal });
        clearTimeout(id);
        const text = await res.text();
        if (!d.matcher(text)) continue;

        // Confirmed once during detection; re-issue once to confirm it reproduces.
        const attempt1: PocAttempt = { ok: true, status: res.status, matched: true };
        const attempt2 = await revalidate(req, d.matcher);

        const exploit = buildPoc({
          vector: d.vector,
          severity: d.severity,
          endpoint: d.endpoint,
          request: req,
          signal: d.signal,
          controlAbsent: true,
          responseBody: text,
          attempts: [attempt1, attempt2],
        });
        const art = renderPocArtifact(exploit);

        findings.push({
          testName: d.vector,
          payload: d.payload,
          severity: d.severity,
          description: d.description,
          fix: d.fix,
          rawRequest: art.rawRequest,
          rawResponse: art.rawResponse,
          validated: exploit.validationStatus === "validated",
        });
        exploits.push(exploit);
      } catch (e) {
        /* Ignore fetch errors for an individual probe. */
      }
    }
  } catch (globalErr) {
    console.warn("Red team active fuzzing encounted top-level error", globalErr);
  }

  return { findings, exploits };
}

interface ApiProbeResult {
  findings: NonNullable<DiagnosticResult["apiSecFindings"]>;
  exploits: ValidatedExploit[];
}

/** Phase 7: probe common API endpoints for GraphQL introspection and broken object-level authorization. */
async function runApiSecurityProbes(
  url: string,
  hostname: string,
  headers: Record<string, string>,
  baseline: SoftNotFoundBaseline,
): Promise<ApiProbeResult> {
  const apiSecFindings: NonNullable<DiagnosticResult["apiSecFindings"]> = [];
  const exploits: ValidatedExploit[] = [];
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

      // Require a genuinely parsed introspection result. (A raw substring match
      // false-positives because the request body itself contains "__schema",
      // which servers frequently echo back in error messages.)
      if (isGraphqlIntrospection(gqlText)) {
        const gqlBody = JSON.stringify({ query: "{__schema{types{name}}}" });
        const req: PocRequest = {
          method: "POST",
          url: `${url}/graphql`,
          headers: { ...apiHeaders, "Content-Type": "application/json" },
          bodyText: gqlBody,
          payload: "{__schema{types{name}}}",
        };
        const attempt1: PocAttempt = { ok: true, status: gqlRes.status, matched: true };
        const attempt2 = await revalidate(req, isGraphqlIntrospection);
        const exploit = buildPoc({
          vector: "GraphQL Schema Introspection Exposed",
          severity: "high",
          endpoint: "/graphql",
          request: req,
          signal: "Parsed introspection result returned a populated __schema.types array",
          controlAbsent: true,
          responseBody: gqlText,
          attempts: [attempt1, attempt2],
        });
        const art = renderPocArtifact(exploit);
        apiSecFindings.push({
          testName: "GraphQL Schema Introspection Exposed",
          endpoint: "/graphql",
          severity: "high",
          description:
            "An active API endpoint probe discovered that GraphQL introspection is globally reachable. Attackers can effortlessly dump the entire undocumented internal schema definitions.",
          fix: "Disable introspection blocks in the production GraphQL backend. Shield API with explicit token authentication schemas.",
          rawRequest: art.rawRequest,
          rawResponse: art.rawResponse,
          validated: exploit.validationStatus === "validated",
        });
        exploits.push(exploit);
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
      const idorContentType = idorRes.headers.get("content-type") || "text/plain";
      const resRawIdor = `HTTP/1.1 ${idorRes.status} ${idorRes.statusText}\nContent-Type: ${idorContentType}\n\n${idorText.substring(0, 500)}...`;

      // Require an actual JSON user object distinct from the soft-404 baseline,
      // not merely the word "email" appearing in an HTML/SPA shell.
      if (isUserObjectLeak(idorContentType, idorRes.status, idorText, baseline)) {
        const req: PocRequest = {
          method: "GET",
          url: `${url}/api/v1/users/admin`,
          headers: apiHeaders,
          payload: "GET /api/v1/users/admin (no authorization)",
        };
        const reMatcher = (body: string) => isUserObjectLeak("application/json", 200, body, baseline);
        const attempt1: PocAttempt = { ok: true, status: idorRes.status, matched: true };
        const attempt2 = await revalidate(req, reMatcher);
        const exploit = buildPoc({
          vector: "Broken Object Level Authorization (BOLA)",
          severity: "critical",
          endpoint: "/api/v1/users/admin",
          request: req,
          signal: "Protected user object returned as JSON to an unauthenticated request",
          controlAbsent: true,
          responseBody: idorText,
          attempts: [attempt1, attempt2],
        });
        const art = renderPocArtifact(exploit);
        apiSecFindings.push({
          testName: "Broken Object Level Authorization (BOLA)",
          endpoint: "/api/v1/users/admin",
          severity: "critical",
          description:
            "API testing successfully resolved protected user entities directly by probing enumerated resource IDs, overriding local tenant boundaries.",
          fix: "Enforce stringent object-level resource verification. Explicitly map authorization states against the retrieved user objects inside controller logic.",
          rawRequest: art.rawRequest,
          rawResponse: art.rawResponse,
          validated: exploit.validationStatus === "validated",
        });
        exploits.push(exploit);
      }
    } catch (e) {
      /* Ignore fetch errors */
    }
  } catch (globalErr) {
    console.warn("API Security fuzzing encounted top-level error", globalErr);
  }

  return { findings: apiSecFindings, exploits };
}

/**
 * Calibrate what a "does-not-exist" response looks like for this target so the
 * path and API probes can distinguish a genuine exposure from a soft-404 / SPA
 * shell. Combines the homepage render with the response to a random unlikely
 * path (two views of the target's generic template).
 */
async function calibrateSoftNotFound(
  host: string,
  headers: Record<string, string>,
  homepageBody: string,
): Promise<SoftNotFoundBaseline> {
  const homepageSig = homepageBody ? signature(200, homepageBody) : null;
  let randomSig: ReturnType<typeof signature> | null = null;
  try {
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 2500);
    const randomPath = `/seclayer-probe-${crypto.randomBytes(8).toString("hex")}`;
    const res = await fetch(`${host}${randomPath}`, {
      method: "GET",
      headers,
      signal: ctl.signal,
    });
    clearTimeout(id);
    const body = await res.text().catch(() => "");
    randomSig = signature(res.status, body);
  } catch (e) {
    /* No baseline from the random path; the homepage signature still helps. */
  }
  return buildBaseline(homepageSig, randomSig);
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
      ip: "unresolved",
      nameserver: "unresolved",
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

  // Baseline of how the target answers non-existent content; used to suppress
  // soft-404 / SPA-shell false positives across the path and API probes.
  let baseline: SoftNotFoundBaseline = buildBaseline();

  try {
    const { htmlText, setCookie } = await probeHeaders(url, headers, result);
    runSastScan(htmlText, result);
    runScaScan(htmlText, setCookie, result);
    runDastAnalysis(htmlText, result);
    baseline = await calibrateSoftNotFound(host, headers, htmlText);
    await runEasmRecon(host, hostname, result, baseline);
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
  const redTeam = await runRedTeamProbes(url, headers);
  result.redTeamFindings = redTeam.findings;

  // --- API SECURITY TESTING ACTIVE PROBES ---
  const apiSec = await runApiSecurityProbes(url, hostname, headers, baseline);
  result.apiSecFindings = apiSec.findings;

  // --- MULTI-PAGE CRAWL + CHAIN DETECTORS (stored XSS, IDOR) ---
  const chainExploits: ValidatedExploit[] = [];
  try {
    const crawlResult = await crawlSite(url, { headers });
    result.crawl = {
      pagesVisited: crawlResult.pages.length,
      formsFound: crawlResult.forms.length,
      idRefsFound: crawlResult.idRefs.length,
    };

    const stored = await detectStoredXss(crawlResult, headers);
    if (stored.findings.length > 0) {
      result.redTeamFindings = [...(result.redTeamFindings ?? []), ...stored.findings];
      chainExploits.push(...stored.exploits);
    }

    const idor = await detectIdor(crawlResult, headers);
    if (idor.findings.length > 0) {
      result.apiSecFindings = [...(result.apiSecFindings ?? []), ...idor.findings];
      chainExploits.push(...idor.exploits);
    }

    // Fuzz crawl-discovered GET parameters for reflected XSS / SQLi.
    const fuzz = await runParamFuzzing(crawlResult, headers);
    if (fuzz.findings.length > 0) {
      result.redTeamFindings = [...(result.redTeamFindings ?? []), ...fuzz.findings];
      chainExploits.push(...fuzz.exploits);
    }
  } catch (err) {
    console.warn("Crawl / chain detection encountered a top-level error", err);
  }

  // Bounded, re-confirmed exploit proofs aggregated across all probes.
  result.validatedExploits = [...redTeam.exploits, ...apiSec.exploits, ...chainExploits];

  return result;
}

/** Trim a full diagnostic run down to the subset persisted alongside a scan for report rendering. */
export function summarizeDiagnostics(diag: DiagnosticResult): ScanDiagnosticsSummary {
  return {
    responseStatus: diag.responseStatus,
    sslSecure: diag.sslSecure,
    headers: diag.headers,
    missingHeaders: diag.missingHeaders,
    techLeaked: diag.techLeaked,
    cookieIssues: diag.cookieIssues,
    probedPaths: diag.probedPaths,
    dastInputs: diag.dastInputs.map((d) => ({
      formAction: d.formAction,
      method: d.method,
      csrfPresent: d.csrfPresent,
    })),
    easmPerimeter: {
      ip: diag.easmPerimeter.ip,
      nameserver: diag.easmPerimeter.nameserver,
      protocol: diag.easmPerimeter.protocol,
      subdomains: diag.easmPerimeter.subdomains.map((s) => ({
        domain: s.domain,
        status: s.status,
        port: s.port,
      })),
    },
  };
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

  // Fallback SAST removed to reduce noise

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

  // Fallback SCA removed to reduce noise

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

  // Default DAST baseline finding removed to decrease informational noise

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
        rawRequest: rt.rawRequest,
        rawResponse: rt.rawResponse,
        validated: rt.validated,
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
        validated: api.validated,
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
