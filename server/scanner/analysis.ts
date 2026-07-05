import { DiagnosticResult } from "./types.js";
import { Severity } from "../../src/types.js";
import { analyzeCookies } from "./cookies.js";

// Analyzes the fetched root document: missing security headers, leaked
// framework signatures, insecure cookie directives, and high-precision
// SAST secret + SCA vulnerable-library signatures in the served markup.
//
// `setCookies` is the per-cookie Set-Cookie array (undici getSetCookie()) so
// multi-cookie responses are analyzed correctly. Header checks are context-aware
// to avoid the common false positives (CSP via meta tag, XFO superseded by CSP
// frame-ancestors, HSTS on plain HTTP, unversioned Server banners).
export function analyzeResponse(result: DiagnosticResult, htmlText: string, url: string, setCookies: string[] = []): void {
    const isHttps = url.startsWith("https://");

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

    // Context-aware suppression of header false positives. A policy can be
    // delivered by a <meta http-equiv> tag rather than a response header, and
    // some headers are only meaningful (or non-redundant) in certain contexts.
    const cspHeader = result.headers["content-security-policy"] || "";
    const metaCspMatch = htmlText.match(
      /<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*content\s*=\s*["']([^"']*)["'][^>]*>/i,
    );
    const metaCsp = metaCspMatch ? metaCspMatch[1] : "";
    const cspText = `${cspHeader} ${metaCsp}`;
    // CSP present via meta tag → not "missing".
    if (metaCsp) {
      result.missingHeaders = result.missingHeaders.filter((h) => h !== "content-security-policy");
    }
    // CSP frame-ancestors supersedes X-Frame-Options — do not flag XFO as missing.
    if (/frame-ancestors/i.test(cspText)) {
      result.missingHeaders = result.missingHeaders.filter((h) => h !== "x-frame-options");
    }
    // HSTS only applies over HTTPS; on plain HTTP the "Insecure Connection"
    // finding already covers it, so flagging missing HSTS is redundant noise.
    if (!isHttps) {
      result.missingHeaders = result.missingHeaders.filter((h) => h !== "strict-transport-security");
    }

    // Technology leaks: only report a banner that discloses a concrete VERSION
    // (e.g. "nginx/1.18.0", "PHP/7.4.3"). A bare product name is not actionable
    // and firing on it produces a finding on nearly every site.
    const hasVersion = (v: string) => /\d+(?:\.\d+)+|\/\d/.test(v);
    const serverHeader = result.headers["server"];
    if (serverHeader && !/cloudflare/i.test(serverHeader) && hasVersion(serverHeader)) {
      result.techLeaked.push(`Server: ${serverHeader}`);
    }
    const poweredBy = result.headers["x-powered-by"];
    if (poweredBy && hasVersion(poweredBy)) {
      result.techLeaked.push(`X-Powered-By: ${poweredBy}`);
    }

    // Cookie flags — scoped to session/auth cookies only (see cookies.ts).
    const cookieList = setCookies.length
      ? setCookies
      : (result.headers["set-cookie"] ? [result.headers["set-cookie"]] : []);
    result.cookieIssues.push(...analyzeCookies(cookieList, isHttps));

    // --- 2. SAST SCAN ENGINE (high-precision secret signatures only) ---
    // Only patterns that are essentially never legitimately client-side are
    // reported with high confidence. Identifiers that are frequently public by
    // design (e.g. Firebase/Maps browser keys) are reported low/medium so they
    // do not become false positives.
    if (htmlText) {
      const patterns = [
        {
          name: "Stripe Secret Key",
          regex: /sk_live_[0-9a-zA-Z]{24,}/,
          severity: "critical" as Severity,
          confidence: "high" as const,
          note: "A Stripe live secret key grants full API access and must never appear client-side.",
        },
        {
          name: "GitHub OAuth Access Token",
          regex: /gho_[a-zA-Z0-9]{36}/,
          severity: "critical" as Severity,
          confidence: "high" as const,
          note: "A GitHub OAuth token grants repository access and must never be shipped to browsers.",
        },
        {
          name: "Private Key Block",
          regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
          severity: "critical" as Severity,
          confidence: "high" as const,
          note: "A PEM private key block was served to the client; the corresponding key must be rotated.",
        },
        {
          name: "AWS Access Key ID",
          regex: /AKIA[0-9A-Z]{16}/,
          severity: "high" as Severity,
          confidence: "medium" as const,
          note: "An AWS access key id is exposed. Confirm the matching secret is not also leaked and rotate it.",
        },
        {
          name: "Google API Key",
          regex: /AIzaSy[A-Za-z0-9_\-]{33}/,
          severity: "low" as Severity,
          confidence: "low" as const,
          note: "Google browser API keys are often intentionally public; verify it is restricted by HTTP referrer/API and not a server key.",
        },
      ];

      patterns.forEach((p) => {
        if (p.regex.test(htmlText)) {
          result.sastFindings.push({
            file: "Client-served HTML/JavaScript",
            issue: `Exposed Credential Signature (${p.name})`,
            severity: p.severity,
            confidence: p.confidence,
            type: "hardcoded_secrets",
            description: `A string matching the ${p.name} format was detected in the client-served response. ${p.note}`,
            fix: `Remove the credential from client code, rotate it immediately, and proxy any required third-party calls through an authenticated backend that holds the secret server-side.`,
          });
        }
      });
    }

    // --- 3. SCA ANALYSIS ENGINE (vulnerable library footprints in markup) ---
    // A library is only flagged when its version regex actually matches a known
    // vulnerable range in the served markup. The reported version is the one
    // captured from the page, and advisories are attributed per-library.
    if (htmlText) {
      const libraries = [
        {
          name: "jQuery",
          match: /jquery[-.](1\.\d+\.\d+|2\.\d+\.\d+)/i,
          severity: "medium" as Severity,
          advisories: ["CVE-2020-11022", "CVE-2020-11023"],
          desc: "jQuery before 3.5.0 is affected by cross-site scripting via htmlPrefilter when passing untrusted HTML to DOM-manipulation methods.",
          fix: "Upgrade jQuery to >= 3.5.0.",
        },
        {
          name: "Bootstrap",
          match: /bootstrap[-./](3\.\d+\.\d+)/i,
          severity: "medium" as Severity,
          advisories: ["CVE-2019-8331"],
          desc: "Bootstrap 3.x is affected by XSS in data-template/tooltip/popover handling and no longer receives security fixes.",
          fix: "Upgrade Bootstrap to >= 4.3.1 (ideally 5.x).",
        },
        {
          name: "AngularJS",
          match: /angular[-.](1\.[0-8]\.\d+)/i,
          severity: "low" as Severity,
          advisories: ["EOL"],
          desc: "AngularJS (1.x) is past end-of-life and receives no further security patches.",
          fix: "Migrate off AngularJS to a maintained framework.",
        },
        {
          name: "Lodash",
          match: /lodash[@/-](4\.(?:[0-9]|1[0-6])\.\d+)\b/i,
          severity: "high" as Severity,
          advisories: ["CVE-2019-10744"],
          desc: "lodash before 4.17.12 is vulnerable to prototype pollution via defaultsDeep.",
          fix: "Upgrade lodash to >= 4.17.21.",
        },
      ];

      libraries.forEach((lib) => {
        const m = lib.match.exec(htmlText);
        if (m) {
          result.scaLibraries.push({
            name: lib.name,
            version: m[1],
            status: "vuln",
            advisories: lib.advisories,
            severity: lib.severity,
            description: lib.desc,
            fix: lib.fix,
          });
        }
      });
    }
}
