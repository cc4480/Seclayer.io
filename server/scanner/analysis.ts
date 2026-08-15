import { DiagnosticResult } from "./types.js";
import { Severity } from "../../src/types.js";
import { analyzeCookies } from "./cookies.js";
import { detectVulnerableLibraries } from "./sca.js";

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
    // Detection is scoped to the code surface (script/link references + inline
    // scripts) so incidental version strings in body text never false-positive.
    result.scaLibraries.push(...detectVulnerableLibraries(htmlText));
}
