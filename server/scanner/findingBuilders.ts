import crypto from "crypto";
import { Finding } from "../../src/types.js";
import { DiagnosticResult } from "./types.js";

// Builds findings derived directly from the diagnostic scan sections
// (perimeter, security headers, cookies, exposed secrets, vulnerable
// libraries, insecure inputs, and probed sensitive paths).
export function pushDiagnosticFindings(diag: DiagnosticResult, findings: Finding[]): void {
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
  }

  // One consolidated finding for all missing cookie directives, rather than a
  // separate finding per flag (which read as duplicate noise).
  if (diag.cookieIssues.length > 0) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Insecure Session Cookie Attributes",
      description: `The session cookie is missing hardening directives: ${diag.cookieIssues.join("; ")}. Without HttpOnly, JavaScript payloads can read active session IDs; without Secure/SameSite the cookie is exposed to interception and cross-site request forgery.`,
      severity: "medium",
      confidence: "high",
      fix: "Set HttpOnly, Secure, and SameSite=Lax (or Strict) on session/auth cookies.",
      category: "IAST",
    });
  }

  // 3. SAST (Static Code Security Analysis) checks
  diag.sastFindings.forEach((sf) => {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: sf.issue,
      description: sf.description,
      severity: sf.severity,
      confidence: sf.confidence,
      fix: sf.fix,
      category: "SAST",
    });
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
  });
}
