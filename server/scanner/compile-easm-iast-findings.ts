import crypto from "crypto";
import { Finding } from "../../src/types.js";
import { DiagnosticResult } from "./diagnostic-types.js";

// Compiles EASM (External Attack Surface Management) and IAST
// (Interactive Application Security / Defensive Rules) findings from
// diagnostics. Returns the findings plus the total score deduction so the
// caller can sum it into the overall score exactly as before.
export function compileEasmIastFindings(diag: DiagnosticResult): {
  findings: Finding[];
  scoreDelta: number;
} {
  const findings: Finding[] = [];
  let scoreDelta = 0;

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
    scoreDelta -= 30;
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
    scoreDelta -= 5;
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
    scoreDelta -= 10;
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
    scoreDelta -= 20;
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
    scoreDelta -= 10;
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
    scoreDelta -= 10;
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
    scoreDelta -= 10;
  });

  return { findings, scoreDelta };
}
