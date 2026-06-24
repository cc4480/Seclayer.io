import { Severity } from "../../src/types.js";
import { DiagnosticResult } from "./diagnostic-types.js";

export function runStaticAnalysisProbes(
  htmlText: string,
  setCookie: string | undefined,
): {
  sastFindings: DiagnosticResult["sastFindings"];
  scaLibraries: DiagnosticResult["scaLibraries"];
  dastInputs: DiagnosticResult["dastInputs"];
} {
  const sastFindings: DiagnosticResult["sastFindings"] = [];
  const scaLibraries: DiagnosticResult["scaLibraries"] = [];
  const dastInputs: DiagnosticResult["dastInputs"] = [];

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
        sastFindings.push({
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
      sastFindings.push({
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
      sastFindings.push({
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
        scaLibraries.push({
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
        dastInputs.push({
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

  return { sastFindings, scaLibraries, dastInputs };
}
