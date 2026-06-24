import { Finding, Severity } from "../src/types.js";
import crypto from "crypto";
import type { DiagnosticResult } from "./scanner/diagnostic-types.js";
import { runStaticAnalysisProbes } from "./scanner/static-analysis-probes.js";
import { runEasmRecon } from "./scanner/easm-recon.js";
import { runRedTeamProbes } from "./scanner/red-team-probes.js";
import { runApiSecProbes } from "./scanner/api-sec-probes.js";
import { compileEasmIastFindings } from "./scanner/compile-easm-iast-findings.js";
import { compileSastScaDastFindings } from "./scanner/compile-sast-sca-dast-findings.js";
import { compileRedteamApiFindings } from "./scanner/compile-redteam-api-findings.js";

export type { DiagnosticResult };

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
      ip: "unknown",
      nameserver: "unknown",
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

    // --- 2-4. SAST / SCA / DAST static analysis probes (pure regex over already-fetched HTML) ---
    const staticProbeResults = runStaticAnalysisProbes(htmlText, setCookie);
    result.sastFindings = staticProbeResults.sastFindings;
    result.scaLibraries = staticProbeResults.scaLibraries;
    result.dastInputs = staticProbeResults.dastInputs;

    // --- 5. EASM PERIMETER (Subdomains, DNS and Real Host IP Lookup) ---
    const easmRecon = await runEasmRecon(hostname, host);
    result.easmPerimeter.subdomains = easmRecon.easmPerimeter.subdomains;
    result.easmPerimeter.ip = easmRecon.easmPerimeter.ip;
    result.easmPerimeter.nameserver = easmRecon.easmPerimeter.nameserver;
    result.probedPaths = easmRecon.probedPaths;
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
  result.redTeamFindings = await runRedTeamProbes(url, headers);

  // --- API SECURITY TESTING ACTIVE PROBES ---
  result.apiSecFindings = await runApiSecProbes(url, hostname, headers);

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

  // 1. EASM checks + 2. IAST checks
  const easmIast = compileEasmIastFindings(diag);
  findings.push(...easmIast.findings);
  score += easmIast.scoreDelta;

  // 3. SAST checks + 4. SCA checks + 5. DAST checks + exposed-path findings
  const sastScaDast = compileSastScaDastFindings(diag);
  findings.push(...sastScaDast.findings);
  score += sastScaDast.scoreDelta;

  // Compile Red Team aggressive probing findings + API Security Testing findings
  const redteamApi = compileRedteamApiFindings(diag);
  findings.push(...redteamApi.findings);
  score += redteamApi.scoreDelta;

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
