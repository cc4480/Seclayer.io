import crypto from "crypto";
import { DiagnosticResult } from "./diagnostic-types.js";

type RedTeamFinding = NonNullable<DiagnosticResult["redTeamFindings"]>[number];

export async function runRedTeamProbes(
  url: string,
  headers: Record<string, string>,
): Promise<RedTeamFinding[]> {
  // --- RED TEAM ACTIVE FUZZING PROBES ---
  const redTeamFindings: RedTeamFinding[] = [];
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

  return redTeamFindings;
}
