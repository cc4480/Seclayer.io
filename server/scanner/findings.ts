import crypto from "crypto";
import { Finding, Severity } from "../../src/types.js";
import { scoreFindings } from "../scoring.js";
import { mapOwasp } from "../owasp.js";
import { DiagnosticResult } from "./types.js";
import { pushDiagnosticFindings } from "./findingBuilders.js";

// Convert diagnostics into structured Category Findings
export function compileStaticFindings(diag: DiagnosticResult): {
  score: number;
  severity: Severity;
  findings: Finding[];
} {
  const findings: Finding[] = [];

  // 0. Surface mapping summary (informational, zero score impact).
  if (diag.crawl && (diag.crawl.pagesVisited > 1 || diag.crawl.endpointsDiscovered > 0)) {
    const c = diag.crawl;
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: `Application Surface Mapped (${c.pagesVisited} pages, ${c.endpointsDiscovered} endpoints)`,
      description: `The crawler mapped ${c.pagesVisited} same-origin page(s) and discovered ${c.endpointsDiscovered} parameterized endpoint(s); ${c.paramsTested} parameter(s) were actively fuzzed.${c.sampleEndpoints.length ? ` Examples: ${c.sampleEndpoints.join(", ")}.` : ""}`,
      severity: "info",
      confidence: "high",
      fix: "No action required — this maps the tested attack surface for context.",
      category: "DAST",
    });
  }


  // Findings derived from the diagnostic scan sections (perimeter,
  // headers, cookies, secrets, libraries, inputs, probed paths).
  pushDiagnosticFindings(diag, findings);


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
    });
  }

  // Template engine findings (exposed panels, config/backup files, actuators).
  if (diag.templateFindings && diag.templateFindings.length > 0) {
    findings.push(...diag.templateFindings);
  }

  // Final dedupe by title so a check can never double-report the same issue.
  const seenTitles = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = f.title.toLowerCase();
    if (seenTitles.has(key)) return false;
    seenTitles.add(key);
    return true;
  });

  // Tag each finding with its OWASP Top 10 (2021) category.
  for (const f of deduped) {
    if (!f.owasp) f.owasp = mapOwasp(f.category, f.title);
  }

  // Score via the shared scoring module so the initial score and any later
  // recalculation (after suppression) always use identical weights.
  const { score, severity } = scoreFindings(deduped);
  return { score, severity, findings: deduped };
}
