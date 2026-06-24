import crypto from "crypto";
import { Finding } from "../../src/types.js";
import { DiagnosticResult } from "./diagnostic-types.js";

// Compiles Red Team active fuzzing findings and API Security testing
// findings from diagnostics. Returns the findings plus the total score
// deduction so the caller can sum it into the overall score exactly as before.
export function compileRedteamApiFindings(diag: DiagnosticResult): {
  findings: Finding[];
  scoreDelta: number;
} {
  const findings: Finding[] = [];
  let scoreDelta = 0;

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
      scoreDelta -= rt.severity === "critical" ? 25 : 15;
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
      scoreDelta -= api.severity === "critical" ? 25 : 15;
    });
  }

  return { findings, scoreDelta };
}
