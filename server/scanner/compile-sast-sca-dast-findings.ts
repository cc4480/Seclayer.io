import crypto from "crypto";
import { Finding } from "../../src/types.js";
import { DiagnosticResult } from "./diagnostic-types.js";

// Compiles SAST / SCA / DAST findings-from-diagnostics, plus exposed-path
// findings, from diagnostics. Returns the findings plus the total score
// deduction so the caller can sum it into the overall score exactly as before.
export function compileSastScaDastFindings(diag: DiagnosticResult): {
  findings: Finding[];
  scoreDelta: number;
} {
  const findings: Finding[] = [];
  let scoreDelta = 0;

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
    scoreDelta -=
      sf.severity === "critical" ? 35 : sf.severity === "high" ? 25 : 15;
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
    scoreDelta -= sca.severity === "high" ? 25 : 15;
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
    scoreDelta -= dast.severity === "high" ? 20 : 10;
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
    scoreDelta -= 35;
  });

  // Default DAST baseline finding removed to decrease informational noise

  return { findings, scoreDelta };
}
