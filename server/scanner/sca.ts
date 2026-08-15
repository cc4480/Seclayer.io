import { Severity } from "../../src/types.js";

export interface ScaLibrary {
  name: string;
  version: string;
  status: "vuln" | "safe";
  advisories: string[];
  severity: Severity;
  description: string;
  fix: string;
}

interface LibrarySignature {
  name: string;
  match: RegExp;
  severity: Severity;
  advisories: string[];
  desc: string;
  fix: string;
}

const LIBRARIES: LibrarySignature[] = [
  {
    name: "jQuery",
    match: /jquery[-.](1\.\d+\.\d+|2\.\d+\.\d+)/i,
    severity: "medium",
    advisories: ["CVE-2020-11022", "CVE-2020-11023"],
    desc: "jQuery before 3.5.0 is affected by cross-site scripting via htmlPrefilter when passing untrusted HTML to DOM-manipulation methods.",
    fix: "Upgrade jQuery to >= 3.5.0.",
  },
  {
    name: "Bootstrap",
    match: /bootstrap[-./](3\.\d+\.\d+)/i,
    severity: "medium",
    advisories: ["CVE-2019-8331"],
    desc: "Bootstrap 3.x is affected by XSS in data-template/tooltip/popover handling and no longer receives security fixes.",
    fix: "Upgrade Bootstrap to >= 4.3.1 (ideally 5.x).",
  },
  {
    name: "AngularJS",
    match: /angular[-.](1\.[0-8]\.\d+)/i,
    severity: "low",
    advisories: ["EOL"],
    desc: "AngularJS (1.x) is past end-of-life and receives no further security patches.",
    fix: "Migrate off AngularJS to a maintained framework.",
  },
  {
    name: "Lodash",
    match: /lodash[@/-](4\.(?:[0-9]|1[0-6])\.\d+)\b/i,
    severity: "high",
    advisories: ["CVE-2019-10744"],
    desc: "lodash before 4.17.12 is vulnerable to prototype pollution via defaultsDeep.",
    fix: "Upgrade lodash to >= 4.17.21.",
  },
];

// Builds the "code surface" a library version can legitimately appear in: the
// URL values of script/link references and the contents of inline <script>
// blocks. Matching only here (instead of the whole document) removes the false
// positive where a version-like string appears in visible body text, JSON-LD,
// or an unrelated attribute — a real loaded library is referenced by src/href
// or shipped inside a script block.
export function collectCodeSurface(html: string): string {
  const parts: string[] = [];

  const attrRe = /\b(?:src|href)\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = attrRe.exec(html))) parts.push(m[1]);

  const scriptRe = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  while ((m = scriptRe.exec(html))) parts.push(m[1]);

  return parts.join("\n");
}

// Detects vulnerable front-end libraries referenced by the page, scoped to the
// code surface so incidental version strings never trigger a finding.
export function detectVulnerableLibraries(html: string): ScaLibrary[] {
  if (!html) return [];
  const surface = collectCodeSurface(html);
  const found: ScaLibrary[] = [];

  for (const lib of LIBRARIES) {
    const hit = lib.match.exec(surface);
    if (hit) {
      found.push({
        name: lib.name,
        version: hit[1],
        status: "vuln",
        advisories: lib.advisories,
        severity: lib.severity,
        description: lib.desc,
        fix: lib.fix,
      });
    }
  }

  return found;
}
