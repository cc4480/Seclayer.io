import crypto from "crypto";
import { safeFetch } from "./ssrf.js";
import { InjectableTarget } from "../crawler.js";

// Active injection fuzzing of discovered GET parameters. Reuses the same SQLi
// error signatures and reflected-XSS token strategy as the root-level probes,
// but injects into real discovered parameters. Globally request-capped.
export async function fuzzDiscoveredTargets(
  targets: InjectableTarget[],
  fuzzHeaders: Record<string, string>,
): Promise<{ findings: any[]; paramsTested: number }> {
  const MAX_REQUESTS = 24;
  const MAX_PARAMS_PER_TARGET = 3;
  const findings: any[] = [];
  const reported = new Set<string>(); // dedupe by testName+endpoint+param
  let budget = MAX_REQUESTS;
  let paramsTested = 0;

  const sqlErrorSig =
    /(SQL syntax;|valid MySQL result|mysqli?_fetch|ORA-\d{4,5}|PLS-\d{4,5}|PostgreSQL.*?ERROR|PG::\w*Error|SQLSTATE\[|SQLite3?::|SQLiteException|Unclosed quotation mark after the character string|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|Npgsql\.)/i;

  const buildUrl = (base: string, param: string, value: string): string => {
    const u = new URL(base);
    u.searchParams.set(param, value);
    return u.toString();
  };

  const probe = async (target: string): Promise<string> => {
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 4000);
    try {
      const res = await safeFetch(target, { headers: fuzzHeaders, signal: ctl.signal });
      return await res.text();
    } finally {
      clearTimeout(id);
    }
  };

  for (const t of targets) {
    if (budget <= 0) break;
    let endpointPath = t.url;
    try {
      endpointPath = new URL(t.url).pathname;
    } catch {}

    for (const param of t.params.slice(0, MAX_PARAMS_PER_TARGET)) {
      if (budget <= 0) break;
      paramsTested++;

      // SQL injection: error-based signature on a discovered parameter.
      try {
        budget--;
        const text = await probe(buildUrl(t.url, param, "' OR 1=1-- -"));
        const key = `sqli:${endpointPath}:${param}`;
        if (sqlErrorSig.test(text) && !reported.has(key)) {
          reported.add(key);
          findings.push({
            testName: "SQL Injection (discovered parameter)",
            payload: `${param}=' OR 1=1-- -`,
            severity: "critical",
            description: `Injecting SQL metacharacters into the discovered parameter "${param}" on ${endpointPath} provoked a database error in the response, indicating an exploitable SQL injection.`,
            fix: "Use parameterized queries / prepared statements for this endpoint; never concatenate request input into SQL.",
          });
        }
      } catch { /* probe failed */ }

      if (budget <= 0) break;

      // Reflected XSS: unique token reflected unencoded.
      try {
        budget--;
        const token = `sx${crypto.randomBytes(4).toString("hex")}`;
        const payload = `<svg/onload=${token}>`;
        const text = await probe(buildUrl(t.url, param, payload));
        const key = `xss:${endpointPath}:${param}`;
        if (text.includes(payload) && !reported.has(key)) {
          reported.add(key);
          findings.push({
            testName: "Reflected XSS (discovered parameter)",
            payload: `${param}=${payload}`,
            severity: "high",
            description: `The discovered parameter "${param}" on ${endpointPath} reflects unencoded HTML/JavaScript into the response, confirming a reflected Cross-Site Scripting vulnerability.`,
            fix: "Apply context-aware output encoding for this parameter and deploy a restrictive Content-Security-Policy.",
          });
        }
      } catch { /* probe failed */ }
    }
  }

  return { findings, paramsTested };
}
