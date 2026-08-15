import { safeFetch } from "./ssrf.js";

// Active API-security probes: GraphQL schema introspection exposure and
// Broken Object Level Authorization (BOLA). Both confirm on real parsed
// responses, never on a bare 200, to honour the zero-false-positive goal.
export async function runApiSecProbes(url: string, hostname: string, headers: Record<string, string>): Promise<any[]> {
  const apiSecFindings: any[] = [];
  try {
    const apiHeaders = { ...headers, "Cache-Control": "no-cache" };

    // 1. GraphQL Introspection Probe
    try {
      const gqlCtl = new AbortController();
      const gqlId = setTimeout(() => gqlCtl.abort(), 4000);
      const reqRaw = `POST /graphql HTTP/1.1\nHost: ${hostname}\nContent-Type: application/json\n\n{"query":"{__schema{types{name}}}"}`;

      const gqlRes = await safeFetch(`${url}/graphql`, {
        method: "POST",
        headers: { ...apiHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{__schema{types{name}}}" }),
        signal: gqlCtl.signal,
      });
      clearTimeout(gqlId);
      const gqlText = await gqlRes.text();
      const resRaw = `HTTP/1.1 ${gqlRes.status} ${gqlRes.statusText}\n\n${gqlText.substring(0, 500)}...`;

      // Confirm a real introspection RESULT (data.__schema.types), not merely
      // the echoed query string or an error mentioning "__schema".
      let introspectionExposed = false;
      try {
        const parsed = JSON.parse(gqlText);
        introspectionExposed = Array.isArray(parsed?.data?.__schema?.types) && parsed.data.__schema.types.length > 0;
      } catch {
        introspectionExposed = false;
      }
      if (introspectionExposed) {
        apiSecFindings.push({
          testName: "GraphQL Schema Introspection Exposed",
          endpoint: "/graphql",
          severity: "high",
          description:
            "An active API endpoint probe discovered that GraphQL introspection is globally reachable. Attackers can effortlessly dump the entire undocumented internal schema definitions.",
          fix: "Disable introspection blocks in the production GraphQL backend. Shield API with explicit token authentication schemas.",
          rawRequest: reqRaw,
          rawResponse: resRaw,
        });
      }
    } catch (e) {
      /* Ignore fetch errors */
    }

    // 2. Broken Object Level Authorization (BOLA) Probe
    try {
      const idorCtl = new AbortController();
      const idorId = setTimeout(() => idorCtl.abort(), 4000);
      const reqRawIdor = `GET /api/v1/users/admin HTTP/1.1\nHost: ${hostname}\nAccept: application/json`;

      const idorRes = await safeFetch(`${url}/api/v1/users/admin`, {
        headers: apiHeaders,
        signal: idorCtl.signal,
      });
      clearTimeout(idorId);
      const idorText = await idorRes.text();
      const idorCt = idorRes.headers.get("content-type") || "text/plain";
      const resRawIdor = `HTTP/1.1 ${idorRes.status} ${idorRes.statusText}\nContent-Type: ${idorCt}\n\n${idorText.substring(0, 500)}...`;

      // Only flag when a JSON user object is actually returned — a 200 HTML
      // page that happens to contain the word "email" is not a BOLA.
      let bolaConfirmed = false;
      if (idorRes.status === 200 && /application\/json/i.test(idorCt)) {
        try {
          const obj = JSON.parse(idorText);
          const candidate = obj?.user ?? obj?.data ?? obj;
          bolaConfirmed = !!candidate && typeof candidate === "object" &&
            ("email" in candidate || "role" in candidate || "username" in candidate);
        } catch {
          bolaConfirmed = false;
        }
      }
      if (bolaConfirmed) {
        apiSecFindings.push({
          testName: "Broken Object Level Authorization (BOLA)",
          endpoint: "/api/v1/users/admin",
          severity: "critical",
          description:
            "API testing successfully resolved protected user entities directly by probing enumerated resource IDs, overriding local tenant boundaries.",
          fix: "Enforce stringent object-level resource verification. Explicitly map authorization states against the retrieved user objects inside controller logic.",
          rawRequest: reqRawIdor,
          rawResponse: resRawIdor,
        });
      }
    } catch (e) {
      /* Ignore fetch errors */
    }
  } catch (globalErr) {
    console.warn("API Security fuzzing encounted top-level error", globalErr);
  }
  return apiSecFindings;
}
