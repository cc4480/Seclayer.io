import { DiagnosticResult } from "./diagnostic-types.js";

type ApiSecFinding = NonNullable<DiagnosticResult["apiSecFindings"]>[number];

export async function runApiSecProbes(
  url: string,
  hostname: string,
  headers: Record<string, string>,
): Promise<ApiSecFinding[]> {
  // --- API SECURITY TESTING ACTIVE PROBES ---
  const apiSecFindings: ApiSecFinding[] = [];
  try {
    const apiHeaders = { ...headers, "Cache-Control": "no-cache" };

    // 1. GraphQL Introspection Probe
    try {
      const gqlCtl = new AbortController();
      const gqlId = setTimeout(() => gqlCtl.abort(), 4000);
      const reqRaw = `POST /graphql HTTP/1.1\nHost: ${hostname}\nContent-Type: application/json\n\n{"query":"{__schema{types{name}}}"}`;

      const gqlRes = await fetch(`${url}/graphql`, {
        method: "POST",
        headers: { ...apiHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{__schema{types{name}}}" }),
        signal: gqlCtl.signal,
      });
      clearTimeout(gqlId);
      const gqlText = await gqlRes.text();
      const resRaw = `HTTP/1.1 ${gqlRes.status} ${gqlRes.statusText}\n\n${gqlText.substring(0, 500)}...`;

      if (gqlText.includes("__schema") || gqlText.includes("__Type")) {
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

      const idorRes = await fetch(`${url}/api/v1/users/admin`, {
        headers: apiHeaders,
        signal: idorCtl.signal,
      });
      clearTimeout(idorId);
      const idorText = await idorRes.text();
      const resRawIdor = `HTTP/1.1 ${idorRes.status} ${idorRes.statusText}\nContent-Type: ${idorRes.headers.get("content-type") || "text/plain"}\n\n${idorText.substring(0, 500)}...`;

      if (
        idorRes.status === 200 &&
        (idorText.includes("email") || idorText.includes('"role"'))
      ) {
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
