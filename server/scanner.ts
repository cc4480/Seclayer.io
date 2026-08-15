import { crawlSite, targetsFromHtml, dedupeTargets, paramsOf } from "./crawler.js";
import { runTemplates, selectTemplates } from "./templateEngine.js";
import { TEMPLATES } from "./templates.js";
import { detectTechTags } from "./techprofile.js";
import { renderPage, isRenderingEnabled } from "./render.js";

import { assertTargetIsScannable, safeFetch } from "./scanner/ssrf.js";
import { parseAuthHeader } from "./scanner/util.js";
import { DiagnosticResult } from "./scanner/types.js";
import { analyzeResponse } from "./scanner/analysis.js";
import { enumeratePerimeter } from "./scanner/easm.js";
import { probeSensitivePaths } from "./scanner/probes.js";
import { runRootRedTeamProbes } from "./scanner/redteam.js";
import { runApiSecProbes } from "./scanner/apisec.js";
import { fuzzDiscoveredTargets } from "./scanner/fuzzer.js";
import { extractSetCookies } from "./scanner/cookies.js";

// Public scanner API — re-exported so existing importers (`./scanner.js`) keep
// working after the internals were split into ./scanner/* modules.
export { isBlockedIp, assertScanTargetSafe, safeFetch } from "./scanner/ssrf.js";
export { looksLikeHtml, parseAuthHeader } from "./scanner/util.js";
export { compileStaticFindings } from "./scanner/findings.js";
export type { DiagnosticResult } from "./scanner/types.js";

// Orchestrates a full black-box diagnostic pass over a target: SSRF-guarded root
// fetch and response analysis, EASM perimeter mapping, sensitive-path probing,
// active red-team and API-security probes, crawl-driven parameter fuzzing, and
// data-driven template detections. Each stage lives in its own module; this
// function only wires them together and owns the shared request context.
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

  // SSRF guard: refuse internal/reserved targets before issuing any request.
  await assertTargetIsScannable(parsedUrl);

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
      ip: "", // resolved from real DNS below
      nameserver: "", // resolved from real DNS below
      protocol: url.startsWith("https://") ? "HTTPS" : "HTTP",
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
  // Authenticated scanning: the user-supplied credential is applied to EVERY
  // request path (root fetch, probes, crawl, and templates) so auth-gated
  // surface is actually reached.
  const authHeaders = parseAuthHeader(authHeader);
  Object.assign(headers, authHeaders);

  // Wrapper that injects the auth + scanner identity into crawler/template
  // requests, which otherwise only carry their own minimal headers.
  const authedFetch = (u: string, init: RequestInit) =>
    safeFetch(u, {
      ...init,
      headers: {
        "User-Agent": headers["User-Agent"],
        ...authHeaders,
        ...((init.headers as Record<string, string>) || {}),
      },
    });

  let rootHtml = ""; // root document HTML, reused to seed the crawler

  try {
    // 1. Core fetch + header/SAST/SCA analysis, EASM perimeter, path probes.
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 6000); // 6s timeout max

    const response = await safeFetch(url, {
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

    const setCookies = extractSetCookies(response.headers);

    const htmlText = await response.text().catch(() => "");
    rootHtml = htmlText;

    analyzeResponse(result, htmlText, url, setCookies);
    await enumeratePerimeter(hostname, result);
    await probeSensitivePaths(host, result);
  } catch (err: any) {
    // A failure reaching the target means we cannot assess it. Surface this as
    // a failed scan rather than a misleading "clean" (no-findings) report.
    if (err?.name === "AbortError") {
      throw new Error(`Target ${url} did not respond within the timeout window.`);
    }
    throw new Error(`Unable to connect to ${url}: ${err?.message || "connection failed"}`);
  }

  // Active root-level red-team and API-security probes (self-contained).
  result.redTeamFindings = await runRootRedTeamProbes(url, headers);
  result.apiSecFindings = await runApiSecProbes(url, hostname, headers);

  // --- CRAWL + DISCOVERED-PARAMETER FUZZING ---
  // Map the real attack surface (links, forms, JS-referenced endpoints) and aim
  // the injection probes at the parameters the application actually uses, rather
  // than only a few hardcoded names. Strictly bounded by page/request/time caps.
  try {
    if (rootHtml && result.responseStatus > 0) {
      const crawl = await crawlSite(url, authedFetch, {
        maxPages: 10,
        maxDepth: 2,
        budgetMs: 15000,
        seedHtml: rootHtml,
      });

      // Optional headless rendering: merge JS-rendered links and XHR/fetch
      // endpoints the static crawl cannot see (no-op unless explicitly enabled).
      let allTargets = crawl.targets;
      if (isRenderingEnabled()) {
        const rendered = await renderPage(url, { "User-Agent": headers["User-Agent"], ...authHeaders });
        if (rendered) {
          const renderedTargets = [
            ...targetsFromHtml(rendered.html, url),
            ...rendered.requestedUrls
              .map((u) => ({ url: u, method: "GET" as const, params: paramsOf(u), source: "script" as const }))
              .filter((t) => t.params.length > 0),
          ];
          allTargets = dedupeTargets([...crawl.targets, ...renderedTargets]);
        }
      }

      const getTargets = allTargets.filter((t) => t.method === "GET" && t.params.length > 0);
      const fuzz = await fuzzDiscoveredTargets(getTargets, { ...headers, "Cache-Control": "no-cache" });
      result.redTeamFindings = [...(result.redTeamFindings || []), ...fuzz.findings];

      result.crawl = {
        pagesVisited: crawl.pagesVisited,
        endpointsDiscovered: allTargets.length,
        paramsTested: fuzz.paramsTested,
        sampleEndpoints: allTargets.slice(0, 8).map((t) => {
          try {
            return new URL(t.url).pathname + (t.params.length ? `?${t.params.join("&")}` : "");
          } catch {
            return t.url;
          }
        }),
      };
    }
  } catch (crawlErr) {
    console.warn("Crawl/fuzz stage encountered an error", crawlErr);
  }

  // --- TEMPLATE-BASED DETECTIONS ---
  // Data-driven checks (exposed panels, config/backup files, actuators, etc.).
  // Each template confirms via a body signature, so SPA fallbacks aren't flagged.
  try {
    if (result.responseStatus > 0) {
      // Gate framework-specific templates by the detected tech profile so the
      // pack scales without running every stack's checks against every target.
      const techTags = detectTechTags(result.headers, rootHtml);
      const selected = selectTemplates(TEMPLATES, techTags);
      result.templateFindings = await runTemplates(host, authedFetch, selected, 6);
    }
  } catch (tplErr) {
    console.warn("Template detection stage encountered an error", tplErr);
  }

  return result;
}
