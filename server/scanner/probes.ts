import { safeFetch } from "./ssrf.js";
import { looksLikeHtml } from "./util.js";
import { DiagnosticResult } from "./types.js";

export async function probeSensitivePaths(host: string, result: DiagnosticResult): Promise<void> {
    // Sensitive Paths Probing. A path is only treated as "exposed" when the
    // response BODY actually matches the file's signature, not merely on a 200.
    // This eliminates the dominant false positive: single-page apps that serve
    // index.html (HTTP 200) for every unknown path including /.env.
    const sensitiveProbes: Array<{ path: string; matches: (body: string) => boolean }> = [
      { path: "/.env", matches: (b) => !looksLikeHtml(b) && /^[A-Z][A-Z0-9_]*\s*=/m.test(b) },
      { path: "/.git/config", matches: (b) => /\[core\]/i.test(b) || /repositoryformatversion/i.test(b) },
      { path: "/.git/HEAD", matches: (b) => /^ref:\s+refs\//m.test(b.trim()) },
      { path: "/phpinfo.php", matches: (b) => /<title>phpinfo\(\)/i.test(b) || /PHP Version\s*</i.test(b) },
      { path: "/.aws/credentials", matches: (b) => !looksLikeHtml(b) && /aws_access_key_id/i.test(b) },
      { path: "/config.json", matches: (b) => !looksLikeHtml(b) && /"(password|secret|api[_-]?key|private[_-]?key)"\s*:/i.test(b) },
    ];

    for (const probe of sensitiveProbes) {
      try {
        const probeController = new AbortController();
        const probeId = setTimeout(() => probeController.abort(), 2500);
        const probeRes = await safeFetch(`${host}${probe.path}`, {
          method: "GET",
          headers: { "User-Agent": "Seclayer-Security-Scanner/2.0 (seclayer.io)" },
          signal: probeController.signal,
        });
        const body = await probeRes.text().catch(() => "");
        clearTimeout(probeId);

        const exposed = probeRes.status === 200 && probe.matches(body);
        result.probedPaths.push({ path: probe.path, status: probeRes.status, exposed });
      } catch (err) {
        result.probedPaths.push({ path: probe.path, status: 0, exposed: false });
      }
    }
}
