import crypto from "crypto";
import { DiagnosticResult } from "./diagnostic-types.js";

const commonSubdomains = [
  "www",
  "api",
  "dev",
  "staging",
  "admin",
  "vpn",
  "dashboard",
  "status",
  "mail",
  "remote",
  "blog",
  "webmail",
  "server",
  "ns1",
  "ns2",
  "smtp",
  "secure",
  "shop",
  "portal",
  "test",
  "cdn",
  "app",
  "m",
  "cloud",
  "qa",
  "support",
  "docs",
  "help",
  "login",
  "auth",
  "ftp",
  "pop",
  "imap",
];

const pathsToProbe = [
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.git/config",
  "/.git/HEAD",
  "/admin",
  "/wp-admin",
  "/phpinfo.php",
  "/server-status",
  "/actuator",
  "/actuator/env",
  "/swagger.json",
  "/openapi.json",
  "/api-docs",
  "/config.php",
  "/backup.sql",
  "/dump.sql",
];

export async function runEasmRecon(
  hostname: string,
  host: string,
): Promise<{
  easmPerimeter: Pick<DiagnosticResult["easmPerimeter"], "subdomains" | "ip" | "nameserver">;
  probedPaths: DiagnosticResult["probedPaths"];
}> {
  const easmPerimeter: Pick<
    DiagnosticResult["easmPerimeter"],
    "subdomains" | "ip" | "nameserver"
  > = {
    subdomains: [],
    ip: "unknown",
    nameserver: "unknown",
  };
  const probedPaths: DiagnosticResult["probedPaths"] = [];

  // --- 5. EASM PERIMETER (Subdomains, DNS and Real Host IP Lookup) ---
  // Perform active Domain audit map
  try {
    const dns = await import("dns/promises");

    const [ipRecords, nsRecords] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolveNs(hostname),
    ]);

    if (ipRecords.status === "fulfilled" && ipRecords.value.length > 0) {
      easmPerimeter.ip = ipRecords.value[0];
    }
    if (nsRecords.status === "fulfilled" && nsRecords.value.length > 0) {
      easmPerimeter.nameserver = nsRecords.value[0];
    }

    // Check for Wildcard DNS to prevent false positive subdomain bloating
    let wildcardIp: string | null = null;
    try {
      const randomSub = crypto.randomBytes(6).toString("hex");
      const wildcardRecords = await dns.resolve4(`${randomSub}.${hostname}`);
      if (wildcardRecords && wildcardRecords.length > 0) {
        wildcardIp = wildcardRecords[0];
      }
    } catch (e) {
      // No wildcard DNS detected
    }

    const subdomainChecks = commonSubdomains.map(async (sub) => {
      const subUrl = `${sub}.${hostname}`;
      try {
        const records = await dns.resolve4(subUrl);

        // Filter out false positives caused by Wildcard DNS records
        if (wildcardIp && records.includes(wildcardIp)) {
          return {
            domain: subUrl,
            status: "inactive" as const,
            port: "0",
          };
        }

        return {
          domain: subUrl,
          status: "live" as const,
          port: sub.includes("vpn")
            ? "1194"
            : sub.includes("mail") || sub.includes("smtp")
              ? "25"
              : "443",
          ip: records[0],
        };
      } catch (err) {
        return {
          domain: subUrl,
          status: "inactive" as const,
          port: "0",
        };
      }
    });

    const subResults = await Promise.all(subdomainChecks);
    easmPerimeter.subdomains = subResults;
  } catch (e) {
    console.warn("DNS resolution failed:", e);
  }

  // Sensitive Paths Probing
  for (const p of pathsToProbe) {
    try {
      const probeController = new AbortController();
      const probeId = setTimeout(() => probeController.abort(), 2500); // short timeout
      const probeUrl = `${host}${p}`;

      const probeRes = await fetch(probeUrl, {
        method: "GET",
        headers: {
          "User-Agent": "Seclayer-Security-Scanner/2.0 (seclayer.io)",
        },
        signal: probeController.signal,
      });
      clearTimeout(probeId);

      const isExposed = probeRes.status === 200;
      probedPaths.push({
        path: p,
        status: probeRes.status,
        exposed: isExposed,
      });
    } catch (err) {
      probedPaths.push({
        path: p,
        status: 0,
        exposed: false,
      });
    }
  }

  return { easmPerimeter, probedPaths };
}
