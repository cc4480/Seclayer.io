import { generatePentagiAnalysis } from './ai.js';
import {
  httpProbe as _httpProbe,
  httpProbeWithTiming as _httpProbeWithTiming,
} from './pentagi/network-probes.js';
import type { AgentName, FindingEntry, PentagiContext, PentagiLogEntry } from './pentagi/context.js';
import { reconDns } from './pentagi/recon-dns.js';
import { reconWeb } from './pentagi/recon-web.js';
import { exploitSurface } from './pentagi/exploit-surface.js';
import { exploitInjection } from './pentagi/exploit-injection.js';
import { exploitDisclosure } from './pentagi/exploit-disclosure.js';
import { exploitInjectionAdvanced } from './pentagi/exploit-injection-advanced.js';
import { exploitExposure } from './pentagi/exploit-exposure.js';
import { exploitAuthenticated } from './pentagi/exploit-authenticated.js';

export type { PentagiLogEntry } from './pentagi/context.js';

export async function runPentagiExploit(
  url: string,
  authHeaders: Record<string, string> = {},
  onLog?: (entry: PentagiLogEntry) => void,
): Promise<PentagiLogEntry[]> {
  const logs: PentagiLogEntry[] = [];
  const findings: FindingEntry[] = [];
  const t0 = Date.now();

  const log = (agent: AgentName, msg: string) => {
    const ms = Date.now() - t0;
    const time = `${String(Math.floor(ms / 60000)).padStart(2, '0')}:${String(Math.floor((ms % 60000) / 1000)).padStart(2, '0')}`;
    const entry: PentagiLogEntry = { time, agent, msg };
    logs.push(entry);
    // Stream the entry to the caller as it is produced so the UI reflects real,
    // in-flight progress rather than a replayed animation.
    try { onLog?.(entry); } catch { /* never let a consumer error abort the run */ }
    console.log(`[PentAGI][${time}] ${agent}: ${msg}`);
  };

  // Auth-aware probe wrappers — automatically inject authHeaders into every request.
  // Probe-specific headers (e.g. a custom Origin) always override auth headers.
  const httpProbe = (u: string, init: RequestInit = {}, timeoutMs = 4000) =>
    _httpProbe(u, {
      ...init,
      headers: { ...authHeaders, ...(init.headers as Record<string, string> ?? {}) },
    }, timeoutMs);
  const httpProbeWithTiming = (u: string, init: RequestInit = {}, timeoutMs = 8000) =>
    _httpProbeWithTiming(u, {
      ...init,
      headers: { ...authHeaders, ...(init.headers as Record<string, string> ?? {}) },
    }, timeoutMs);

  let targetUrl = url.trim();
  if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    log('Reporter Agent', `Invalid target URL: ${url}`);
    return logs;
  }

  const hostname = parsed.hostname;
  const origin = parsed.origin;
  const isHttps = parsed.protocol === 'https:';

  // Shared state handed to every stage module. Stage functions destructure this
  // back into the same local names the probes use, keeping their bodies verbatim.
  const ctx: PentagiContext = {
    url, targetUrl, origin, hostname, isHttps, authHeaders,
    findings, log, httpProbe, httpProbeWithTiming,
  };

  // ==========================================================
  // STAGE 1: SCOUT AGENT — RECONNAISSANCE
  // ==========================================================

  await reconDns(ctx);

  await reconWeb(ctx);

  // ==========================================================
  // STAGE 2: EXPLOITER AGENT — ACTIVE EXPLOIT PROBES
  // ==========================================================

  await exploitSurface(ctx);

  await exploitInjection(ctx);

  await exploitDisclosure(ctx);

  await exploitInjectionAdvanced(ctx);

  await exploitExposure(ctx);

  await exploitAuthenticated(ctx);

  // ==========================================================
  // STAGE 3: REPORTER AGENT — COMPILE RESULTS
  // ==========================================================

  log('Reporter Agent', `Pentest session complete. Compiling ${findings.length} confirmed finding${findings.length !== 1 ? 's' : ''}...`);

  const bySev = {
    critical: findings.filter(f => f.severity === 'critical'),
    high: findings.filter(f => f.severity === 'high'),
    medium: findings.filter(f => f.severity === 'medium'),
    low: findings.filter(f => f.severity === 'low'),
  };

  if (bySev.critical.length > 0) {
    log('Reporter Agent', `[CRITICAL ×${bySev.critical.length}] ${bySev.critical.map(f => f.title).join(' | ')}`);
  }
  if (bySev.high.length > 0) {
    log('Reporter Agent', `[HIGH ×${bySev.high.length}] ${bySev.high.map(f => f.title).join(' | ')}`);
  }
  if (bySev.medium.length > 0) {
    log('Reporter Agent', `[MEDIUM ×${bySev.medium.length}] ${bySev.medium.map(f => f.title).join(' | ')}`);
  }
  if (bySev.low.length > 0) {
    log('Reporter Agent', `[LOW ×${bySev.low.length}] ${bySev.low.map(f => f.title).join(' | ')}`);
  }
  if (findings.length === 0) {
    log('Reporter Agent', 'No confirmed exploitable vulnerabilities detected. Strong baseline security posture observed.');
  }

  const riskScore = Math.max(10, 100 - bySev.critical.length * 30 - bySev.high.length * 15 - bySev.medium.length * 5 - bySev.low.length * 2);
  const riskLevel = bySev.critical.length > 0 ? 'CRITICAL' : bySev.high.length > 0 ? 'HIGH' : bySev.medium.length > 0 ? 'MEDIUM' : 'LOW';
  log('Reporter Agent', `Risk rating: ${riskLevel} | Posture score: ${riskScore}/100 | Session artifacts archived`);

  // AI-synthesized strategic analysis of the real findings (DeepSeek when
  // configured, deterministic otherwise). This is the genuine AI step in the run.
  log('Reporter Agent', 'Synthesizing strategic exploitation analysis from confirmed findings...');
  const analysis = await generatePentagiAnalysis(url, findings);
  for (const line of analysis) {
    log('Reporter Agent', line);
  }

  return logs;
}
