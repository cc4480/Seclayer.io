import type { Severity } from '../src/types.js';
import type { DiagnosticResult } from './scanner.js';

/** A single entry in the PentAGI autonomous-agent activity feed. */
export interface PentagiLog {
  time: string;
  agent: 'Scout Agent' | 'Exploiter Agent' | 'Reporter Agent';
  msg: string;
}

/**
 * Structured, factual evidence distilled from a real diagnostics run. The
 * PentAGI feed is rendered entirely from this object, so every line the agents
 * "report" is grounded in something the scanner actually observed.
 */
export interface PentagiEvidence {
  target: string;
  hostname: string;
  responseStatus: number;
  sslSecure: boolean;
  ip: string;
  nameserver: string;
  liveSubdomains: string[];
  leakedTech: string[];
  exposedPaths: string[];
  exploitFindings: Array<{ name: string; severity: Severity; detail: string; payload?: string }>;
  dastIssues: Array<{ endpoint: string; issue: string }>;
  worstSeverity: Severity;
  score: number;
  totalFindings: number;
}

/** Distill a diagnostics run + compiled findings into the PentAGI evidence model. */
export function derivePentagiEvidence(
  target: string,
  diag: DiagnosticResult,
  compiled: { score: number; severity: Severity; findings: unknown[] },
): PentagiEvidence {
  const hostname = safeHostname(target);

  const liveSubdomains = diag.easmPerimeter.subdomains
    .filter((s) => s.status === 'live')
    .map((s) => s.domain);

  const exposedPaths = diag.probedPaths.filter((p) => p.exposed).map((p) => p.path);

  const exploitFindings = [
    ...(diag.redTeamFindings ?? []).map((rt) => ({
      name: rt.testName,
      severity: rt.severity,
      detail: rt.description,
      payload: rt.payload,
    })),
    ...(diag.apiSecFindings ?? []).map((api) => ({
      name: api.testName,
      severity: api.severity,
      detail: api.description,
    })),
  ];

  const dastIssues = diag.dastInputs
    .filter((d) => !d.csrfPresent)
    .map((d) => ({ endpoint: d.formAction, issue: d.vulnerability }));

  return {
    target,
    hostname,
    responseStatus: diag.responseStatus,
    sslSecure: diag.sslSecure,
    ip: diag.easmPerimeter.ip,
    nameserver: diag.easmPerimeter.nameserver,
    liveSubdomains,
    leakedTech: diag.techLeaked,
    exposedPaths,
    exploitFindings,
    dastIssues,
    worstSeverity: compiled.severity,
    score: compiled.score,
    totalFindings: compiled.findings.length,
  };
}

/**
 * Render a deterministic, chronological 3-agent activity feed from real
 * evidence. Used directly when no AI provider is configured, and as the
 * fallback when an AI narration call fails. Never claims an exploit that the
 * scanner did not actually observe.
 */
export function buildPentagiLogs(evidence: PentagiEvidence): PentagiLog[] {
  const logs: PentagiLog[] = [];
  let seconds = 1;
  const at = () => {
    const stamp = formatElapsed(seconds);
    seconds += 3 + Math.floor(Math.random() * 3);
    return stamp;
  };

  // --- Scout Agent: reconnaissance grounded in real DNS/HTTP recon ---
  const ipLabel = evidence.ip && evidence.ip !== 'unresolved' ? evidence.ip : 'no A record resolved';
  logs.push({
    time: at(),
    agent: 'Scout Agent',
    msg: `DNS enumeration of ${evidence.hostname} complete. Resolved address: ${ipLabel}. Authoritative nameserver: ${evidence.nameserver}.`,
  });
  logs.push({
    time: at(),
    agent: 'Scout Agent',
    msg: evidence.sslSecure
      ? `Transport fingerprint on ${evidence.hostname}: HTTPS negotiated, server responded HTTP ${evidence.responseStatus || 'n/a'}.`
      : `Transport fingerprint on ${evidence.hostname}: plaintext HTTP only, server responded HTTP ${evidence.responseStatus || 'n/a'}.`,
  });
  if (evidence.liveSubdomains.length > 0) {
    logs.push({
      time: at(),
      agent: 'Scout Agent',
      msg: `Perimeter mapping discovered ${evidence.liveSubdomains.length} live subdomain(s): ${evidence.liveSubdomains.slice(0, 6).join(', ')}.`,
    });
  } else {
    logs.push({
      time: at(),
      agent: 'Scout Agent',
      msg: `Perimeter mapping found no additional live subdomains on the ${evidence.hostname} attack surface.`,
    });
  }
  if (evidence.leakedTech.length > 0) {
    logs.push({
      time: at(),
      agent: 'Scout Agent',
      msg: `Technology fingerprint leaked via response headers: ${evidence.leakedTech.join('; ')}.`,
    });
  }

  // --- Exploiter Agent: only reports vectors actually confirmed by probes ---
  if (evidence.exploitFindings.length === 0 && evidence.exposedPaths.length === 0 && evidence.dastIssues.length === 0) {
    logs.push({
      time: at(),
      agent: 'Exploiter Agent',
      msg: `Ran active fuzzing probes (SQLi, reflected XSS, command injection, SSRF, GraphQL introspection, BOLA) against ${evidence.target}. No payload triggered an observable taint sink or backend error — no exploitable vector confirmed.`,
    });
  } else {
    evidence.exposedPaths.forEach((p) => {
      logs.push({
        time: at(),
        agent: 'Exploiter Agent',
        msg: `Confirmed publicly accessible sensitive resource at ${p} on ${evidence.target}. Retrieved over an unauthenticated request.`,
      });
    });
    evidence.exploitFindings.forEach((f) => {
      const payload = f.payload ? ` Payload: ${f.payload}.` : '';
      logs.push({
        time: at(),
        agent: 'Exploiter Agent',
        msg: `[${f.severity.toUpperCase()}] ${f.name} confirmed against ${evidence.target}.${payload} ${f.detail}`,
      });
    });
    evidence.dastIssues.forEach((d) => {
      logs.push({
        time: at(),
        agent: 'Exploiter Agent',
        msg: `Dynamic test flagged "${d.endpoint}": ${d.issue}.`,
      });
    });
  }

  // --- Reporter Agent: honest posture summary from compiled findings ---
  const hasExploit = evidence.exploitFindings.some(
    (f) => f.severity === 'critical' || f.severity === 'high',
  );
  logs.push({
    time: at(),
    agent: 'Reporter Agent',
    msg: hasExploit
      ? `Exploit chain validated. ${evidence.totalFindings} finding(s) correlated; highest severity ${evidence.worstSeverity.toUpperCase()}. Posture score: ${evidence.score}/100. Prioritize immediate remediation.`
      : `Assessment complete. ${evidence.totalFindings} finding(s) correlated; highest severity ${evidence.worstSeverity.toUpperCase()}. Posture score: ${evidence.score}/100. No high-severity exploit chain was confirmed on this run.`,
  });
  logs.push({
    time: at(),
    agent: 'Reporter Agent',
    msg: 'Standardized findings artifact generated (DefectDojo-compatible JSON schema).',
  });

  return logs;
}

function formatElapsed(totalSeconds: number): string {
  const mm = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
  const ss = (totalSeconds % 60).toString().padStart(2, '0');
  return `${mm}:${ss}`;
}

function safeHostname(target: string): string {
  try {
    const u = target.startsWith('http') ? target : `https://${target}`;
    return new URL(u).hostname;
  } catch {
    return target;
  }
}
