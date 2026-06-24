export type AgentName = 'Scout Agent' | 'Exploiter Agent' | 'Reporter Agent';
export type PentagiLogEntry = { time: string; agent: AgentName; msg: string };
export type FindingEntry = { severity: 'critical' | 'high' | 'medium' | 'low'; title: string };

export type ProbeResult = { status: number; body: string; headers: Record<string, string> } | null;
export type TimingProbeResult =
  | { status: number; body: string; headers: Record<string, string>; elapsedMs: number }
  | null;

/**
 * Shared state threaded through every PentAGI stage. Stage modules destructure
 * this object back into the same local names the probes originally used, so the
 * probe bodies remain byte-for-byte identical to the pre-refactor implementation.
 */
export interface PentagiContext {
  /** Raw, un-normalized target URL exactly as supplied by the caller. */
  url: string;
  /** Normalized target URL (scheme guaranteed). */
  targetUrl: string;
  origin: string;
  hostname: string;
  isHttps: boolean;
  authHeaders: Record<string, string>;
  findings: FindingEntry[];
  log: (agent: AgentName, msg: string) => void;
  httpProbe: (u: string, init?: RequestInit, timeoutMs?: number) => Promise<ProbeResult>;
  httpProbeWithTiming: (u: string, init?: RequestInit, timeoutMs?: number) => Promise<TimingProbeResult>;
}
