export type ScanStatus = 'queued' | 'scanning' | 'analyzing' | 'complete' | 'failed';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface User {
  id: string;
  email: string;
  credits: number;
  apiKey: string;
  notifyWebhook?: string; // optional Slack-compatible alert webhook
  createdAt: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence?: 'low' | 'medium' | 'high';
  fix: string;
  category: string;
  owasp?: string; // mapped OWASP Top 10 2021 category, e.g. "A03:2021 – Injection"
  isFalsePositive?: boolean;
  suppressionReason?: string;
  suppressedAt?: string;
  endpoint?: string;
  rawRequest?: string;
  rawResponse?: string;
}

export interface SuppressionRule {
  id: string;
  userId: string;
  targetUrl: string;
  findingTitle: string;
  reason: string;
  createdAt: string;
}

// Reconnaissance + surface metadata captured during a scan. This is the real
// data behind the report's EASM/DAST panels (resolved IP, authoritative
// nameserver, live subdomains, probed paths, crawl surface) — persisted so the
// report renders actual findings context instead of placeholder values.
export interface ScanSubdomain {
  domain: string;
  status: 'live' | 'inactive';
  port: string;
}

export interface ScanProbedPath {
  path: string;
  status: number;
  exposed: boolean;
}

export interface ScanMetadata {
  responseStatus?: number;
  ip?: string;
  nameserver?: string;
  protocol?: string; // "HTTPS" | "HTTP"
  tls?: string; // human-readable TLS posture line
  serverHeader?: string;
  techLeaked?: string[];
  missingHeaders?: string[];
  liveSubdomains?: ScanSubdomain[];
  subdomainsChecked?: number;
  probedPaths?: ScanProbedPath[];
  crawl?: {
    pagesVisited: number;
    endpointsDiscovered: number;
    paramsTested: number;
    sampleEndpoints: string[];
  };
}

export interface Scan {
  id: string;
  userId: string;
  url: string;
  authHeader?: string;
  status: ScanStatus;
  score?: number; // 0 - 100
  severity?: Severity;
  findings?: Finding[];
  aiSummary?: string;
  metadata?: ScanMetadata; // reconnaissance + surface context (see above)
  error?: string;
  createdAt: string;
  completedAt?: string;
}

export interface CreditTransaction {
  id: string;
  userId: string;
  amount: number; // e.g. +5, -1
  type: 'purchase' | 'scan_debit';
  stripeSessionId?: string;
  createdAt: string;
}

export interface MonitoredTarget {
  id: string;
  userId: string;
  url: string;
  frequencyDays: number;
  scheduleString?: string;
  lastScannedAt?: string;
  nextScanAt?: string;
  createdAt: string;
}

export interface ApiKey {
  id: string;
  userId: string;
  key: string;
  credits: number;
  active: boolean;
  createdAt: string;
}
