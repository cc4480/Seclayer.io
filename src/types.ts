export type ScanStatus = 'queued' | 'scanning' | 'analyzing' | 'complete' | 'failed';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface User {
  id: string;
  email: string;
  credits: number;
  apiKey: string;
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
  isFalsePositive?: boolean;
  suppressionReason?: string;
  suppressedAt?: string;
  endpoint?: string;
  rawRequest?: string;
  rawResponse?: string;
  plainEnglish?: string;
  codeFixExample?: string;
}

export interface SuppressionRule {
  id: string;
  userId: string;
  targetUrl: string;
  findingTitle: string;
  reason: string;
  createdAt: string;
}

export interface ScanDiagnostics {
  responseStatus: number;
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
  ip: string;
  nameserver: string;
  protocol: string;
  probedPaths: Array<{ path: string; status: number; exposed: boolean }>;
  techLeaked: string[];
  missingHeaders: string[];
  liveSubdomains: number;
}

export interface CrawlPage {
  url: string;
  status: number;
  depth: number;
  title?: string;
  contentType?: string;
}

export interface CrawlForm {
  pageUrl: string;
  action: string;
  method: string;
  inputs: string[];
  hasPassword: boolean;
  hasCsrfToken: boolean;
  insecure: boolean; // submits over plain HTTP
}

export interface CrawlResult {
  startUrl: string;
  pagesCrawled: number;
  maxDepthReached: number;
  durationMs: number;
  authenticated: boolean;
  pages: CrawlPage[];
  forms: CrawlForm[];
  discoveredParams: string[];
}

export interface Scan {
  id: string;
  userId: string;
  url: string;
  authHeader?: string;
  authProfileId?: string;
  webhookUrl?: string;
  status: ScanStatus;
  score?: number; // 0 - 100
  severity?: Severity;
  findings?: Finding[];
  aiSummary?: string;
  diagnostics?: ScanDiagnostics;
  crawl?: CrawlResult;
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

export type AuthType = 'cookie' | 'bearer' | 'header' | 'basic' | 'form';

export interface AuthProfile {
  id: string;
  userId: string;
  name: string;
  type: AuthType;
  // cookie / bearer / header
  headerName?: string;
  headerValue?: string;
  // basic
  username?: string;
  password?: string;
  // form-based login
  loginUrl?: string;
  loginUsernameField?: string;
  loginPasswordField?: string;
  loginUsername?: string;
  loginPassword?: string;
  verifiedAt?: string;
  createdAt: string;
}
