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
