import crypto from 'crypto';
import { User, Scan, ApiKey } from '../../src/types.js';

// Magic-link + session tokens are random secrets; only their SHA-256 hash is
// persisted so a DB read cannot reveal a usable login link or session token.
export function hashToken(raw: string): string {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

export function rowToUser(row: any): User | undefined {
  if (!row) return undefined;
  return {
    id: row.id, email: row.email, credits: row.credits, apiKey: row.apiKey,
    notifyWebhook: row.notifyWebhook ?? undefined, createdAt: row.createdAt,
  };
}

export function rowToScan(row: any): Scan | undefined {
  if (!row) return undefined;
  return {
    id: row.id,
    userId: row.userId,
    url: row.url,
    authHeader: row.authHeader ?? undefined,
    status: row.status,
    score: row.score ?? undefined,
    severity: row.severity ?? undefined,
    findings: row.findings ? JSON.parse(row.findings) : undefined,
    aiSummary: row.aiSummary ?? undefined,
    error: row.error ?? undefined,
    createdAt: row.createdAt,
    completedAt: row.completedAt ?? undefined,
  };
}

export function rowToApiKey(row: any): ApiKey {
  return {
    id: row.id, userId: row.userId, key: row.key,
    credits: row.credits, active: !!row.active, createdAt: row.createdAt,
  };
}
