import crypto from 'crypto';

export interface OastInteraction {
  token: string;
  timestamp: number;
  sourceIp: string;
  path: string;
  method: string;
}

// In-memory store: token → interactions
const store = new Map<string, OastInteraction[]>();
const tokenCreatedAt = new Map<string, number>();

export function createOastToken(): string {
  const token = crypto.randomBytes(14).toString('hex');
  store.set(token, []);
  tokenCreatedAt.set(token, Date.now());
  return token;
}

export function recordInteraction(token: string, sourceIp: string, path: string, method: string): void {
  const list = store.get(token);
  if (!list) return;
  list.push({ token, timestamp: Date.now(), sourceIp, path, method });
}

export function hasInteraction(token: string): boolean {
  return (store.get(token)?.length ?? 0) > 0;
}

export function getInteractions(token: string): OastInteraction[] {
  return store.get(token) ?? [];
}

// Poll until a callback arrives or timeout expires
export function waitForInteraction(token: string, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    if (hasInteraction(token)) { resolve(true); return; }
    const pollMs = 300;
    let elapsed = 0;
    const iv = setInterval(() => {
      elapsed += pollMs;
      if (hasInteraction(token)) { clearInterval(iv); resolve(true); }
      else if (elapsed >= timeoutMs) { clearInterval(iv); resolve(false); }
    }, pollMs);
  });
}

// Evict tokens older than 2 hours every 10 minutes
setInterval(() => {
  const cutoff = Date.now() - 7_200_000;
  for (const [token, ts] of tokenCreatedAt.entries()) {
    if (ts < cutoff) { store.delete(token); tokenCreatedAt.delete(token); }
  }
}, 600_000).unref();
