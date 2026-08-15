// Thin wrappers over the backend HTTP API. Each returns the raw Response so
// callers keep full control over status/ok handling; identity travels via the
// httpOnly session cookie, so no userId is ever passed from the client.

const jsonHeaders = { 'Content-Type': 'application/json' };

export const api = {
  me: () => fetch('/api/auth/me'),
  scans: () => fetch('/api/scans'),
  keys: () => fetch('/api/keys'),
  credits: () => fetch('/api/credits'),
  logout: () => fetch('/api/auth/logout', { method: 'POST' }),

  createScan: (url: string, authHeader?: string) =>
    fetch('/api/scans', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ url, authHeader }),
    }),

  generateKey: () => fetch('/api/keys', { method: 'POST', headers: jsonHeaders }),

  revokeKey: (keyId: string) => fetch(`/api/keys/${keyId}`, { method: 'DELETE' }),

  checkout: (pack: string) =>
    fetch('/api/credits/checkout', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ pack }),
    }),
};
