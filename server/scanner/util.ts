// Small pure helpers shared across scanner stages.

// Heuristic: does this body look like an HTML document (e.g. a single-page-app
// catch-all that returns index.html for every path)? Used to suppress false
// positives where a 200 response is just the SPA shell, not a real exposed file.
export function looksLikeHtml(body: string): boolean {
  const head = body.slice(0, 512).toLowerCase();
  return /<!doctype html|<html|<head|<body|<title|<div|<script|<meta/.test(head);
}

// Parses a user-supplied credential into request headers for authenticated
// scans. Accepts either a bare Authorization value ("Bearer …", "Basic …") or
// an explicit "Header-Name: value" (e.g. "Cookie: session=…", "X-API-Key: …"),
// enabling token, basic, cookie, or custom-header authentication.
export function parseAuthHeader(authHeader?: string): Record<string, string> {
  const raw = (authHeader || "").trim();
  if (!raw) return {};
  const idx = raw.indexOf(":");
  if (idx > 0) {
    const name = raw.slice(0, idx).trim();
    const value = raw.slice(idx + 1).trim();
    if (name && value && /^[A-Za-z0-9-]+$/.test(name) && !/^(bearer|basic|negotiate|digest)$/i.test(name)) {
      return { [name]: value };
    }
  }
  return { Authorization: raw };
}
