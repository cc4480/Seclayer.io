# Seclayer

**Pay-Per-Scan Black-Box Penetration Testing SaaS & MCP Server.**

Seclayer runs automated black-box security assessments against a target URL and
returns a structured pentest report (posture score, severity, prioritized
findings, and an executive summary). It exposes a web dashboard, a REST API, and
an MCP-compatible endpoint so AI agents can trigger scans programmatically.

The scan engine performs real network diagnostics — security-header analysis,
TLS checks, SAST/SCA pattern matching on returned markup, DAST form inspection,
subdomain/EASM enumeration via DNS, sensitive-path probing, and active red-team
fuzzing (SQLi / XSS / command injection / SSRF probes) — then optionally enriches
the report with the Gemini API (with a deterministic local fallback when no key
is configured).

## Tech stack

- **Frontend:** React 19 + Vite 6 + Tailwind CSS 4
- **Backend:** Express 4 (TypeScript), bundled to a single CJS file with esbuild
- **Datastore:** append-safe JSON file store (atomic writes)
- **AI:** Google Gemini (`@google/genai`), optional

## Quick start

**Prerequisites:** Node.js >= 20

```bash
npm install
cp .env.example .env      # optionally set GEMINI_API_KEY
npm run dev               # http://localhost:3000
```

The app is fully functional without a Gemini key — report summaries fall back to
a deterministic local generator.

## Scripts

| Script | Description |
| --- | --- |
| `npm run dev` | Start the dev server (Vite middleware + API) with hot reload. |
| `npm run build` | Build the client bundle and the production server (`dist/`). |
| `npm start` | Run the built production server (`dist/server.cjs`). |
| `npm run typecheck` / `npm run lint` | Type-check the whole project (`tsc --noEmit`). |
| `npm test` | Run the unit test suite (Node's built-in test runner). |
| `npm run ci` | Type-check, test, and build — the full local CI gate. |

## Configuration

All configuration is environment-driven and validated at startup; see
[`.env.example`](.env.example) for the complete list. Key variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | _(unset)_ | Enables AI report enrichment; falls back to local summaries when absent. |
| `PORT` / `HOST` | `3000` / `0.0.0.0` | HTTP bind. |
| `NODE_ENV` | `development` | `development` \| `production` \| `test`. |
| `LOG_LEVEL` / `LOG_JSON` | `info` / `true` (prod) | Logging verbosity and format. |
| `CORS_ORIGINS` | _(empty)_ | Comma-separated CORS allowlist. |
| `SCANNER_ALLOW_PRIVATE_TARGETS` | `false` (prod) | SSRF guard — block scanning private/internal addresses. |
| `RATE_LIMIT_*` | `120/min`, scans `10/min` | API rate limits. |

## API surface

- `POST /api/auth/login` — passwordless email login.
- `POST /api/scans` — queue a scan (deducts 1 credit; SSRF-guarded).
- `GET  /api/scans/:id` / `:id/report` — scan status and final report.
- `POST /api/mcp/scan` — synchronous scan for MCP agents (API-key authenticated).
- `GET  /api/system/health` — liveness probe.
- `GET  /api/system/ready` — readiness probe (datastore + AI provider status).

Suppression rules, continuous monitoring, credits/checkout, API-key management,
and the enterprise pipeline demos (`/api/enterprise/*`) are also exposed.

## Production readiness

The platform ships with: centralized validated configuration, structured
JSON logging with per-request correlation IDs, an SSRF guard on scan targets,
input validation on all write endpoints, in-memory rate limiting, hardened
security headers (including CSP), CORS allowlisting, body-size limits, a
centralized error handler, graceful shutdown, process-level crash guards,
health/readiness probes, a unit test suite, and a CI pipeline. See
[`docs/PRODUCTION.md`](docs/PRODUCTION.md) for the full audit and deployment
notes.

## Deployment

```bash
docker build -t seclayer .
docker run -p 3000:3000 -e GEMINI_API_KEY=... -e NODE_ENV=production seclayer
```

The image runs as a non-root user and includes a container `HEALTHCHECK`.
For non-container deployment, run `npm run build` then `npm start`.
