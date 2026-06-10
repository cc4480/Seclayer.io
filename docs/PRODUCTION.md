# Production Readiness — Audit & Notes

This document records the production-readiness audit of the Seclayer platform:
what was implemented to harden the application, and the remaining
recommendations that require product/infra decisions before a real launch.

## Implemented in this pass

### Configuration management
- `server/config.ts` centralizes **all** environment access behind one typed,
  validated module. Nothing else reads `process.env` directly.
- `validateConfig()` runs at startup, fails fast on invalid values (bad
  `LOG_LEVEL`, out-of-range `PORT`), and emits warnings for risky production
  settings (localhost `APP_URL`, SSRF guard disabled, missing AI key).
- Every variable is documented in `.env.example`.

### Logging & observability
- `server/logger.ts` is a dependency-free leveled logger. It emits
  line-delimited JSON in production (for log aggregators) and human-readable
  text in development.
- Every request gets a correlation ID (`X-Request-Id`, honored from upstream if
  present) and a child logger; access logs include method, path, status, and
  duration. 5xx vs 4xx are logged at appropriate levels to avoid alert noise.
- Health (`/api/system/health`) and readiness (`/api/system/ready`) probes.

### Security
- **SSRF guard** (`server/validation.ts`): scan targets are normalized and
  resolved; targets in private/loopback/link-local/CGNAT/reserved ranges
  (incl. cloud metadata `169.254.169.254` and IPv6 equivalents) are rejected
  unless `SCANNER_ALLOW_PRIVATE_TARGETS=true`. This closes the SSRF vector
  inherent to a product that fetches user-supplied URLs.
- **Input validation** on all write endpoints (email shape, URL scheme/length,
  required/optional string caps, numeric bounds). Non-http(s) schemes such as
  `ftp:`, `file:`, and `javascript:` are rejected rather than mangled.
- **Security headers** including a real Content-Security-Policy, HSTS,
  `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and
  `Permissions-Policy`.
- **Rate limiting** — general API cap plus a stricter cap on expensive scan
  endpoints, with standard `X-RateLimit-*` / `Retry-After` headers.
- **CORS** allowlist, **body-size limits**, and `x-powered-by` disabled.

### Reliability & error handling
- Centralized Express error handler with a typed `HttpError`; internal details
  and stack traces are never leaked in production responses.
- `asyncHandler` wrapper so rejected promises in async routes reach the error
  handler instead of crashing the process.
- JSON 404 handler for unknown API routes (the SPA fallback no longer swallows
  unmatched `/api/*` paths).
- **Graceful shutdown** on SIGTERM/SIGINT (drains connections, 10s force-exit
  timeout) and process-level `unhandledRejection` / `uncaughtException` guards.
- The background scan worker isolates failures and records a `failed` state.

### Data layer
- `server/db.ts` now writes **atomically** (temp file + rename) so a crash
  mid-write cannot corrupt `db.json`.
- Added a public `listTransactions()` accessor and `isHealthy()` readiness
  check, removing the previous `(db as any).data` private-field access.

### Testing & CI/CD
- Unit tests (`tests/`) using Node's built-in runner — no new dependencies —
  covering the SSRF guard, input validation, scan scoring, and URL/email
  normalization.
- `.github/workflows/ci.yml` runs type-check, tests, and build on Node 20 & 22,
  plus an `npm audit` job for production dependencies.

### Packaging
- Multi-stage `Dockerfile` (non-root user, production-only deps, container
  `HEALTHCHECK`) and `.dockerignore`.
- `engines.node >= 20`, real package name, and `typecheck` / `test` / `ci`
  scripts.

## Recommendations not yet implemented

These are deliberate scope boundaries — they change product behavior or require
infrastructure choices and credentials.

1. **Real authentication & authorization.** Login is currently passwordless by
   email and `userId` is passed by the client, so any user can read another
   user's data by guessing an ID. Before launch: issue signed, httpOnly session
   cookies (or JWTs) on login, derive `userId` server-side from the session, and
   authorize every resource access against it. The MCP endpoint already
   authenticates by API key and is the right model to generalize from.
2. **Durable datastore.** The JSON file store is single-instance and not safe
   for concurrent writers or horizontal scaling. Move to Postgres (the data
   model maps cleanly to tables) behind a repository interface; keep the file
   store as a dev fallback.
3. **Real payments.** `/api/credits/checkout` and `/api/webhooks/stripe` are
   mocks that grant credits instantly. Integrate Stripe Checkout + verified
   webhook signatures, and make credit grants idempotent on the webhook.
4. **Distributed rate limiting & job queue.** The in-memory limiter and the
   in-process scan worker are single-instance. For multiple replicas, back the
   limiter with Redis and move scans to a real queue (pg-boss/BullMQ).
5. **Secret management.** Inject secrets from a managed store (Cloud Run / AWS
   Secrets Manager / Vault) rather than a committed `.env`.
6. **Frontend bundle size.** The client bundle exceeds 500 kB; code-split heavy
   dependencies (`jspdf`, `html2canvas`) with dynamic `import()`.
7. **Scan abuse controls.** Beyond the SSRF guard, consider per-user scan
   quotas/cooldowns and an explicit authorization model so users can only scan
   domains they own or have permission to test.
