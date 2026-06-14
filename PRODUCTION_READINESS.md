# Production Readiness

A candid assessment of what is production-ready and what is not. Scope: the
application and the scanning engine. Payments (Stripe) are intentionally a mock
and are out of scope here.

## TL;DR

The **scanning engine, scan lifecycle, and authentication are production-ready**
— real detection across 16 vulnerability classes, validated PoCs, a CI-enforced
0% false-positive benchmark, bounded concurrency, crash recovery, a working
monitoring scheduler, and signed session-cookie auth so requests can no longer
impersonate another user. The main gap before a **multi-tenant public launch**
is **datastore scale** (plus real payments, parked separately).

---

## ✅ Production-ready

### Scanning engine
- Real active probes: SQLi, reflected & stored XSS, OS command injection, SSRF,
  GraphQL introspection, BOLA, IDOR — each confirmed with control comparison and
  re-issued for reproducibility.
- Static/recon classes: hardcoded secrets (SAST), outdated libraries (SCA),
  exposed `.env`/`.git`/`phpinfo()`, missing CSRF tokens, missing security
  headers, tech/version disclosure.
- Bounded same-origin **crawler**, **chain detectors** (stored XSS, IDOR),
  **crawl-driven parameter fuzzing**, and **authenticated scanning** (bearer
  token *and* form-login session cookie).
- Every confirmed exploit ships a **reproducible PoC** (runnable curl + evidence,
  credentials redacted) and a validation status surfaced in the report UI.
- **False-positive suppression**: soft-404/SPA-shell baseline calibration,
  control-relative injection evidence, and structured (not substring) validation.
- **Accuracy benchmark** (`npm run benchmark`): 16/16 detection, 0/16 false
  positives, 10 validated PoCs — CI-gated, and the landing-page numbers are
  asserted against the live scanner so they cannot drift.
- Enterprise modules (ASPM, EASM, IAST, Hadrian, PentAGI) all derive from real
  diagnostics; PentAGI narrates only real evidence (AI when configured,
  deterministic fallback otherwise).

### Scan lifecycle & reliability
- **Bounded job queue** (`SCAN_MAX_CONCURRENT`, default 3) with a hard
  **per-job timeout** (`SCAN_TIMEOUT_MS`, default 180s).
- **Crash recovery**: scans left mid-flight by a restart are marked failed on
  startup — none stay stuck.
- **Continuous-monitoring scheduler**: due targets are scanned on schedule
  (credit-charged, rescheduled), disabled under test, stopped on shutdown.

### Authentication & sessions
- **Signed, HttpOnly session cookies** (HMAC-SHA256, `base64url(payload).base64url(sig)`,
  constant-time signature check, expiry enforced server-side). Login issues a
  cookie; logout clears it. No server-side session store needed.
- Every `/api/*` route derives identity from `currentUserId(req)` — the
  verified session, or the shared `user_default` account for anonymous callers
  — never from a client-supplied `userId` in the query or body. A caller can no
  longer act as, or read the data of, another user by passing their id.

### Platform
- Fail-fast **config validation** (throws in production on invalid config,
  including a missing `SESSION_SECRET`).
- **SSRF protection** on every scan path, including monitored URLs validated at
  add-time and DNS-rebinding-aware private-range checks.
- Strong **security headers** (CSP, HSTS preload, X-Frame-Options, nosniff,
  Permissions-Policy), configurable **CORS** allowlist, body-size limits.
- In-memory **rate limiting** (general + stricter scan limiter).
- Centralized **error handling** with request IDs; **structured logging**.
- **Graceful shutdown** (SIGTERM/SIGINT drain) and process guards.
- **Atomic datastore writes** (temp-file + rename).
- **Liveness/readiness probes** (`/api/system/health`, `/api/system/ready`),
  the latter reporting datastore health, AI provider, and scan-queue depth.
- **76 tests** + CI (typecheck + tests + build).

---

## ⚠️ Not production-ready (known gaps)

### 1. Datastore scale — **highest remaining priority**
A JSON file (atomic, single-node) backs all state. Correct and safe for a single
instance, but it does not scale horizontally, has no write-throughput headroom,
and **grows unbounded** (no scan-retention/pruning policy).

**For scale:** migrate to Postgres/SQLite, add a retention policy for old scans,
and a distributed lock for the monitoring scheduler if running >1 instance
(today, multiple instances would double-run monitors).

### 2. API keys at rest
Developer API keys are stored in plaintext (so they can be re-displayed in the
dashboard). **For production:** store a hash and show the key only once at
creation.

### 3. Payments
Stripe checkout/webhook are mocks (instant credit top-up). Parked intentionally;
wire real Stripe (Checkout session + signature-verified webhook) before charging.

### 4. Observability depth
Structured logs + readiness probe are in place, but there is no metrics/tracing
export (Prometheus/OpenTelemetry). Add if you need dashboards/alerting.

### 5. Login is passwordless
Login is email → user record with no password/OTP/magic-link verification, so
anyone who knows (or guesses) an email can obtain that account's session cookie.
The session layer itself is now sound (signed, HttpOnly, expiring); what's
missing is verifying the email belongs to the caller before issuing it.
**Before multi-tenant launch:** add magic-link email verification or
passwordless OTP before `setSessionCookie` is called.

---

## Operational configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SESSION_SECRET` | dev fallback | HMAC key for session cookies — **required in prod** |
| `SESSION_TTL_SECONDS` | `604800` (7d) | Session cookie lifetime |
| `SCAN_MAX_CONCURRENT` | `3` | Max concurrent scan jobs |
| `SCAN_TIMEOUT_MS` | `180000` | Hard per-scan timeout |
| `MONITORING_ENABLED` | on (off in test) | Run the monitoring scheduler |
| `MONITORING_POLL_MS` | `60000` | Scheduler poll interval |
| `SCANNER_ALLOW_PRIVATE_TARGETS` | off in prod | SSRF guard (lab use only) |
| `RATE_LIMIT_*` | see config | Request rate limits |
| `DEEPSEEK_API_KEY` | — | AI reports (deterministic fallback if unset) |
| `CORS_ORIGINS` | same-origin | CORS allowlist |
| `APP_URL` | localhost | Public URL for self-links |

See `.env.example` for the full list. Verify accuracy any time with
`npm run benchmark`; gate releases on `npm run ci`.
