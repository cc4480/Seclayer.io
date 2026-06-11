# Scanner Accuracy Benchmark

A reproducible measurement of the scanner's **detection rate** and
**false-positive rate** against labeled ground truth. Unlike scanning a live
third-party app, this benchmark is deterministic and runs anywhere — no external
network dependency on DVWA / Juice Shop being reachable.

## Run it

```bash
npm run benchmark      # prints the report and writes bench/results.json
npm test               # the same checks run as a CI-gated test (tests/benchmark.test.ts)
```

## Method

Local fixture targets with a known ground truth (`bench/fixtures.ts`):

- **Vulnerable target** — exposes exactly one genuine instance of each of the
  **12 detectable vulnerability classes**, shaped to match what the scanner
  actually sends: Reflected XSS, SQL Injection, OS Command Injection, SSRF,
  GraphQL introspection, BOLA, exposed `.env`, exposed `.git/config`, exposed
  `phpinfo()`, a hardcoded secret (SAST), an outdated library (SCA), and a
  CSRF-unprotected form. Unknown paths return a real 404 so the soft-404
  baseline is clean.

- **Clean target** — a hardened app and a deliberate **false-positive trap**. It
  answers `200` for *every* path with the same shell (soft-404) and embeds every
  decoy a naive scanner keys on: `SQL syntax`, `uid=0(root) gid=…`, `__schema`,
  `email`, `Protocol mismatch`, a near-miss `AKIA…` secret, a **patched** jQuery
  3.x, a CSRF-protected form, and a reflected — but HTML-encoded — query
  parameter. Its `/graphql` echoes the query in an error (so the response
  contains `__schema` without being a real introspection result). A correct
  scanner reports **zero** findings here.

- **Authenticated target** — gates a BOLA endpoint behind a Bearer token. The
  benchmark scans it with and without credentials and proves the authenticated
  scan reaches a finding the anonymous scan cannot.

The real scanner (`runDiagnostics` + `compileStaticFindings`) runs against each
target; findings are scored against the labels (`bench/scoring.ts`). Set
`BENCH_REAL_TARGET=http://host:port` to additionally profile a live app
(e.g. a local DVWA / Juice Shop) when network is available.

Header/protocol findings (e.g. "missing HSTS", "plaintext HTTP") are
deterministic facts and are intentionally **out of scope** for the
false-positive metric — the benchmark measures the precision of the high-signal
active probes, which is what the calibration and validation logic governs.

## Headline result

| Metric | Result |
| --- | --- |
| Detection rate (recall) | **100%** (12 / 12) |
| False-positive rate | **0%** (0 / 12) |
| Precision | **100%** |
| Re-confirmed PoCs | **6** (XSS, SQLi, cmd injection, SSRF, GraphQL, BOLA) |
| Authenticated scanning | **proven** (reaches a gated finding) |

The clean target's decoys — which would each trip a substring-based scanner —
are all suppressed by the soft-404 baseline calibration and the
control-comparison / structured-validation checks.

The benchmark gates on `detection == 100%`, `false positives == 0`, and proven
authenticated scanning; it fails otherwise, so regressions in scanner precision
are caught in CI. The same headline numbers are published on the landing page
via `src/lib/benchmark-stats.ts`, which a CI test asserts against this live
benchmark — so the marketing number can never drift from the engine.
