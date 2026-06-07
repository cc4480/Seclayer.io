# Seclayer

Pay-Per-Scan black-box penetration testing SaaS with an MCP scan endpoint.

Seclayer runs real black-box checks against a target URL — security headers,
TLS, cookie flags, exposed-secret signatures, vulnerable-library detection,
DNS/subdomain recon, sensitive-path probing, and active SQLi / XSS /
command-injection / SSRF / GraphQL / object-level-authorization probes — then
enriches the results with a DeepSeek-generated executive report and a posture
score. Findings are designed for high precision (signature-confirmed) to avoid
false positives.

## Stack

- **Frontend:** React 19 + Vite 6 + Tailwind 4
- **Backend:** Express 4 (TypeScript via tsx), better-sqlite3
- **Auth:** passwordless magic-link sign-in with httpOnly session cookies
- **AI:** DeepSeek (OpenAI-compatible API), with local fallback summaries
- **Email:** Resend (magic links); console fallback in dev
- **Payments:** Stripe Checkout + signed webhooks

## Run locally

**Prerequisites:** Node.js 22+

```bash
npm install
cp .env.example .env.local   # optional: configure keys
npm run dev                  # http://localhost:3000
```

With no keys set, the app still runs: AI uses local summaries, magic-link URLs
are printed to the server console (and returned to the dev UI), and credit
purchases are disabled.

## Scripts

- `npm run dev` — server + Vite dev middleware
- `npm run lint` — TypeScript typecheck (`tsc --noEmit`)
- `npm test` — unit tests (Node test runner)
- `npm run build` — build client + bundle server to `dist/`
- `npm start` — run the production build

## Configuration

See [.env.example](.env.example). Key variables:

| Variable | Purpose |
|----------|---------|
| `NODE_ENV` | `production` enables Secure cookies, HSTS, trust-proxy, static serving |
| `PORT` | Listen port (default 3000) |
| `APP_URL` | Public base URL (magic-link + checkout redirect URLs) |
| `DB_PATH` | SQLite file path (default `./data.sqlite`) |
| `DEEPSEEK_API_KEY` | Enables AI reports (else local summaries) |
| `RESEND_API_KEY` / `EMAIL_FROM` | Sends magic-link emails (else console) |
| `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` | Enables credit purchases |

Point your Stripe webhook at `POST /api/webhooks/stripe`
(`checkout.session.completed`). Credits are granted only on a verified webhook.

## Deployment

```bash
docker build -t seclayer .
docker run -p 3000:3000 --env-file .env.local -v seclayer-data:/data seclayer
```

The container exposes a `/api/system/health` healthcheck and stores its SQLite
database on the `/data` volume. CI (`.github/workflows/ci.yml`) runs typecheck,
tests, and build on every push.
