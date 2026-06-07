# Seclayer.io

Black-box penetration testing SaaS. Scan any public web target and get a structured security report powered by AI analysis, DAST probing, and certificate transparency lookups.

## Features

- **Black-box scanner** — HTTP diagnostics, SSL/TLS inspection, security header analysis, cookie auditing, sensitive path discovery
- **AI-powered reports** — DeepSeek analysis produces executive summaries and actionable remediation guidance; degrades gracefully without an API key
- **PentAGI exploit runner** — real multi-stage automated exploit probes: port scanning, DNS enumeration, CORS reflection, SQLi/XSS/SSTI/LFI/CRLF, Host-header injection, GraphQL introspection, admin panel discovery
- **EASM** — real DNS + crt.sh certificate transparency subdomain enumeration
- **ASPM** — cross-scan vulnerability correlation and risk aggregation
- **Continuous monitoring** — schedule recurring scans for any target
- **Suppression rules** — mark false positives and filter findings per URL
- **API key access** — machine-to-machine scanning via Bearer key authentication

## Stack

| Layer | Tech |
|---|---|
| Frontend | React 19, TypeScript, Tailwind CSS, Vite |
| Backend | Express, TypeScript, ESM |
| Auth | JWT (HS256) + bcrypt |
| Database | File-backed JSON (`LocalFileDb`) |
| AI | DeepSeek via OpenAI-compatible SDK |
| Tests | Vitest + Supertest (129 tests) |

## Quick Start

**Prerequisites:** Node.js 20+

```bash
git clone <repo>
cd Seclayer.io
npm install
cp .env.example .env
# Edit .env — at minimum set JWT_SECRET
npm run dev
```

Open `http://localhost:3000`. Register an account — you receive 5 free scan credits.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET` | Yes | Secret for signing session tokens. Use a long random string in production. Generate: `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
| `DEEPSEEK_API_KEY` | No | Powers AI report summaries. Without it, a local rule-based summary is used. Get one at [platform.deepseek.com](https://platform.deepseek.com/api_keys) |
| `NODE_ENV` | No | Set to `production` when deploying |

## Scripts

```bash
npm run dev      # Start dev server (Vite + Express, HMR enabled)
npm run build    # Build for production
npm start        # Serve production build
npm test         # Run test suite (Vitest)
```

## API

All scan endpoints require `Authorization: Bearer <token>` (JWT) or a valid API key (`POST /api/mcp/scan`).

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Register a new account |
| `POST` | `/api/auth/login` | Login, returns JWT |
| `GET` | `/api/auth/me` | Current user |
| `POST` | `/api/scans` | Start a new scan (costs 1 credit) |
| `GET` | `/api/scans` | List scans |
| `GET` | `/api/scans/:id` | Get scan status |
| `GET` | `/api/scans/:id/logs` | Real-time scan logs |
| `GET` | `/api/scans/:id/report` | Full security report |
| `POST` | `/api/mcp/scan` | Machine-to-machine scan via API key |
| `GET` | `/api/keys` | List API keys |
| `POST` | `/api/keys` | Generate API key |
| `DELETE` | `/api/keys/:id` | Revoke API key |
| `GET` | `/api/monitoring` | List monitored targets |
| `POST` | `/api/monitoring` | Add monitoring target |
| `DELETE` | `/api/monitoring/:id` | Remove monitoring target |
| `GET` | `/api/suppressions` | List suppression rules |
| `POST` | `/api/suppressions` | Add suppression rule |
| `DELETE` | `/api/suppressions/:id` | Delete suppression rule |
| `POST` | `/api/enterprise/aspm/correlate` | Cross-scan correlation |
| `POST` | `/api/enterprise/easm/recon` | DNS + subdomain enumeration |
| `POST` | `/api/enterprise/api-scan/hadrian` | API endpoint discovery |
| `GET` | `/api/enterprise/pentagi/logs` | Autonomous exploit runner |

## Security

- SSRF protection: private/loopback IPs and RFC1918 ranges are blocked on all scan-accepting routes
- Rate limiting: auth endpoints 30 req/15 min, scan endpoints 15 req/min
- Security headers: HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Passwords hashed with bcrypt (12 rounds)
