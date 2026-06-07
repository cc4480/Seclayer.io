# Seclayer

Pay-Per-Scan Black-Box Penetration Testing SaaS & MCP Server.

Seclayer scans a target URL, runs a battery of black-box security checks
(headers, TLS, cookies, subdomain/EASM recon, sensitive-path probing, and active
SQLi/XSS/command-injection/SSRF/API fuzzing), then enriches the results with a
DeepSeek-generated executive report and severity score.

## Run Locally

**Prerequisites:** Node.js

1. Install dependencies:
   `npm install`
2. (Optional) Set `DEEPSEEK_API_KEY` in `.env.local` to enable AI-generated
   reports. Without it, the app falls back to high-quality local summaries.
   See [.env.example](.env.example) for optional model/endpoint overrides.
3. Run the app:
   `npm run dev`

The server (Express + Vite middleware) listens on http://localhost:3000.

## AI Models

Reports are generated via DeepSeek's OpenAI-compatible API:

- **deepseek-v4-pro** — deep security report reasoning (`DEEPSEEK_MODEL_PRO`)
- **deepseek-v4-flash** — fast PentAGI log narration (`DEEPSEEK_MODEL_FLASH`)
