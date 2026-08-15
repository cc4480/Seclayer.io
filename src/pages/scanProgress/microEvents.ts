// Micro-event telemetry copy keyed by scan status. Describes the scanner's
// actual work stages; the live feed cycles through the entries for the current
// backend status. Data only — no behaviour.
export const microEventsConfig: Record<string, string[]> = {
  initial: [
    "Validating target URL and DNS resolution...",
    "Running SSRF safety checks on the destination host...",
    "Establishing scanner session..."
  ],
  queued: [
    "Resolving DNS A / AAAA records for the target host...",
    "Verifying the target is publicly reachable...",
    "Preparing the diagnostic probe sequence..."
  ],
  scanning: [
    "Fetching the root document and inspecting response headers...",
    "Evaluating CSP, HSTS, X-Frame-Options and cookie directives...",
    "Scanning the client payload for exposed secret signatures...",
    "Checking JavaScript libraries against known CVEs...",
    "Enumerating subdomains via DNS and probing sensitive paths..."
  ],
  analyzing: [
    "Running active injection probes (SQLi, XSS, command, SSRF)...",
    "Testing the API surface (GraphQL introspection, object-level auth)...",
    "Forwarding diagnostics to DeepSeek for analysis...",
    "Compiling findings, severities and remediation guidance...",
    "Calculating the posture score..."
  ],
  complete: [
    "Finalizing the report...",
    "Persisting findings to your account...",
    "Scan complete."
  ]
};
