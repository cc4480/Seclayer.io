import { Scan } from '../../types.js';

// Derives the scanner console log lines that correspond to a scan's current
// status, so the terminal visualises the pipeline stages already reached.
export function buildStageLogs(scan: Scan): string[] {
  const logsList: string[] = [];
  const timestamp = () => new Date().toLocaleTimeString();

  logsList.push(`[${timestamp()}] [SYSTEM] Queued target URL: ${scan.url}`);
  logsList.push(`[${timestamp()}] [SYSTEM] Validated target and resolved DNS.`);

  if (scan.status === 'scanning' || scan.status === 'analyzing' || scan.status === 'complete') {
    logsList.push(`[${timestamp()}] [HTTP] Fetched root document; inspecting response headers...`);
    logsList.push(`[${timestamp()}] [HEADERS] Evaluating CSP, HSTS, X-Frame-Options and cookie directives...`);
    logsList.push(`[${timestamp()}] [SCAN] Scanning client payload for exposed secrets and outdated libraries...`);
    logsList.push(`[${timestamp()}] [EASM] Enumerating subdomains via DNS and probing sensitive paths...`);
  }

  if (scan.status === 'analyzing' || scan.status === 'complete') {
    logsList.push(`[${timestamp()}] [PROBES] Running active SQLi / XSS / command-injection / SSRF probes...`);
    logsList.push(`[${timestamp()}] [API] Testing GraphQL introspection and object-level authorization...`);
    logsList.push(`[${timestamp()}] [DEEPSEEK] Forwarding diagnostics to DeepSeek for analysis...`);
    logsList.push(`[${timestamp()}] [DEEPSEEK] Compiling findings, severities and developer fixes...`);
  }

  if (scan.status === 'complete') {
    logsList.push(`[${timestamp()}] [SYSTEM] Report compiled and saved.`);
  }

  return logsList;
}
