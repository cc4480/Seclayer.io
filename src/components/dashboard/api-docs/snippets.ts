export function buildSnippets(origin: string) {
  const requestSchema = `{
  "url": "https://example.com",     // (Required) The fully qualified domain name to scan
  "apiKey": "sec_b7x9...",          // (Required) Your provisioned MCP API key
  "authHeader": "Bearer ey...",     // (Optional) Authorization header to pass to the target
  "webhookUrl": "https://hooks.example.com/seclayer"  // (Optional) POSTed when scan finishes
}`;

  const sarifCurlSnippet = `# Download SARIF report for upload to GitHub Security tab
curl -H "X-API-Key: YOUR_API_KEY" \\
  ${origin}/api/scans/SCAN_ID/sarif \\
  -o results.sarif`;

  const githubActionsYaml = `name: Seclayer Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  seclayer-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Seclayer Scan
        id: scan
        run: |
          RESPONSE=$(curl -s -X POST ${origin}/api/mcp/scan \\
            -H "Content-Type: application/json" \\
            -d '{"url":"\${{ vars.SCAN_TARGET }}","apiKey":"\${{ secrets.SECLAYER_API_KEY }}"}')
          echo "scan_id=$(echo $RESPONSE | jq -r '.scanId')" >> $GITHUB_OUTPUT
          echo "score=$(echo $RESPONSE | jq -r '.postureScore')" >> $GITHUB_OUTPUT

      - name: Download SARIF
        run: |
          curl -H "X-API-Key: \${{ secrets.SECLAYER_API_KEY }}" \\
            ${origin}/api/scans/\${{ steps.scan.outputs.scan_id }}/sarif \\
            -o results.sarif

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif`;

  const gitlabCiYaml = `seclayer-scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      RESPONSE=$(curl -s -X POST ${origin}/api/mcp/scan \\
        -H "Content-Type: application/json" \\
        -d '{"url":"$SCAN_TARGET","apiKey":"$SECLAYER_API_KEY"}')
      SCAN_ID=$(echo $RESPONSE | jq -r '.scanId')
      curl -H "X-API-Key: $SECLAYER_API_KEY" \\
        ${origin}/api/scans/$SCAN_ID/sarif \\
        -o gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
  variables:
    SCAN_TARGET: "https://staging.example.com"`;

  const webhookPayload = `{
  "event": "scan.complete",
  "scanId": "scan_4f3a...",
  "url": "https://staging.example.com",
  "status": "complete",
  "score": 72,
  "severity": "high",
  "findingCount": 5,
  "criticalCount": 0,
  "highCount": 2,
  "mediumCount": 3,
  "lowCount": 0,
  "completedAt": "2025-06-07T12:34:56.789Z",
  "error": null
}`;

  const curlSnippet = `curl -X POST ${origin}/api/mcp/scan \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://example.com",
    "apiKey": "YOUR_API_KEY"
  }'`;

  const responseEnvelope = `{
  "success": true,
  "targetUrl": "https://staging.api.vulnerable.org",
  "postureScore": 85,
  "vulnerabilityLevel": "medium",
  "analysisSummary": "Seclayer automated assessment identified 1 or more...",
  "securityFindings": [
    {
      "testName": "GraphQL Schema Introspection Exposed",
      "endpoint": "/graphql",
      "severity": "high",
      "description": "An active API endpoint probe discovered...",
      "fix": "Disable introspection blocks in the production backend..."
    }
  ]
}`;

  const tsSnippet = `async function runSeclayerScan(target: string, key: string) {
  const response = await fetch('${origin}/api/mcp/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: target, apiKey: key })
  });

  if (!response.ok) throw new Error('Scan failed');

  const report = await response.json();
  console.log(\`Score: \${report.postureScore}/100\`);
  return report.securityFindings;
}`;

  return {
    requestSchema,
    sarifCurlSnippet,
    githubActionsYaml,
    gitlabCiYaml,
    webhookPayload,
    curlSnippet,
    responseEnvelope,
    tsSnippet,
  };
}
