import React from 'react';
import { Code, Copy, FileText } from 'lucide-react';
import { Notify } from './useApiAction.js';

interface ApiDocsTabProps {
  notify: Notify;
}

/** API & MCP integration documentation with copyable request/response snippets. */
export default function ApiDocsTab({ notify }: ApiDocsTabProps) {
  return (
    <div className="space-y-6 animate-fade-in text-xs font-mono">
      <div className="bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5">
        <Code className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5" />
        <div className="space-y-1">
          <h4 className="text-white text-xs uppercase font-bold">API & MCP Integration Documentation</h4>
          <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
            Integrate Seclayer's automated penetration testing capabilities into your CI/CD pipelines, security orchestration tools, or LLM-based autonomous agents using our Model Context Protocol (MCP) standard endpoints.
          </p>
        </div>
      </div>

      <div className="space-y-6">
        <div className="bg-black border border-[#27272a] rounded overflow-hidden">
          <div className="bg-[#0c0c0e] px-4 py-3 border-b border-[#27272a] flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="bg-[#22c55e]/10 text-[#22c55e] px-2 py-0.5 rounded font-mono text-[9px] uppercase font-bold tracking-wider">POST</span>
              <h3 className="text-white font-mono text-xs font-bold sm:text-sm">/api/mcp/scan</h3>
            </div>
            <span className="text-[10px] text-[#52525b] uppercase tracking-wider bg-[#18181b] px-2 py-1 rounded border border-[#27272a]">1 Credit / Request</span>
          </div>

          <div className="p-5 space-y-6">
            <p className="text-[#a1a1aa] text-[11px] font-sans">
              Initiate an active security diagnostic sweep and exploit chain analysis against a target URI. Synchronously returns calculated posture scores, unified threat logic, and explicit schema findings formatted for agent context passing.
            </p>

            <div>
              <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Request Parameter Schema (JSON)</h4>
              <div className="relative group">
                <pre className="bg-[#09090b] border border-[#27272a]/40 p-4 rounded text-[#a1a1aa] text-[10px] overflow-x-auto">
{`{
  "url": "https://example.com",     // (Required) The fully qualified domain name to scan
  "apiKey": "sec_b7x9...",          // (Required) Your provisioned MCP API key
  "authHeader": "Bearer ey..."      // (Optional) Authorization header to pass to the target
}`}
                </pre>
                <button
                  className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                  onClick={() => {
                    navigator.clipboard.writeText(`{\n  "url": "https://example.com",     // (Required) The fully qualified domain name to scan\n  "apiKey": "sec_b7x9...",          // (Required) Your provisioned MCP API key\n  "authHeader": "Bearer ey..."      // (Optional) Authorization header to pass to the target\n}`);
                    notify('Schema snippet copied to clipboard');
                  }}
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            <div>
              <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Interactive cURL Snippet</h4>
              <div className="relative group">
                <pre className="bg-[#18181b] border border-[#27272a] p-4 rounded text-[#22c55e] text-[10px] overflow-x-auto">
                  <code>
{`curl -X POST ${window.location.origin}/api/mcp/scan \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://example.com",
    "apiKey": "YOUR_API_KEY"
  }'`}
                  </code>
                </pre>
                <button
                  className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                  onClick={() => {
                    navigator.clipboard.writeText(`curl -X POST ${window.location.origin}/api/mcp/scan -H "Content-Type: application/json" -d '{\n  "url": "https://example.com", \n  "apiKey": "YOUR_API_KEY"\n}'`);
                    notify('cURL snippet copied to clipboard');
                  }}
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            <div>
              <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Response Data Envelope (200 OK)</h4>
              <div className="relative group">
                <pre className="bg-[#09090b] border border-[#27272a]/40 p-4 rounded text-[#a1a1aa] text-[10px] overflow-x-auto">
{`{
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
  ],
  "creditsRemaining": 90
}`}
                </pre>
                <button
                  className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                  onClick={() => {
                    navigator.clipboard.writeText(`{\n  "success": true,\n  "targetUrl": "https://staging.api.vulnerable.org",\n  "postureScore": 85,\n  "vulnerabilityLevel": "medium",\n  "analysisSummary": "Seclayer automated assessment identified 1 or more...",\n  "securityFindings": [\n    {\n      "testName": "GraphQL Schema Introspection Exposed",\n      "endpoint": "/graphql",\n      "severity": "high",\n      "description": "An active API endpoint probe discovered...",\n      "fix": "Disable introspection blocks in the production backend..."\n    }\n  ],\n  "creditsRemaining": 90\n}`);
                    notify('Response envelope snippet copied to clipboard');
                  }}
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Node JS snippets etc. - Keep it minimal */}
        <div className="bg-black border border-[#27272a] rounded overflow-hidden">
          <div className="bg-[#0c0c0e] px-4 py-3 border-b border-[#27272a] flex items-center justify-between">
            <div className="flex items-center space-x-2">
               <FileText className="w-3.5 h-3.5 text-[#52525b]" />
               <h3 className="text-white font-mono text-xs font-bold sm:text-sm">Example: TypeScript / Fetch</h3>
            </div>
          </div>
          <div className="p-5">
            <div className="relative group">
              <pre className="bg-[#09090b] border border-[#27272a]/40 p-4 rounded text-[#a1a1aa] text-[10px] overflow-x-auto">
                  <code>
{`async function runSeclayerScan(target: string, key: string) {
  const response = await fetch('${window.location.origin}/api/mcp/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: target, apiKey: key })
  });

  if (!response.ok) throw new Error('Scan failed');

  const report = await response.json();
  console.log(\`Score: \${report.postureScore}/100\`);
  return report.securityFindings;
}`}
                  </code>
              </pre>
              <button
                className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                onClick={() => {
                  navigator.clipboard.writeText(`async function runSeclayerScan(target: string, key: string) {\n  const response = await fetch('${window.location.origin}/api/mcp/scan', {\n    method: 'POST',\n    headers: { 'Content-Type': 'application/json' },\n    body: JSON.stringify({ url: target, apiKey: key })\n  });\n\n  if (!response.ok) throw new Error('Scan failed');\n  \n  const report = await response.json();\n  console.log(\`Score: \${report.postureScore}/100\`);\n  return report.securityFindings;\n}`);
                  notify('TypeScript snippet copied to clipboard');
                }}
              >
                <Copy className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
