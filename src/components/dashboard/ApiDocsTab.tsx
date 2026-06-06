import React, { useState } from 'react';
import { Code, Copy, FileText, CheckCircle } from 'lucide-react';
import { ApiKey } from '../../types.js';

interface ApiDocsTabProps {
  apiKeys: ApiKey[];
}

export default function ApiDocsTab({ apiKeys }: ApiDocsTabProps) {
  const [toastMsg, setToastMsg] = useState('');
  const [showToast, setShowToast] = useState(false);

  const copy = (text: string, msg: string) => {
    navigator.clipboard.writeText(text);
    setToastMsg(msg);
    setShowToast(true);
    setTimeout(() => setShowToast(false), 3000);
  };

  const origin = window.location.origin;

  const requestSchema = `{
  "url": "https://example.com",     // (Required) The fully qualified domain name to scan
  "apiKey": "sec_b7x9...",          // (Required) Your provisioned MCP API key
  "authHeader": "Bearer ey..."      // (Optional) Authorization header to pass to the target
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

  return (
    <div className="space-y-6 text-xs font-mono">
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
          </div>

          <div className="p-5 space-y-6">
            <p className="text-[#a1a1aa] text-[11px] font-sans">
              Initiate an active security diagnostic sweep and exploit chain analysis against a target URI. Synchronously returns calculated posture scores, unified threat logic, and explicit schema findings formatted for agent context passing.
            </p>

            <div>
              <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Request Parameter Schema (JSON)</h4>
              <div className="relative group">
                <pre className="bg-[#09090b] border border-[#27272a]/40 p-4 rounded text-[#a1a1aa] text-[10px] overflow-x-auto">{requestSchema}</pre>
                <button
                  className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                  onClick={() => copy(requestSchema, 'Schema snippet copied to clipboard')}
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            <div>
              <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Interactive cURL Snippet</h4>
              <div className="relative group">
                <pre className="bg-[#18181b] border border-[#27272a] p-4 rounded text-[#22c55e] text-[10px] overflow-x-auto">
                  <code>{curlSnippet}</code>
                </pre>
                <button
                  className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                  onClick={() => copy(curlSnippet, 'cURL snippet copied to clipboard')}
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            <div>
              <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Response Data Envelope (200 OK)</h4>
              <div className="relative group">
                <pre className="bg-[#09090b] border border-[#27272a]/40 p-4 rounded text-[#a1a1aa] text-[10px] overflow-x-auto">{responseEnvelope}</pre>
                <button
                  className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                  onClick={() => copy(responseEnvelope, 'Response envelope snippet copied to clipboard')}
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-black border border-[#27272a] rounded overflow-hidden">
          <div className="bg-[#0c0c0e] px-4 py-3 border-b border-[#27272a] flex items-center">
            <FileText className="w-3.5 h-3.5 text-[#52525b] mr-2" />
            <h3 className="text-white font-mono text-xs font-bold sm:text-sm">Example: TypeScript / Fetch</h3>
          </div>
          <div className="p-5">
            <div className="relative group">
              <pre className="bg-[#09090b] border border-[#27272a]/40 p-4 rounded text-[#a1a1aa] text-[10px] overflow-x-auto">
                <code>{tsSnippet}</code>
              </pre>
              <button
                className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                onClick={() => copy(tsSnippet, 'TypeScript snippet copied to clipboard')}
              >
                <Copy className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {showToast && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0c0c0e] border border-[#22c55e] text-[#22c55e] px-4 py-3 rounded shadow-2xl shadow-green-950/20 font-mono text-xs flex items-center space-x-2 animate-bounce">
          <CheckCircle className="w-4 h-4 text-[#22c55e] shrink-0 animate-pulse" />
          <span>{toastMsg}</span>
        </div>
      )}
    </div>
  );
}
