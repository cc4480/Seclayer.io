import React, { useState } from 'react';
import { Code, CheckCircle, GitBranch, Webhook } from 'lucide-react';
import { ApiKey } from '../../types.js';
import { buildSnippets } from './api-docs/snippets.js';
import CodeBlock from './api-docs/CodeBlock.js';
import InfoBanner from './api-docs/InfoBanner.js';
import EndpointCard from './api-docs/EndpointCard.js';
import SnippetCard from './api-docs/SnippetCard.js';

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

  const {
    requestSchema,
    sarifCurlSnippet,
    githubActionsYaml,
    gitlabCiYaml,
    webhookPayload,
    curlSnippet,
    responseEnvelope,
    tsSnippet,
  } = buildSnippets(origin);

  return (
    <div className="space-y-6 text-xs font-mono">
      <InfoBanner
        icon={<Code className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5" />}
        title="API & MCP Integration Documentation"
        description="Integrate Seclayer's automated penetration testing capabilities into your CI/CD pipelines, security orchestration tools, or LLM-based autonomous agents using our Model Context Protocol (MCP) standard endpoints."
      />

      <div className="space-y-6">
        <EndpointCard method="POST" path="/api/mcp/scan">
          <div className="p-5 space-y-6">
            <p className="text-[#a1a1aa] text-[11px] font-sans">
              Initiate an active security diagnostic sweep and exploit chain analysis against a target URI. Synchronously returns calculated posture scores, unified threat logic, and explicit schema findings formatted for agent context passing.
            </p>

            <div>
              <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Request Parameter Schema (JSON)</h4>
              <CodeBlock code={requestSchema} variant="dim" onCopy={() => copy(requestSchema, 'Schema snippet copied to clipboard')} />
            </div>

            <div>
              <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Interactive cURL Snippet</h4>
              <CodeBlock code={curlSnippet} variant="terminal" wrapInCode onCopy={() => copy(curlSnippet, 'cURL snippet copied to clipboard')} />
            </div>

            <div>
              <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Response Data Envelope (200 OK)</h4>
              <CodeBlock code={responseEnvelope} variant="dim" onCopy={() => copy(responseEnvelope, 'Response envelope snippet copied to clipboard')} />
            </div>
          </div>
        </EndpointCard>

        <SnippetCard title="Example: TypeScript / Fetch">
          <CodeBlock code={tsSnippet} variant="dim" wrapInCode onCopy={() => copy(tsSnippet, 'TypeScript snippet copied to clipboard')} />
        </SnippetCard>

        {/* ── CI/CD Pipeline Integration ────────────────────────────────── */}
        <InfoBanner
          className="mt-2"
          icon={<GitBranch className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5" />}
          title="CI/CD Pipeline Integration"
          description="Embed Seclayer scans into GitHub Actions or GitLab CI. Scan results are automatically uploaded to the GitHub Security tab as SARIF 2.1.0 and surfaced as code-scanning alerts on pull requests."
        />

        <EndpointCard method="GET" path="/api/scans/:id/sarif">
          <div className="p-5 space-y-4">
            <p className="text-[#a1a1aa] text-[11px] font-sans">
              Download a completed scan as SARIF 2.1.0. Accepts either a JWT Bearer token (dashboard) or <code className="text-[#22c55e]">X-API-Key</code> header for pipeline use. Findings map to SARIF levels: critical/high → error, medium → warning, low/info → note.
            </p>
            <CodeBlock code={sarifCurlSnippet} variant="terminal" wrapInCode onCopy={() => copy(sarifCurlSnippet, 'SARIF curl snippet copied')} />
          </div>
        </EndpointCard>

        <SnippetCard title="GitHub Actions — .github/workflows/seclayer.yml">
          <CodeBlock code={githubActionsYaml} variant="dim" wrapInCode onCopy={() => copy(githubActionsYaml, 'GitHub Actions YAML copied')} />
        </SnippetCard>

        <SnippetCard title="GitLab CI — .gitlab-ci.yml">
          <CodeBlock code={gitlabCiYaml} variant="dim" wrapInCode onCopy={() => copy(gitlabCiYaml, 'GitLab CI YAML copied')} />
        </SnippetCard>

        {/* ── Webhook Callbacks ─────────────────────────────────────────── */}
        <InfoBanner
          icon={<Webhook className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5" />}
          title="Webhook Callbacks"
          description={
            <>
              Pass a <code className="text-[#22c55e]">webhookUrl</code> in any scan request. Seclayer POSTs a JSON payload to that URL when the scan completes or fails. Use this to trigger downstream actions — Slack alerts, Jira tickets, deployment gates.
            </>
          }
        />

        <SnippetCard title="Webhook Payload (scan.complete)">
          <CodeBlock code={webhookPayload} variant="dim" wrapInCode onCopy={() => copy(webhookPayload, 'Webhook payload copied')} />
        </SnippetCard>
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
