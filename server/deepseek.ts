import crypto from "crypto";
import { Finding, Severity } from '../src/types.js';

// DeepSeek exposes an OpenAI-compatible chat completions API, so we talk to it
// directly over fetch and avoid pulling in a heavyweight SDK dependency.
const DEEPSEEK_BASE_URL = process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com';

// The "pro" tier handles the deep security report reasoning.
const MODEL_PRO = process.env.DEEPSEEK_MODEL_PRO || 'deepseek-v4-pro';

function getApiKey(): string | null {
  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (!apiKey || apiKey === 'MY_DEEPSEEK_API_KEY' || apiKey.trim() === '') {
    return null;
  }
  return apiKey;
}

// Calls the DeepSeek chat completions endpoint in JSON mode and returns the raw
// model message content. Returns null when no API key is configured so callers
// can gracefully fall back to local generation.
async function callDeepSeek(model: string, prompt: string, temperature: number): Promise<string | null> {
  const apiKey = getApiKey();
  if (!apiKey) return null;

  const response = await fetch(`${DEEPSEEK_BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages: [{ role: 'user', content: prompt }],
      response_format: { type: 'json_object' },
      temperature,
      max_tokens: 4096,
      stream: false,
    }),
  });

  if (!response.ok) {
    const errBody = await response.text().catch(() => '');
    throw new Error(`DeepSeek API error ${response.status}: ${errBody}`);
  }

  const data = await response.json();
  const content = data?.choices?.[0]?.message?.content;
  return typeof content === 'string' ? content : null;
}

export async function generateAiReport(
  url: string,
  diagnostics: any,
  staticCompiled: { score: number; severity: Severity; findings: Finding[] }
): Promise<{ score: number; severity: Severity; findings: Finding[]; aiSummary: string }> {

  if (!getApiKey()) {
    console.log("No valid DEEPSEEK_API_KEY set. Generating elegant local-mode executive summary.");
    const defaultSecSummary = compileLocalSummary(url, staticCompiled);
    return {
      ...staticCompiled,
      aiSummary: defaultSecSummary
    };
  }

  try {
    const findingsSummaryText = staticCompiled.findings.map(f => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.description} (Fix: ${f.fix})`).join('\n');

    const prompt = `You are Seclayer's automated penetration testing AI.
Analyze the following black-box scanner diagnostics for target web url: "${url}" and the compiled issues listed below.
Generate a structured penetration testing report output in JSON format.

DIAGNOSTIC DATA:
Response Status Code: ${diagnostics.responseStatus}
SSL Encryption Active: ${diagnostics.sslSecure}
Missing Essential Defensive Security Headers: ${diagnostics.missingHeaders.join(', ')}
Technology Framework Signature Leaks: ${diagnostics.techLeaked.join(', ')}
Inspected Directories Probe results: ${JSON.stringify(diagnostics.probedPaths)}
Cookie Configuration Flags: ${JSON.stringify(diagnostics.cookieIssues)}

DETECTED ISSUES:
${findingsSummaryText}

FALSE POSITIVE FILTERING (CRITICAL):
- Aggressively filter out noise, theoretical vulnerabilities, and duplicate findings.
- If a "missing header" or "cookie issue" is low-impact in the context of the discovered application type, downgrade its severity or omit it.
- Consolidate multiple similar issues into a single actionable finding.
- Do NOT hallucinate vulnerabilities that are not supported by the DIAGNOSTIC DATA or DETECTED ISSUES.

Please return a JSON object containing exactly these keys:
1. "aiSummary": A direct, plain-English, professional executive summary paragraph (3-5 sentences) summarizing overall posture, potential risks, and urgency level. Speak with the authority of an active principal cybersecurity assessor. Do NOT use fake placeholders like "example.com", you MUST explicitly mention the target url "${url}" in your summary. Do NOT use markdown links.
2. "adjustedScore": An integer safety score from 0 to 100 based on the severity of the findings (e.g. critical items lower score near 10-30, high items live around 40-60, clean sites get 90+).
3. "findings": An array corresponding to the detected issues, but written or enriched with clearer titles/descriptions of how an attacker would exploit the issue and exactly how a developer would fix it. Each item MUST have the fields: "title", "description", "severity", "fix", "category". The "severity" field MUST be one of: "info", "low", "medium", "high", "critical". The "category" field MUST be strictly one of the following 6 AppSec categories: "DAST", "SAST", "IAST", "SCA", "EASM", "RED_TEAM". Replace any generic placeholder domains (like example.com) with the real target "${url}".

Ensure the returned output is strictly valid JSON compliant with the required structure.`;

    const bodyTextRaw = await callDeepSeek(MODEL_PRO, prompt, 0.4);
    if (!bodyTextRaw) {
      return { ...staticCompiled, aiSummary: compileLocalSummary(url, staticCompiled) };
    }

    let bodyText = bodyTextRaw.trim();
    try {
        const u = url.startsWith('http') ? url : `https://${url}`;
        const parsedUrl = new URL(u);
        bodyText = bodyText.replace(/example\.com/gi, parsedUrl.hostname);
        bodyText = bodyText.replace(/yourdomain\.com/gi, parsedUrl.hostname);
    } catch(e) {}
    const data = JSON.parse(bodyText);

    // Safeguard values
    const finalScore = Math.max(10, Math.min(100, Number(data.adjustedScore ?? staticCompiled.score)));
    const finalFindings: Finding[] = (data.findings || []).map((f: any, idx: number) => ({
      id: `f_gen_${idx}_${crypto.randomUUID().slice(0,4)}`,
      title: f.title || 'Vulnerability Finding',
      description: f.description || '',
      severity: (['info', 'low', 'medium', 'high', 'critical'].includes(f.severity?.toLowerCase()) ? f.severity.toLowerCase() : 'low') as Severity,
      fix: f.fix || '',
      category: (() => {
        const cat = String(f.category || '').toUpperCase().replace(' ', '_');
        if (['DAST', 'SAST', 'IAST', 'SCA', 'EASM', 'RED_TEAM'].includes(cat)) return cat;
        if (cat.includes('RED') || cat.includes('TEAM') || cat.includes('FUZZ') || cat.includes('EXPLOIT')) return 'RED_TEAM';
        if (cat.includes('STATIC') || cat.includes('CODE') || cat.includes('SECRET') || cat.includes('KEY')) return 'SAST';
        if (cat.includes('DEPEND') || cat.includes('LIBRAR') || cat.includes('COMPOSIT') || cat.includes('SOFTWARE')) return 'SCA';
        if (cat.includes('INTERFACE') || cat.includes('INTERACT') || cat.includes('COOKIE') || cat.includes('SESSION')) return 'IAST';
        if (cat.includes('SURFACE') || cat.includes('DNS') || cat.includes('PORT') || cat.includes('ATTACK') || cat.includes('SSL') || cat.includes('DOMAIN') || cat.includes('CERT')) return 'EASM';
        return 'DAST';
      })()
    }));

    // Find highest severity from findings
    let finalSeverity: Severity = 'low';
    if (finalFindings.some(f => f.severity === 'critical')) finalSeverity = 'critical';
    else if (finalFindings.some(f => f.severity === 'high')) finalSeverity = 'high';
    else if (finalFindings.some(f => f.severity === 'medium')) finalSeverity = 'medium';
    else if (finalFindings.some(f => f.severity === 'low')) finalSeverity = 'low';

    return {
      score: finalScore,
      severity: finalSeverity,
      findings: finalFindings.length > 0 ? finalFindings : staticCompiled.findings,
      aiSummary: data.aiSummary || compileLocalSummary(url, staticCompiled)
    };

  } catch (err: any) {
    console.warn(`DeepSeek API call or parsing failed, using high-quality local summary: ${err?.message || err}`);
    return {
      ...staticCompiled,
      aiSummary: compileLocalSummary(url, staticCompiled)
    };
  }
}

function compileLocalSummary(url: string, sc: { score: number; severity: Severity; findings: Finding[] }): string {
  if (sc.severity === 'critical' || sc.severity === 'high') {
    return `Seclayer security scan for ${url} has identified several severe security perimeters leaks. Multiple high or critical level configuration issues have been detected, presenting actionable vectors for unauthorized access, data exposure, or client hijacking. Remediation of dotfile policies and deploying standard script isolation wrappers should be handled as an urgent engineering requirement to protect customer resources.`;
  }
  if (sc.severity === 'medium') {
    return `Seclayer security assessment for ${url} indicates moderate vulnerability flags are present. Key defensive layers (including SSL redirection pipelines, XSS protection boundaries, or secure session cookie directives) are absent or require strict consolidation. While not presenting an immediate server compromise, hardening these perimeter checkpoints aligns with standard production guidelines.`;
  }
  return `Seclayer verification scanner reports that ${url} displays strong basic defensive hygiene. No critical system exposures or active data leaks were detected. To reach industry-leading status, minor improvements should be introduced to satisfy full HSTS preload targets and deploy advanced content routing headers.`;
}
