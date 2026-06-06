import OpenAI from 'openai';
import crypto from 'crypto';
import { Finding, Severity } from '../src/types.js';

const VALID_CATEGORIES = ['DAST', 'SAST', 'IAST', 'SCA', 'EASM', 'RED_TEAM'] as const;
const VALID_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;

let aiClient: OpenAI | null = null;

function getClient(): OpenAI | null {
  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (!apiKey || apiKey === 'YOUR_DEEPSEEK_API_KEY' || !apiKey.trim()) {
    return null;
  }
  if (!aiClient) {
    aiClient = new OpenAI({
      apiKey,
      baseURL: 'https://api.deepseek.com',
    });
  }
  return aiClient;
}

export function normalizeCategory(raw: string): string {
  const cat = String(raw || '').toUpperCase().replace(/[\s-]/g, '_');
  if ((VALID_CATEGORIES as readonly string[]).includes(cat)) return cat;
  if (cat.includes('RED') || cat.includes('TEAM') || cat.includes('FUZZ') || cat.includes('EXPLOIT')) return 'RED_TEAM';
  if (cat.includes('STATIC') || cat.includes('CODE') || cat.includes('SECRET') || cat.includes('KEY')) return 'SAST';
  if (cat.includes('DEPEND') || cat.includes('LIBRAR') || cat.includes('COMPOSIT') || cat.includes('SOFTWARE')) return 'SCA';
  if (cat.includes('INTERACTIVE') || cat.includes('COOKIE') || cat.includes('SESSION')) return 'IAST';
  if (cat.includes('SURFACE') || cat.includes('DNS') || cat.includes('PORT') || cat.includes('SSL') || cat.includes('CERT')) return 'EASM';
  return 'DAST';
}

function compileLocalSummary(url: string, sc: { score: number; severity: Severity; findings: Finding[] }): string {
  if (sc.severity === 'critical' || sc.severity === 'high') {
    return `Seclayer security scan for ${url} identified critical exposures. Multiple high-severity vulnerabilities present actionable vectors for unauthorized access, data exfiltration, or service compromise. Immediate remediation is required.`;
  }
  if (sc.severity === 'medium') {
    return `Seclayer security assessment for ${url} indicates moderate vulnerabilities are present. Key defensive configurations are absent or misconfigured. Hardening these controls is recommended to meet production security standards.`;
  }
  return `Seclayer scan for ${url} reports strong baseline security hygiene. No critical exposures were detected. Minor improvements to security headers and transport policies are recommended for industry-leading posture.`;
}

export async function generateAiReport(
  url: string,
  diagnostics: any,
  staticCompiled: { score: number; severity: Severity; findings: Finding[] }
): Promise<{ score: number; severity: Severity; findings: Finding[]; aiSummary: string }> {
  const client = getClient();
  if (!client) {
    console.log('[AI] No DEEPSEEK_API_KEY configured — using local summary.');
    return { ...staticCompiled, aiSummary: compileLocalSummary(url, staticCompiled) };
  }

  try {
    const findingsList = staticCompiled.findings
      .map(f => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.description} (Fix: ${f.fix})`)
      .join('\n');

    const userPrompt = `Analyze this black-box security scan for: ${url}

DIAGNOSTICS:
- HTTP Status: ${diagnostics.responseStatus}
- SSL/TLS Active: ${diagnostics.sslSecure}
- Missing security headers: ${diagnostics.missingHeaders.join(', ') || 'None'}
- Technology leaks in response: ${diagnostics.techLeaked.join(', ') || 'None'}
- Exposed sensitive paths: ${JSON.stringify(diagnostics.probedPaths)}
- Cookie security issues: ${JSON.stringify(diagnostics.cookieIssues)}

DETECTED ISSUES:
${findingsList || 'No issues detected.'}

RULES:
- Consolidate duplicate findings. Filter informational noise.
- Do NOT fabricate vulnerabilities unsupported by the data above.
- Always mention the exact target URL "${url}" in the summary — never substitute "example.com".

Return a JSON object with exactly these three keys:
{
  "aiSummary": "<3-5 sentence executive summary from a senior penetration tester — authority tone, present tense, no markdown>",
  "adjustedScore": <integer 10-100; critical findings → 10-30, high → 31-55, medium → 56-75, clean → 76-100>,
  "findings": [
    {
      "title": "<concise finding title>",
      "description": "<how an attacker exploits this vulnerability against ${url}>",
      "severity": "<info|low|medium|high|critical>",
      "fix": "<specific remediation steps>",
      "category": "<one of: DAST|SAST|IAST|SCA|EASM|RED_TEAM>"
    }
  ]
}`;

    const completion = await client.chat.completions.create({
      model: 'deepseek-v4-flash',
      messages: [
        {
          role: 'system',
          content: "You are Seclayer's automated penetration testing AI. You analyze black-box scanner diagnostics and return structured JSON security reports. Always respond with valid JSON only — no markdown, no code fences.",
        },
        { role: 'user', content: userPrompt },
      ],
      response_format: { type: 'json_object' },
      temperature: 0.3,
      max_tokens: 4096,
    });

    let bodyText = completion.choices[0]?.message?.content?.trim() || '{}';

    // Sanitize placeholder domains Gemini-style hallucinations (DeepSeek occasionally does the same)
    try {
      const hostname = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
      bodyText = bodyText.replace(/example\.com/gi, hostname).replace(/yourdomain\.com/gi, hostname);
    } catch {}

    const data = JSON.parse(bodyText);

    const finalScore = Math.max(10, Math.min(100, Number(data.adjustedScore ?? staticCompiled.score)));
    const finalFindings: Finding[] = (data.findings || []).map((f: any, idx: number) => ({
      id: `f_ds_${idx}_${crypto.randomBytes(3).toString('hex')}`,
      title: f.title || 'Security Finding',
      description: f.description || '',
      severity: ((VALID_SEVERITIES as readonly string[]).includes(f.severity?.toLowerCase())
        ? f.severity.toLowerCase()
        : 'low') as Severity,
      fix: f.fix || '',
      category: normalizeCategory(f.category || ''),
    }));

    let finalSeverity: Severity = 'low';
    if (finalFindings.some(f => f.severity === 'critical')) finalSeverity = 'critical';
    else if (finalFindings.some(f => f.severity === 'high')) finalSeverity = 'high';
    else if (finalFindings.some(f => f.severity === 'medium')) finalSeverity = 'medium';

    return {
      score: finalScore,
      severity: finalSeverity,
      findings: finalFindings.length > 0 ? finalFindings : staticCompiled.findings,
      aiSummary: data.aiSummary || compileLocalSummary(url, staticCompiled),
    };
  } catch (err: any) {
    console.warn(`[AI] DeepSeek report generation failed: ${err?.message || err}`);
    return { ...staticCompiled, aiSummary: compileLocalSummary(url, staticCompiled) };
  }
}
