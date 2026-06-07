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
    return `Your app at ${url} has serious security issues that need fixing before you launch. An attacker could compromise user accounts or steal data. Fix the critical findings first.`;
  }
  if (sc.severity === 'medium') {
    return `Your app at ${url} has some security gaps worth addressing before you go live. No critical exposures were found, but the issues flagged could be exploited by a motivated attacker.`;
  }
  return `Your app at ${url} looks secure. No major vulnerabilities were found. A few minor improvements are noted below.`;
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
    const techStack = (diagnostics.techLeaked as string[] | undefined)?.join(', ') || 'Unknown — default to Node.js/Express';
    const findingsList = staticCompiled.findings
      .map(f => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.description} (Fix: ${f.fix})`)
      .join('\n');

    const userPrompt = `Analyze this black-box security scan for: ${url}

DETECTED TECH STACK (from HTTP headers/body):
${techStack}

DIAGNOSTICS:
- HTTP Status: ${diagnostics.responseStatus}
- SSL/TLS Active: ${diagnostics.sslSecure}
- Missing security headers: ${diagnostics.missingHeaders?.join(', ') || 'None'}
- Tech signatures detected: ${techStack}
- Exposed sensitive paths: ${JSON.stringify(diagnostics.probedPaths)}
- Cookie security issues: ${JSON.stringify(diagnostics.cookieIssues)}

DETECTED ISSUES:
${findingsList || 'No issues detected.'}

RULES:
- Write for a developer who built their first SaaS app, not a security auditor
- aiSummary must start with "Your app at ${url}" — tell them in plain English: is it safe to launch? What's the most serious issue? What should they fix first?
- Never use jargon like "attack surface", "threat vector", "exploit chain", "adversarial"
- DO NOT fabricate vulnerabilities not supported by the data above
- For codeFixExample: detect the tech stack from the DETECTED TECH STACK above (Express/Node/JS → JavaScript; Django/Flask/Python → Python; Rails/Ruby → Ruby; Laravel/PHP → PHP; otherwise default to Node.js/Express). Write actual before/after code or the specific lines to add/change.
- plainEnglish must answer: "What can go wrong? What can an attacker actually do?" in one sentence a non-technical founder can understand.
- Consolidate duplicate findings
- Always use the exact target URL "${url}" — never substitute "example.com"

Return exactly this JSON structure (no markdown, no code fences):
{
  "aiSummary": "3-4 sentences starting with 'Your app at ${url}'. Plain English — safe to ship? Worst issue? Fix first. Like a senior dev friend.",
  "adjustedScore": <integer 10-100; critical findings → 10-30, high → 31-55, medium → 56-75, clean → 76-100>,
  "findings": [
    {
      "title": "<concise finding title>",
      "description": "<technical description — how an attacker exploits this against ${url}>",
      "plainEnglish": "<one sentence: what can go wrong in plain terms a founder understands>",
      "severity": "<info|low|medium|high|critical>",
      "fix": "<step-by-step remediation>",
      "codeFixExample": "<actual code snippet in detected stack showing how to fix it — before/after or specific lines to add>",
      "category": "<DAST|SAST|IAST|SCA|EASM|RED_TEAM>"
    }
  ]
}`;

    const completion = await client.chat.completions.create({
      model: 'deepseek-v4-flash',
      messages: [
        {
          role: 'system',
          content: "You are Seclayer — an automated security scanner that writes reports for solo developers and small teams. Write like a senior developer helping a friend: clear, direct, no jargon. Every finding must include a plain-English impact statement and a real code fix example in the app's detected tech stack. Always respond with valid JSON only — no markdown, no code fences.",
        },
        { role: 'user', content: userPrompt },
      ],
      response_format: { type: 'json_object' },
      temperature: 0.3,
      max_tokens: 6000,
    });

    let bodyText = completion.choices[0]?.message?.content?.trim() || '{}';

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
      plainEnglish: f.plainEnglish || '',
      codeFixExample: f.codeFixExample || '',
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
