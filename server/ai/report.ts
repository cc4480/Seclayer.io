import crypto from 'crypto';
import { Finding, Severity } from '../../src/types.js';
import { getClient, MODEL_PRO, REPORT_EFFORT, VALID_SEVERITIES } from './client.js';
import { normalizeCategory, compileLocalSummary } from './normalize.js';

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
      model: MODEL_PRO,
      messages: [
        {
          role: 'system',
          content: "You are Seclayer — an automated security scanner that writes reports for solo developers and small teams. Write like a senior developer helping a friend: clear, direct, no jargon. Every finding must include a plain-English impact statement and a real code fix example in the app's detected tech stack. Always respond with valid JSON only — no markdown, no code fences.",
        },
        { role: 'user', content: userPrompt },
      ],
      response_format: { type: 'json_object' },
      reasoning_effort: REPORT_EFFORT,
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
