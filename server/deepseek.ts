import OpenAI from 'openai';
import { Finding, Severity } from '../src/types.js';
import { config } from './config.js';
import { logger } from './logger.js';
import { buildPentagiLogs, type PentagiEvidence, type PentagiLog } from './pentagi.js';

/**
 * AI integration layer, backed by DeepSeek via its OpenAI-compatible API.
 *
 * Every entry point degrades gracefully: when no DEEPSEEK_API_KEY is configured
 * (or a call fails), the deterministic local generators are used instead, so the
 * product remains fully functional without an AI provider.
 */

let aiInstance: OpenAI | null = null;

function getAiClient(): OpenAI | null {
  if (!config.deepseek.configured) {
    // Graceful check; stay silent unless a call is actually attempted.
    return null;
  }

  if (!aiInstance) {
    aiInstance = new OpenAI({
      apiKey: config.deepseek.apiKey,
      baseURL: config.deepseek.baseUrl,
      timeout: config.deepseek.timeoutMs,
    });
  }
  return aiInstance;
}

/** Extract the text content from a chat completion, tolerating empty responses. */
function completionText(completion: OpenAI.Chat.Completions.ChatCompletion): string {
  return completion.choices?.[0]?.message?.content?.trim() ?? '';
}

// `thinking` is a DeepSeek extension to the OpenAI chat-completions schema.
type DeepSeekChatParams = OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming & {
  thinking?: { type: 'enabled' | 'disabled' };
};

/**
 * Build chat-completion params for a strict-JSON request against DeepSeek V4.
 *
 * DeepSeek's JSON mode is only reliable in NON-thinking mode — with thinking
 * enabled, V4 can emit malformed/empty structured output. We therefore disable
 * thinking explicitly and cap max_tokens to avoid mid-object truncation.
 */
function jsonParams(
  model: string,
  systemPrompt: string,
  userPrompt: string,
  temperature: number,
): DeepSeekChatParams {
  return {
    model,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ],
    response_format: { type: 'json_object' },
    temperature,
    max_tokens: config.deepseek.maxTokens,
    // DeepSeek-specific: force non-thinking mode for dependable JSON output.
    thinking: { type: 'disabled' },
  };
}

/**
 * Run a strict-JSON DeepSeek chat completion and parse the response.
 *
 * Replaces placeholder hostnames the model may emit (despite instructions)
 * with the real target hostname before parsing, so callers never need to
 * post-process raw completion text themselves.
 */
async function runJsonCompletion(
  ai: OpenAI,
  model: string,
  systemPrompt: string,
  userPrompt: string,
  temperature: number,
  url: string,
): Promise<any> {
  const completion = await ai.chat.completions.create(
    jsonParams(model, systemPrompt, userPrompt, temperature),
  );

  let bodyText = completionText(completion);
  try {
    const u = url.startsWith('http') ? url : `https://${url}`;
    const parsedUrl = new URL(u);
    bodyText = bodyText.replace(/example\.com/gi, parsedUrl.hostname);
    bodyText = bodyText.replace(/yourdomain\.com/gi, parsedUrl.hostname);
  } catch (e) {}
  return JSON.parse(bodyText);
}

export async function generateAiReport(
  url: string,
  diagnostics: any,
  staticCompiled: { score: number; severity: Severity; findings: Finding[] }
): Promise<{ score: number; severity: Severity; findings: Finding[]; aiSummary: string }> {

  const ai = getAiClient();
  if (!ai) {
    logger.debug('DEEPSEEK_API_KEY not configured; using deterministic local executive summary.');
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

Return ONLY a JSON object (no markdown, no code fences) with exactly these keys:
1. "aiSummary": A direct, plain-English, professional executive summary paragraph (3-5 sentences) summarizing overall posture, potential risks, and urgency level. Speak with the authority of an active principal cybersecurity assessor. Do NOT use fake placeholders like "example.com", you MUST explicitly mention the target url "${url}" in your summary. Do NOT use markdown links.
2. "adjustedScore": An integer safety score from 0 to 100 based on the severity of the findings (e.g. critical items lower score near 10-30, high items live around 40-60, clean sites get 90+).
3. "findings": An array of objects. Each object MUST have the fields: "title", "description", "severity", "fix", "category". Write or enrich each with clearer titles/descriptions of how an attacker would exploit the issue and exactly how a developer would fix it. "severity" MUST be one of: info, low, medium, high, critical. "category" MUST be strictly one of: "DAST", "SAST", "IAST", "SCA", "EASM", "RED_TEAM". Replace any generic placeholder domains (like example.com) with the real target "${url}".

Ensure the returned output is strictly valid JSON compliant with the required structure.`;

    const data = await runJsonCompletion(
      ai,
      config.deepseek.reportModel,
      'You are a precise security analysis engine that always responds with strictly valid JSON.',
      prompt,
      0.3,
      url,
    );

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
    logger.warn('DeepSeek report generation failed; falling back to local summary.', { err });
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

/**
 * Narrate a PentAGI autonomous-agent activity feed from real scan evidence.
 *
 * The AI is used only to phrase what the scanner actually observed — it is
 * explicitly instructed never to invent vulnerabilities beyond the supplied
 * evidence. When no AI provider is configured (or the call fails), the
 * deterministic `buildPentagiLogs` renderer produces an equivalent grounded
 * feed, so the feature is fully functional and truthful either way.
 */
export async function generatePentagiLogs(evidence: PentagiEvidence): Promise<PentagiLog[]> {
  const fallbackLogs = buildPentagiLogs(evidence);
  const ai = getAiClient();
  if (!ai) {
    return fallbackLogs;
  }

  try {
    const evidenceJson = JSON.stringify(
      {
        target: evidence.target,
        hostname: evidence.hostname,
        responseStatus: evidence.responseStatus,
        sslSecure: evidence.sslSecure,
        ip: evidence.ip,
        nameserver: evidence.nameserver,
        liveSubdomains: evidence.liveSubdomains,
        leakedTech: evidence.leakedTech,
        exposedPaths: evidence.exposedPaths,
        exploitFindings: evidence.exploitFindings,
        dastIssues: evidence.dastIssues,
        worstSeverity: evidence.worstSeverity,
        score: evidence.score,
        totalFindings: evidence.totalFindings,
      },
      null,
      2,
    );

    const prompt = `You are PentAGI, an Autonomous Multi-Agent Multi-Step Pentest Coordinator narrating the work of three agents: "Scout Agent" (recon), "Exploiter Agent" (active vulnerability testing), and "Reporter Agent" (impact summary + artifacts).

You are given the REAL evidence collected by a live black-box scan of "${evidence.target}". Narrate a chronological activity feed describing ONLY what this evidence supports.

REAL SCAN EVIDENCE (JSON):
${evidenceJson}

STRICT GROUNDING RULES:
- Describe ONLY findings present in the evidence. Do NOT invent vulnerabilities, endpoints, payloads, or exploit chains that are not in the evidence.
- If "exploitFindings", "exposedPaths", and "dastIssues" are all empty, the Exploiter Agent MUST report that active probes confirmed no exploitable vector, and the Reporter Agent MUST NOT claim a successful exploit.
- If exploit evidence is present, narrate those specific findings (use their severity and detail).
- The Reporter Agent MUST cite the real score (${evidence.score}/100), total findings (${evidence.totalFindings}), and highest severity (${evidence.worstSeverity}).
- The first Scout Agent log MUST mention the target "${evidence.target}".

Return ONLY a JSON object (no markdown, no code fences) containing a single "logs" array of 6 to 10 objects. Each log object MUST have:
1. "time": a string "MM:SS" of elapsed time, strictly increasing chronologically.
2. "agent": strictly one of "Scout Agent", "Exploiter Agent", or "Reporter Agent".
3. "msg": a technical, professional log line grounded in the evidence.

Return ONLY valid JSON compliant with the requested schema.`;

    const data = await runJsonCompletion(
      ai,
      config.deepseek.logModel,
      'You are a security analysis engine that narrates only real evidence and always responds with strictly valid JSON.',
      prompt,
      0.6,
      evidence.target,
    );

    if (data.logs && Array.isArray(data.logs) && data.logs.length > 0) {
      // Keep only entries matching the agent contract; fall back if the model drifts.
      const cleaned: PentagiLog[] = data.logs
        .filter(
          (l: any) =>
            l &&
            typeof l.time === 'string' &&
            typeof l.msg === 'string' &&
            ['Scout Agent', 'Exploiter Agent', 'Reporter Agent'].includes(l.agent),
        )
        .map((l: any) => ({ time: l.time, agent: l.agent, msg: l.msg }));
      if (cleaned.length > 0) return cleaned;
    }
    return fallbackLogs;
  } catch (err: any) {
    logger.warn('DeepSeek PentAGI log generation failed; using grounded fallback logs.', { err });
    return fallbackLogs;
  }
}
