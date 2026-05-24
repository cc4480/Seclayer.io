import { GoogleGenAI, Type } from "@google/genai";
import { Finding, Severity } from '../src/types.js';

let aiInstance: GoogleGenAI | null = null;

function getAiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === "MY_GEMINI_API_KEY" || apiKey.trim() === "") {
    // Graceful check, let's keep it silent unless a call is made
    return null;
  }
  
  if (!aiInstance) {
    aiInstance = new GoogleGenAI({
      apiKey: apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
  }
  return aiInstance;
}

export async function generateAiReport(
  url: string,
  diagnostics: any,
  staticCompiled: { score: number; severity: Severity; findings: Finding[] }
): Promise<{ score: number; severity: Severity; findings: Finding[]; aiSummary: string }> {
  
  const ai = getAiClient();
  if (!ai) {
    console.log("No valid GEMINI_API_KEY set. Generating elegant local-mode executive summary.");
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

Please return a JSON response containing:
1. "aiSummary": A direct, plain-English, professional executive summary paragraph (3-5 sentences) summarizing overall posture, potential risks, and urgency level. Speak with the authority of an active principal cybersecurity assessor. Do NOT use fake placeholders like "example.com", you MUST explicitly mention the target url "${url}" in your summary. Do NOT use markdown links.
2. "adjustedScore": A safety score from 0 to 100 based on the severity of the findings (e.g. critical items lower score near 10-30, high items live around 40-60, clean sites get 90+).
3. "findings": An array corresponding to the detected issues, but written or enriched with clearer titles/descriptions of how an attacker would exploit the issue and exactly how a developer would fix it. Maintain the fields: title, description, severity, fix, category. The "category" field MUST be strictly one of the following 6 AppSec categories: "DAST", "SAST", "IAST", "SCA", "EASM", "RED_TEAM". Replace any generic placeholder domains (like example.com) with the real target "${url}".

Ensure the returned output is strictly compliant with the required JSON structure.`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          required: ["aiSummary", "adjustedScore", "findings"],
          properties: {
            aiSummary: { type: Type.STRING, description: "Penetration testing executive summary in active cybersecurity voice." },
            adjustedScore: { type: Type.INTEGER, description: "Score between 10 and 100." },
            findings: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ["title", "description", "severity", "fix", "category"],
                properties: {
                  title: { type: Type.STRING },
                  description: { type: Type.STRING, description: "Exploit path explainers." },
                  severity: { type: Type.STRING, description: "info, low, medium, high, critical" },
                  fix: { type: Type.STRING },
                  category: { type: Type.STRING, description: "MUST be one of: DAST, SAST, IAST, SCA, EASM, RED_TEAM" }
                }
              }
            }
          }
        }
      }
    });

    let bodyText = response.text.trim();
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
    console.warn(`Gemini API call or parsing failed, using high-quality local summary: ${err?.message || err}`);
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

export async function generatePentagiLogs(url: string | undefined): Promise<{ time: string; agent: string; msg: string; }[]> {
  const defaultUrl = url || 'staging.api.vulnerable.org';
  const ai = getAiClient();
  
  const fallbackLogs = [
    { time: '00:01', agent: 'Scout Agent', msg: `Core DNS Enumeration on domain base completed. Discovered open host ${defaultUrl}.` },
    { time: '00:04', agent: 'Scout Agent', msg: 'Probing HTTP port 443. Technology fingerprint matches Node.js Express & Apache HTTP Server v2.4.' },
    { time: '00:08', agent: 'Scout Agent', msg: 'Identified dynamic endpoint list: /api/v1/auth/login, /api/v1/support/ticket, /recovery/reset.' },
    { time: '00:12', agent: 'Exploiter Agent', msg: 'Testing "/recovery/reset" endpoint. Found active open redirect.' },
    { time: '00:15', agent: 'Exploiter Agent', msg: 'Constructing dynamic CSRF token bypass session.' },
    { time: '00:19', agent: 'Exploiter Agent', msg: 'Chaining Open Redirect bypass with active session forgery. Admin user redirected -> Session token exfiltrated to PentAGI listener hook!' },
    { time: '00:23', agent: 'Exploiter Agent', msg: 'Injected Administrative Bearer key. Successfully bypassed authentication constraints.' },
    { time: '00:27', agent: 'Reporter Agent', msg: 'Vulnerability exploit chain validated. Severity calculation: CRITICAL (10.0 CVSS).' },
    { time: '00:30', agent: 'Reporter Agent', msg: 'Standardized DefectDojo JSON findings schema generated.' }
  ];

  if (!ai) {
    return fallbackLogs;
  }

  try {
    const prompt = `You are PentAGI, an Autonomous Multi-Agent Multi-Step Pentest Coordinator.
Your goal is to simulate a realistic sequence of actions taken by three AI agents: "Scout Agent" (performs recon/scanning), "Exploiter Agent" (finds and tests vulnerabilities), and "Reporter Agent" (summarizes impact and generates artifacts).
The target is "${defaultUrl}".

Generate an array of 6 to 9 log messages that sequentially describe a successful multi-stage attack simulation ending with a report generation.

Please return a JSON response containing a single "logs" array. Each log object MUST have:
1. "time": a string formatted as "MM:SS" (e.g. "00:01", "00:15", "01:30") showing elapsed time in the operation. Ensure the time progresses chronologically.
2. "agent": strictly one of "Scout Agent", "Exploiter Agent", or "Reporter Agent".
3. "msg": the log message describing what the agent is doing or has found. Make it sound highly technical, professional, and cyber-security focused. Mention the target url "${defaultUrl}" in the first Scout log.

Do NOT use fake placeholders like "example.com" other than the provided target.
Return ONLY valid JSON compliant with the requested schema.`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          required: ["logs"],
          properties: {
            logs: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ["time", "agent", "msg"],
                properties: {
                  time: { type: Type.STRING, description: "MM:SS" },
                  agent: { type: Type.STRING },
                  msg: { type: Type.STRING }
                }
              }
            }
          }
        }
      }
    });

    let bodyText = response.text.trim();
    try {
        const u = defaultUrl.startsWith('http') ? defaultUrl : `https://${defaultUrl}`;
        const parsedUrl = new URL(u);
        bodyText = bodyText.replace(/example\.com/gi, parsedUrl.hostname);
        bodyText = bodyText.replace(/yourdomain\.com/gi, parsedUrl.hostname);
    } catch(e) {}
    const data = JSON.parse(bodyText);
    
    if (data.logs && Array.isArray(data.logs) && data.logs.length > 0) {
      return data.logs;
    }
    return fallbackLogs;
  } catch (err: any) {
    console.warn(`Gemini PentAGI generation failed, using fallback logs: ${err?.message || err}`);
    return fallbackLogs;
  }
}
