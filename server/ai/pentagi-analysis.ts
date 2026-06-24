import { getClient, MODEL_FLASH, PENTAGI_EFFORT } from './client.js';

/**
 * Reporter Agent synthesis for the PentAGI engine. Given the confirmed findings
 * from a real exploitation run, produces a short strategic analysis (attack
 * chaining, business impact, remediation priority). Uses DeepSeek when a key is
 * configured; otherwise returns a deterministic analysis derived from the real
 * findings (an honest degradation, never fabricated vulnerabilities).
 */
export async function generatePentagiAnalysis(
  url: string,
  findings: { severity: string; title: string }[],
): Promise<string[]> {
  const bySev = (s: string) => findings.filter(f => f.severity === s).map(f => f.title);

  const fallback = (): string[] => {
    if (findings.length === 0) {
      return [`No exploitable vulnerabilities were confirmed against ${url}. Maintain current controls and re-test after any significant change.`];
    }
    const crit = bySev('critical');
    const high = bySev('high');
    const top = [...crit, ...high].slice(0, 3);
    const lines: string[] = [
      `${findings.length} confirmed issue${findings.length !== 1 ? 's' : ''} on ${url} — ${crit.length} critical, ${high.length} high. Remediate critical and high severity first.`,
    ];
    if (top.length > 0) {
      lines.push(`Highest-impact targets to close now: ${top.join(' | ')}.`);
    }
    return lines;
  };

  const client = getClient();
  if (!client) {
    console.log('[PentAGI] No DEEPSEEK_API_KEY configured — using deterministic analysis.');
    return fallback();
  }

  try {
    const findingsList = findings.map(f => `- [${f.severity.toUpperCase()}] ${f.title}`).join('\n') || 'No findings.';
    const completion = await client.chat.completions.create({
      model: MODEL_FLASH,
      messages: [
        {
          role: 'system',
          content: 'You are the Reporter Agent of an automated black-box penetration test. Given the confirmed findings from a completed run, write a concise strategic analysis: how an attacker would realistically chain these findings, the concrete business impact, and the order in which to remediate. Base every statement strictly on the findings provided — never invent vulnerabilities. Respond as JSON only: {"analysis": ["line 1", "line 2", ...]} with 2 to 4 short lines, no markdown.',
        },
        { role: 'user', content: `Target: ${url}\n\nConfirmed findings:\n${findingsList}` },
      ],
      response_format: { type: 'json_object' },
      reasoning_effort: PENTAGI_EFFORT,
      temperature: 0.3,
      max_tokens: 700,
    });
    const data = JSON.parse(completion.choices[0]?.message?.content?.trim() || '{}');
    const lines = Array.isArray(data.analysis)
      ? data.analysis.filter((l: any) => typeof l === 'string' && l.trim()).map((l: string) => l.trim())
      : [];
    return lines.length > 0 ? lines : fallback();
  } catch (err: any) {
    console.warn(`[PentAGI] AI analysis failed: ${err?.message || err}`);
    return fallback();
  }
}
