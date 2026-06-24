import OpenAI from 'openai';

export const VALID_CATEGORIES = ['DAST', 'SAST', 'IAST', 'SCA', 'EASM', 'RED_TEAM'] as const;
export const VALID_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;

// ── DeepSeek V4 model routing ────────────────────────────────────────────────
// Pro (1.6T params) for the heavy lifting (full report generation); Flash (284B,
// faster/cheaper) for lighter synthesis. Both are OpenAI-SDK compatible on the
// same base URL and support JSON output mode. All overridable via env.
export type ReasoningEffort = 'none' | 'minimal' | 'low' | 'medium' | 'high' | 'xhigh';
export const MODEL_PRO = process.env.DEEPSEEK_MODEL_PRO?.trim() || 'deepseek-v4-pro';
export const MODEL_FLASH = process.env.DEEPSEEK_MODEL_FLASH?.trim() || 'deepseek-v4-flash';
// DeepSeek V4 enables reasoning by default (high effort). For strict JSON
// extraction we default it OFF — predictable output, lower latency and cost.
// Dial up per surface (e.g. 'medium'/'high') via env when deeper reasoning helps.
export const REPORT_EFFORT = (process.env.DEEPSEEK_REPORT_EFFORT?.trim() as ReasoningEffort) || 'none';
export const PENTAGI_EFFORT = (process.env.DEEPSEEK_PENTAGI_EFFORT?.trim() as ReasoningEffort) || 'none';

let aiClient: OpenAI | null = null;

export function getClient(): OpenAI | null {
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
