// Centralized runtime configuration + boot-time validation. Keeps environment
// handling in one place and surfaces misconfiguration as clear startup warnings
// instead of silent degradation in production.

function clean(v: string | undefined, placeholder?: string): string | undefined {
  if (!v) return undefined;
  const t = v.trim();
  if (!t || (placeholder && t === placeholder)) return undefined;
  return t;
}

export const config = {
  port: Number(process.env.PORT) || 3000,
  isProd: process.env.NODE_ENV === 'production',
  appUrl: clean(process.env.APP_URL, 'MY_APP_URL')?.replace(/\/+$/, ''),
  deepseekConfigured: !!clean(process.env.DEEPSEEK_API_KEY, 'MY_DEEPSEEK_API_KEY'),
  emailConfigured: !!clean(process.env.RESEND_API_KEY, 'MY_RESEND_API_KEY'),
};

// Logs configuration warnings; returns false if a production-critical setting is
// missing so the caller can decide whether to refuse to boot.
export function validateConfigOnBoot(): boolean {
  const warnings: string[] = [];
  let prodCriticalMissing = false;

  if (!config.deepseekConfigured) {
    warnings.push('DEEPSEEK_API_KEY not set — AI reports will use built-in local summaries.');
  }
  if (!config.emailConfigured) {
    warnings.push('RESEND_API_KEY not set — magic-link emails are written to the console (dev/demo mode).');
  }

  if (config.isProd) {
    if (!config.appUrl) {
      warnings.push('APP_URL is not set in production — magic-link URLs will fall back to the inbound request host.');
    }
    if (!config.emailConfigured) {
      warnings.push('Running in production without an email provider: users will NOT receive sign-in links.');
      prodCriticalMissing = true;
    }
  }

  for (const w of warnings) console.warn(`[config] ${w}`);
  return !prodCriticalMissing;
}
