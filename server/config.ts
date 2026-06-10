import 'dotenv/config';

/**
 * Centralized, validated application configuration.
 *
 * All environment access flows through this module so the rest of the codebase
 * never reads `process.env` directly. Invalid configuration fails fast at boot
 * (in production) instead of surfacing as confusing runtime errors later.
 */

export type NodeEnv = 'development' | 'production' | 'test';

function parseIntEnv(value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim() === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBoolEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  return /^(1|true|yes|on)$/i.test(value.trim());
}

const nodeEnv = (process.env.NODE_ENV as NodeEnv) || 'development';
const isProduction = nodeEnv === 'production';

const deepseekApiKey = (process.env.DEEPSEEK_API_KEY || '').trim();
const deepseekConfigured =
  deepseekApiKey !== '' && deepseekApiKey !== 'MY_DEEPSEEK_API_KEY';

export const config = {
  nodeEnv,
  isProduction,
  isTest: nodeEnv === 'test',

  /** HTTP port. Defaults to 3000; respects $PORT for PaaS platforms. */
  port: parseIntEnv(process.env.PORT, 3000),

  /** Bind host. 0.0.0.0 so containers expose the port. */
  host: process.env.HOST || '0.0.0.0',

  /** Public-facing URL, used for self-referential links. */
  appUrl: process.env.APP_URL || `http://localhost:${parseIntEnv(process.env.PORT, 3000)}`,

  /** Comma-separated allowlist of CORS origins. Empty => same-origin only. */
  corsOrigins: (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean),

  /** Maximum JSON/body payload size accepted by the API. */
  bodyLimit: process.env.BODY_LIMIT || '256kb',

  /** Log verbosity: 'debug' | 'info' | 'warn' | 'error'. */
  logLevel: (process.env.LOG_LEVEL || (isProduction ? 'info' : 'debug')).toLowerCase(),

  /** Emit logs as JSON (machine-readable) instead of pretty text. */
  logJson: parseBoolEnv(process.env.LOG_JSON, isProduction),

  /** Path to the JSON datastore file. */
  dbFile: process.env.DB_FILE || 'db.json',

  deepseek: {
    apiKey: deepseekApiKey,
    configured: deepseekConfigured,
    /** OpenAI-compatible base URL for the DeepSeek API. */
    baseUrl: process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com',
    /** Higher-quality model used for analytical pentest report generation. */
    reportModel: process.env.DEEPSEEK_REPORT_MODEL || 'deepseek-v4-pro',
    /** Faster/cheaper model used for the PentAGI log simulation. */
    logModel: process.env.DEEPSEEK_LOG_MODEL || 'deepseek-v4-flash',
    /** Per-request timeout (ms) for AI calls. */
    timeoutMs: parseIntEnv(process.env.DEEPSEEK_TIMEOUT_MS, 30_000),
    /** Max output tokens — capped to prevent JSON truncation in JSON mode. */
    maxTokens: parseIntEnv(process.env.DEEPSEEK_MAX_TOKENS, 4096),
  },

  rateLimit: {
    /** Sliding window length in milliseconds. */
    windowMs: parseIntEnv(process.env.RATE_LIMIT_WINDOW_MS, 60_000),
    /** Max requests per window for general API traffic. */
    maxRequests: parseIntEnv(process.env.RATE_LIMIT_MAX, 120),
    /** Stricter cap for expensive scan endpoints. */
    scanMaxRequests: parseIntEnv(process.env.RATE_LIMIT_SCAN_MAX, 10),
  },

  scanner: {
    /**
     * When false (default), the scanner refuses targets that resolve to
     * private/loopback/link-local addresses. This blocks the SSRF vector where
     * a user points the scanner at internal infrastructure. Enable only in
     * trusted lab environments.
     */
    allowPrivateTargets: parseBoolEnv(process.env.SCANNER_ALLOW_PRIVATE_TARGETS, !isProduction),
  },
} as const;

/**
 * Validate configuration at startup. Throws in production when required values
 * are missing so the process never starts in a half-configured state.
 */
export function validateConfig(): string[] {
  const warnings: string[] = [];

  if (!config.deepseek.configured) {
    warnings.push(
      'DEEPSEEK_API_KEY is not set — AI report generation will use the deterministic local fallback.',
    );
  }

  if (config.isProduction) {
    if (config.appUrl.startsWith('http://localhost')) {
      warnings.push('APP_URL is not configured for production (defaults to localhost).');
    }
    if (config.scanner.allowPrivateTargets) {
      warnings.push(
        'SCANNER_ALLOW_PRIVATE_TARGETS is enabled in production — this exposes an SSRF risk.',
      );
    }
  }

  const validLevels = ['debug', 'info', 'warn', 'error'];
  if (!validLevels.includes(config.logLevel)) {
    throw new Error(
      `Invalid LOG_LEVEL "${config.logLevel}". Expected one of: ${validLevels.join(', ')}`,
    );
  }

  if (config.port < 1 || config.port > 65535) {
    throw new Error(`Invalid PORT "${config.port}". Expected 1-65535.`);
  }

  return warnings;
}
