import { config } from './config.js';

/**
 * Tiny dependency-free structured logger.
 *
 * - Respects LOG_LEVEL (debug < info < warn < error).
 * - Emits line-delimited JSON in production (LOG_JSON=true) for log aggregators,
 *   and human-readable text in development.
 * - Supports a per-request child logger that carries a correlation id.
 */

type Level = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_WEIGHT: Record<Level, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const threshold = LEVEL_WEIGHT[(config.logLevel as Level)] ?? LEVEL_WEIGHT.info;

function write(level: Level, msg: string, meta?: Record<string, unknown>) {
  if (LEVEL_WEIGHT[level] < threshold) return;

  const timestamp = new Date().toISOString();

  if (config.logJson) {
    const record = { timestamp, level, msg, ...meta };
    const line = JSON.stringify(record, replaceError);
    (level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(line + '\n');
    return;
  }

  const tag = `[${timestamp}] ${level.toUpperCase().padEnd(5)}`;
  const extra = meta && Object.keys(meta).length ? ' ' + JSON.stringify(meta, replaceError) : '';
  const sink = level === 'error' || level === 'warn' ? console.error : console.log;
  sink(`${tag} ${msg}${extra}`);
}

/** JSON.stringify replacer that serializes Error objects usefully. */
function replaceError(_key: string, value: unknown) {
  if (value instanceof Error) {
    return { name: value.name, message: value.message, stack: value.stack };
  }
  return value;
}

export interface Logger {
  debug(msg: string, meta?: Record<string, unknown>): void;
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
  child(bindings: Record<string, unknown>): Logger;
}

function makeLogger(bindings: Record<string, unknown> = {}): Logger {
  const merge = (meta?: Record<string, unknown>) =>
    Object.keys(bindings).length || meta ? { ...bindings, ...meta } : undefined;

  return {
    debug: (msg, meta) => write('debug', msg, merge(meta)),
    info: (msg, meta) => write('info', msg, merge(meta)),
    warn: (msg, meta) => write('warn', msg, merge(meta)),
    error: (msg, meta) => write('error', msg, merge(meta)),
    child: (childBindings) => makeLogger({ ...bindings, ...childBindings }),
  };
}

export const logger = makeLogger();
