import type { Request, Response, NextFunction, RequestHandler, ErrorRequestHandler } from 'express';
import crypto from 'crypto';
import { config } from './config.js';
import { logger } from './logger.js';

/**
 * HTTP-level production middleware: request correlation, structured access
 * logging, security headers, CORS, in-memory rate limiting, and centralized
 * error handling. All dependency-free.
 */

// Augment Express Request with the fields we attach.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      id: string;
      log: ReturnType<typeof logger.child>;
    }
  }
}

/** Attach a correlation id + child logger and log request completion. */
export function requestContext(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const incoming = req.headers['x-request-id'];
    req.id = (Array.isArray(incoming) ? incoming[0] : incoming) || crypto.randomUUID();
    req.log = logger.child({ requestId: req.id });
    res.setHeader('X-Request-Id', req.id);

    const start = process.hrtime.bigint();
    res.on('finish', () => {
      const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
      const meta = {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs: Math.round(durationMs * 10) / 10,
      };
      if (res.statusCode >= 500) req.log.error('request failed', meta);
      else if (res.statusCode >= 400) req.log.warn('request rejected', meta);
      else req.log.info('request completed', meta);
    });

    next();
  };
}

/** Security response headers, including the CSP this product itself recommends. */
export function securityHeaders(): RequestHandler {
  return (_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), interest-cohort=()',
    );
    res.setHeader(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        // Vite injects inline bootstrap styles; allow inline styles only.
        "style-src 'self' 'unsafe-inline'",
        "script-src 'self'" + (config.isProduction ? '' : " 'unsafe-inline' 'unsafe-eval'"),
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self'" + (config.isProduction ? '' : ' ws:'),
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
      ].join('; '),
    );
    next();
  };
}

/** Minimal CORS handling driven by the configured allowlist. */
export function cors(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    if (origin && config.corsOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-Id');
    }
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  };
}

interface Bucket {
  count: number;
  resetAt: number;
}

/**
 * Fixed-window in-memory rate limiter keyed by client IP. Adequate for a
 * single-instance deployment; swap for a Redis-backed limiter when scaling
 * horizontally.
 */
export function rateLimit(options?: { windowMs?: number; max?: number; name?: string }): RequestHandler {
  const windowMs = options?.windowMs ?? config.rateLimit.windowMs;
  const max = options?.max ?? config.rateLimit.maxRequests;
  const name = options?.name ?? 'global';
  const buckets = new Map<string, Bucket>();

  // Opportunistic cleanup so the map does not grow unbounded.
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= now) buckets.delete(key);
    }
  }, windowMs);
  // Do not keep the event loop alive solely for the sweeper.
  if (typeof sweep.unref === 'function') sweep.unref();

  return (req: Request, res: Response, next: NextFunction) => {
    const key = `${name}:${clientIp(req)}`;
    const now = Date.now();
    let bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;

    const remaining = Math.max(0, max - bucket.count);
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(bucket.resetAt / 1000)));

    if (bucket.count > max) {
      const retryAfter = Math.ceil((bucket.resetAt - now) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      req.log?.warn('rate limit exceeded', { limiter: name, ip: clientIp(req) });
      res.status(429).json({
        status: 'error',
        message: 'Too many requests. Please slow down and try again shortly.',
      });
      return;
    }
    next();
  };
}

function clientIp(req: Request): string {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

/**
 * Wrap an async route handler so rejected promises reach the error middleware
 * instead of crashing the process with an unhandled rejection.
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>,
): RequestHandler {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/** Typed application error carrying an HTTP status code. */
export class HttpError extends Error {
  status: number;
  details?: unknown;
  constructor(status: number, message: string, details?: unknown) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.details = details;
  }
}

/** 404 handler for unmatched API routes. */
export function notFound(): RequestHandler {
  return (req: Request, res: Response) => {
    res.status(404).json({
      status: 'error',
      message: `Route not found: ${req.method} ${req.path}`,
      requestId: req.id,
    });
  };
}

/** Centralized error handler — the last middleware in the chain. */
export function errorHandler(): ErrorRequestHandler {
  return (err: unknown, req: Request, res: Response, _next: NextFunction) => {
    const status = err instanceof HttpError ? err.status : 500;
    const message =
      err instanceof HttpError
        ? err.message
        : 'An unexpected internal error occurred.';

    const log = req.log ?? logger;
    const meta = { status, path: req.path, method: req.method };
    if (status >= 500) {
      // Server faults: log the full error with stack for investigation.
      log.error('route error', { ...meta, err });
    } else {
      // Expected client errors (4xx): log lightly, no stack trace noise.
      log.debug('route client error', { ...meta, message: (err as Error)?.message });
    }

    if (res.headersSent) return;

    const payload: Record<string, unknown> = {
      status: 'error',
      message,
      requestId: req.id,
    };
    // Never leak internals (stack traces / details) in production.
    if (!config.isProduction && err instanceof HttpError && err.details) {
      payload.details = err.details;
    }
    res.status(status).json(payload);
  };
}
