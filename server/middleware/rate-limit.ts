import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { config } from '../config.js';

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
