import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { config } from '../config.js';

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
