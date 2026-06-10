import type { Request, Response, NextFunction, RequestHandler } from 'express';
import crypto from 'crypto';
import { logger } from '../logger.js';

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
