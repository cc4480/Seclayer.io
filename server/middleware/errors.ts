import type { Request, Response, NextFunction, RequestHandler, ErrorRequestHandler } from 'express';
import { config } from '../config.js';
import { logger } from '../logger.js';

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
