import express from 'express';

// Terminal JSON error handler. Keeps thrown route errors from leaking stack
// traces or crashing the process, and — importantly — classifies body-parser
// failures as CLIENT errors. Returning 500 for a malformed request body would
// pollute error logs and trip production alerting on what is really a bad
// request, so those map to 400/413 instead.
export function jsonErrorHandler(
  err: any,
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  if (res.headersSent) return next(err);

  if (err?.type === 'entity.parse.failed' || (err instanceof SyntaxError && 'body' in err)) {
    return res.status(400).json({ status: 'error', message: 'Request body is not valid JSON.' });
  }
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({ status: 'error', message: 'Request body is too large.' });
  }

  console.error('[server] Unhandled route error:', err?.message || err);
  res.status(500).json({ status: 'error', message: 'An unexpected server error occurred.' });
}
