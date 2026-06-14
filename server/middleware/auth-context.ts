import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { verifySession, readSessionToken } from '../session.js';

/**
 * Establish request identity from the signed session cookie — never from a
 * client-supplied `userId`. Routes read `currentUserId(req)`, which returns the
 * authenticated user or the shared default identity for anonymous callers. A
 * caller can therefore no longer impersonate another user by passing their id.
 */

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Authenticated user id from a verified session, or undefined if anonymous. */
      userId?: string;
    }
  }
}

const DEFAULT_USER_ID = 'user_default';

/** Verify the session cookie and attach `req.userId` when valid. */
export function authContext(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const userId = verifySession(readSessionToken(req));
    if (userId) req.userId = userId;
    next();
  };
}

/**
 * The identity to act as for this request: the authenticated user, or the
 * shared default account for anonymous callers (preserving the out-of-box demo).
 */
export function currentUserId(req: Request): string {
  return req.userId ?? DEFAULT_USER_ID;
}
