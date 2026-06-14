/**
 * HTTP-level production middleware: request correlation, structured access
 * logging, security headers, CORS, in-memory rate limiting, and centralized
 * error handling. All dependency-free.
 *
 * Each concern lives in its own module under `./middleware/`; this file is a
 * stable re-export barrel so existing `from './server/middleware.js'`
 * imports keep working unchanged.
 */
export { requestContext } from './middleware/request-context.js';
export { authContext, currentUserId } from './middleware/auth-context.js';
export { securityHeaders } from './middleware/security-headers.js';
export { cors } from './middleware/cors.js';
export { rateLimit } from './middleware/rate-limit.js';
export { asyncHandler } from './middleware/async-handler.js';
export { HttpError, notFound, errorHandler } from './middleware/errors.js';
