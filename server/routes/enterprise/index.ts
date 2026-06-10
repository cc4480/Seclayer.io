import type { Express, RequestHandler } from 'express';
import { registerAspmRoutes } from './aspm.js';
import { registerEasmRoutes } from './easm.js';
import { registerHadrianRoutes } from './hadrian.js';
import { registerIastRoutes } from './iast.js';
import { registerPentagiRoutes } from './pentagi.js';

/**
 * Enterprise pipeline endpoints.
 *
 * Each module below runs the same real diagnostics engine used by /api/scans
 * against the user-supplied target and derives its response entirely from the
 * findings actually observed — there is no canned/hardcoded result data.
 */
export function registerEnterpriseRoutes(app: Express, scanLimiter: RequestHandler): void {
  registerAspmRoutes(app, scanLimiter);
  registerEasmRoutes(app, scanLimiter);
  registerHadrianRoutes(app, scanLimiter);
  registerIastRoutes(app, scanLimiter);
  registerPentagiRoutes(app);
}
