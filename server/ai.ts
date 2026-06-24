// Barrel re-exporting the AI module surface. Kept for backward compatibility
// with existing import paths (`./ai.js` / `../ai.js`); the actual
// implementations live under server/ai/*.
export { normalizeCategory } from './ai/normalize.js';
export { generatePentagiAnalysis } from './ai/pentagi-analysis.js';
export { selectAutoFixFile, generateAutoFixPatch } from './ai/auto-fix.js';
export { generateAiReport } from './ai/report.js';
