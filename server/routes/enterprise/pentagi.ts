import type { Express } from 'express';
import { asyncHandler } from '../../middleware.js';
import { generatePentagiLogs } from '../../deepseek.js';

/** PentAGI Autonomous Pentest AI Exploit Agent: simulated multi-agent exploit log feed. */
export function registerPentagiRoutes(app: Express): void {
  app.get(
    '/api/enterprise/pentagi/logs',
    asyncHandler(async (req, res) => {
      const url = req.query.url as string | undefined;
      const logs = await generatePentagiLogs(url);
      res.json({
        success: true,
        engine: 'PentAGI Autonomous Multi-Agent Multi-Step Pentest Coordinator',
        agents: ['Scout', 'Exploiter', 'Reporter'],
        logs,
      });
    }),
  );
}
