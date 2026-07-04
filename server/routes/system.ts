import express from 'express';

export function registerSystemRoutes(app: express.Express): void {
  app.get('/api/system/health', (req, res) => {
    res.json({
      status: 'Online',
      version: 'v2.1.2-stable',
      timestamp: new Date().toISOString()
    });
  });
}
