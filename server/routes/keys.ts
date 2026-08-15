import express from 'express';
import { db } from '../db.js';
import { requireAuth, getUserId } from '../http/context.js';

// API Key routes for developer MCP usecases
export function registerKeyRoutes(app: express.Express): void {
  app.get('/api/keys', requireAuth, (req, res) => {
    res.json({ keys: db.listApiKeys(getUserId(req)) });
  });

  app.post('/api/keys', requireAuth, (req, res) => {
    res.json({ status: 'ok', key: db.generateApiKey(getUserId(req)) });
  });

  app.delete('/api/keys/:id', requireAuth, (req, res) => {
    if (!db.revokeApiKey(getUserId(req), req.params.id)) {
      return res.status(404).json({ status: 'error', message: 'Key not found or could not be revoked' });
    }
    res.json({ status: 'ok' });
  });
}
