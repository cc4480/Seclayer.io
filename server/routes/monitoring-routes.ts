import { Express } from 'express';
import { LocalFileDb } from '../db.js';
import { requireAuth } from '../middleware.js';
import { validateTargetUrl, resolveAuthProfile } from '../scan-pipeline-helpers.js';

/** Current-user lookup, monitored targets (scheduled scans), API keys, and auth profiles (incl. live verification test). */
export function registerMonitoringRoutes(app: Express, dbInstance: LocalFileDb) {
  app.get('/api/auth/me', requireAuth, (req, res) => {
    const user = dbInstance.getUser(req.userId!);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({ user });
  });

  // Monitoring
  app.get('/api/monitoring', requireAuth, (req, res) => {
    res.json({ monitoredTargets: dbInstance.listMonitoredTargets(req.userId!) });
  });

  app.post('/api/monitoring', requireAuth, (req, res) => {
    const { url, frequencyDays = 7, scheduleString } = req.body;
    if (!url) return res.status(400).json({ error: 'url is required.' });
    const urlErr = validateTargetUrl(url); if (urlErr) return res.status(400).json({ error: urlErr });
    const target = dbInstance.addMonitoredTarget(req.userId!, url, frequencyDays, scheduleString);
    res.json({ status: 'ok', target });
  });

  app.delete('/api/monitoring/:id', requireAuth, (req, res) => {
    const success = dbInstance.removeMonitoredTarget(req.userId!, req.params.id);
    if (!success) return res.status(404).json({ error: 'Monitored target not found.' });
    res.json({ status: 'ok' });
  });

  // API Keys
  app.get('/api/keys', requireAuth, (req, res) => {
    res.json({ keys: dbInstance.listApiKeys(req.userId!) });
  });

  app.post('/api/keys', requireAuth, (req, res) => {
    const keyObj = dbInstance.generateApiKey(req.userId!);
    res.json({ status: 'ok', key: keyObj });
  });

  app.delete('/api/keys/:id', requireAuth, (req, res) => {
    const success = dbInstance.revokeApiKey(req.userId!, req.params.id);
    if (!success) return res.status(404).json({ error: 'Key not found.' });
    res.json({ status: 'ok' });
  });

  // --- AUTH PROFILES ---
  app.get('/api/auth-profiles', requireAuth, (req, res) => {
    res.json({ profiles: dbInstance.listAuthProfiles(req.userId!) });
  });

  app.post('/api/auth-profiles', requireAuth, (req, res) => {
    const { name, type, headerName, headerValue, username, password,
            loginUrl, loginUsernameField, loginPasswordField, loginUsername, loginPassword } = req.body;
    if (!name || !type) return res.status(400).json({ error: 'name and type are required.' });
    const VALID_TYPES = ['cookie', 'bearer', 'header', 'basic', 'form'];
    if (!VALID_TYPES.includes(type)) return res.status(400).json({ error: 'Invalid auth type.' });
    const profile = dbInstance.createAuthProfile(req.userId!, {
      name, type, headerName, headerValue, username, password,
      loginUrl, loginUsernameField, loginPasswordField, loginUsername, loginPassword,
    });
    res.status(201).json({ profile });
  });

  app.delete('/api/auth-profiles/:id', requireAuth, (req, res) => {
    const ok = dbInstance.deleteAuthProfile(req.userId!, req.params.id);
    if (!ok) return res.status(404).json({ error: 'Auth profile not found.' });
    res.json({ status: 'ok' });
  });

  app.post('/api/auth-profiles/:id/test', requireAuth, async (req, res) => {
    const profile = dbInstance.getAuthProfile(req.userId!, req.params.id);
    if (!profile) return res.status(404).json({ error: 'Auth profile not found.' });
    const { testUrl } = req.body;
    if (!testUrl) return res.status(400).json({ error: 'testUrl is required.' });
    const urlErr = validateTargetUrl(testUrl);
    if (urlErr) return res.status(400).json({ error: urlErr });
    try {
      const headers = await resolveAuthProfile(profile);
      if (Object.keys(headers).length === 0) {
        return res.json({ success: false, status: 0, message: 'Could not resolve auth credentials (form login may have failed or credentials are incomplete).' });
      }
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 8000);
      const testRes = await fetch(testUrl, { headers: { ...headers, 'User-Agent': 'Mozilla/5.0' }, signal: ctrl.signal });
      const ok = testRes.status < 400;
      // Mark as verified
      dbInstance.updateAuthProfile(req.userId!, req.params.id, { verifiedAt: new Date().toISOString() });
      res.json({
        success: ok,
        status: testRes.status,
        message: ok
          ? `Auth confirmed — ${testUrl} returned HTTP ${testRes.status}`
          : `Auth may be invalid — ${testUrl} returned HTTP ${testRes.status} (401/403 indicates rejected credentials)`,
      });
    } catch (err: any) {
      res.json({ success: false, status: 0, message: `Request failed: ${err.message}` });
    }
  });
}
