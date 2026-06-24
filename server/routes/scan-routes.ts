import { Express } from 'express';
import { LocalFileDb } from '../db.js';
import { recheckFinding } from '../recheck.js';
import { requireAuth, requireAuthOrApiKey, scanLimiter } from '../middleware.js';
import { validateTargetUrl, resolveAuthProfile } from '../scan-pipeline-helpers.js';
import { generateSarif } from '../sarif.js';
import type { ScanJobRunner } from '../scan-job.js';
import type { Scan, Finding, RemediationStatus } from '../../src/types.js';

/** Scan lifecycle (create/list/get/logs/report/sarif), suppressions, and per-finding remediation + recheck. */
export function registerScanRoutes(app: Express, dbInstance: LocalFileDb, ctx: { processScanJob: ScanJobRunner['processScanJob'] }) {
  app.post('/api/scans', scanLimiter, requireAuth, async (req, res) => {
    const { url, authHeader, authProfileId, webhookUrl } = req.body;
    if (!url) return res.status(400).json({ message: 'Target URL is required.' });
    const urlMsg = validateTargetUrl(url); if (urlMsg) return res.status(400).json({ message: urlMsg });

    // Validate webhookUrl if provided — must be http(s) and not SSRF target
    if (webhookUrl) {
      const whErr = validateTargetUrl(webhookUrl);
      if (whErr) return res.status(400).json({ message: `Invalid webhookUrl: ${whErr}` });
    }

    // Resolve auth profile to a header value for the scanner
    let resolvedAuthHeader = authHeader;
    if (authProfileId && !authHeader) {
      const profile = dbInstance.getAuthProfile(req.userId!, authProfileId);
      if (profile) {
        const headers = await resolveAuthProfile(profile);
        if (headers.Authorization) resolvedAuthHeader = headers.Authorization;
        else if (headers.Cookie) resolvedAuthHeader = headers.Cookie;
      }
    }
    const scan = dbInstance.createScan(req.userId!, url, resolvedAuthHeader);
    const updates: Partial<Scan> = {};
    if (authProfileId) updates.authProfileId = authProfileId;
    if (webhookUrl) updates.webhookUrl = webhookUrl;
    if (Object.keys(updates).length) dbInstance.updateScan(scan.id, updates);
    ctx.processScanJob(scan.id);
    res.json({ status: 'ok', scan: { ...scan, ...updates } });
  });

  app.get('/api/scans', requireAuth, (req, res) => {
    const scansList = dbInstance.listScans(req.userId!).map(s => dbInstance.getScanWithSuppressedFindings(s));
    res.json({ scans: scansList });
  });

  app.get('/api/scans/:id', requireAuth, (req, res) => {
    let scan = dbInstance.getScan(req.params.id);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    scan = dbInstance.getScanWithSuppressedFindings(scan);
    res.json({ scan });
  });

  app.get('/api/scans/:id/logs', requireAuth, (req, res) => {
    const scan = dbInstance.getScan(req.params.id);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    res.json({ logs: dbInstance.getScanLogs(req.params.id) });
  });

  app.get('/api/scans/:id/report', requireAuth, (req, res) => {
    let scan = dbInstance.getScan(req.params.id);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    if (scan.status !== 'complete') {
      return res.status(400).json({ error: 'Scan is not complete yet.' });
    }
    scan = dbInstance.getScanWithSuppressedFindings(scan);
    res.json({
      scanId: scan.id, url: scan.url, score: scan.score, severity: scan.severity,
      aiSummary: scan.aiSummary, findings: scan.findings,
      createdAt: scan.createdAt, completedAt: scan.completedAt,
    });
  });

  app.get('/api/scans/:id/sarif', requireAuthOrApiKey(dbInstance), (req, res) => {
    let scan = dbInstance.getScan(req.params.id);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    if (scan.status !== 'complete') {
      return res.status(400).json({ error: 'Scan is not complete yet.' });
    }
    scan = dbInstance.getScanWithSuppressedFindings(scan);
    const sarif = generateSarif(scan);
    res.setHeader('Content-Type', 'application/sarif+json');
    res.json(sarif);
  });

  // Suppressions
  app.get('/api/suppressions', requireAuth, (req, res) => {
    res.json({ suppressions: dbInstance.listSuppressions(req.userId!) });
  });

  app.post('/api/suppressions', requireAuth, (req, res) => {
    const { targetUrl, findingTitle, reason } = req.body;
    if (!targetUrl || !findingTitle) {
      return res.status(400).json({ error: 'targetUrl and findingTitle are required.' });
    }
    const rule = dbInstance.addSuppression(req.userId!, targetUrl, findingTitle, reason || 'False positive');
    res.json({ status: 'ok', rule });
  });

  app.delete('/api/suppressions/:id', requireAuth, (req, res) => {
    const success = dbInstance.removeSuppression(req.userId!, req.params.id);
    if (!success) return res.status(404).json({ error: 'Suppression rule not found.' });
    res.json({ status: 'ok' });
  });

  app.post('/api/scans/:scanId/findings/:findingId/suppress', requireAuth, (req, res) => {
    const { scanId, findingId } = req.params;
    const { reason = 'Manual validation' } = req.body;
    const scan = dbInstance.getScan(scanId);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    const finding = scan.findings?.find(f => f.id === findingId);
    if (!finding) return res.status(404).json({ error: 'Finding not found.' });
    const rule = dbInstance.addSuppression(req.userId!, scan.url, finding.title, reason);
    res.json({ status: 'ok', rule });
  });

  // Remediation lifecycle — set a finding's status (open/in_progress/fixed/verified)
  app.patch('/api/scans/:scanId/findings/:findingId/remediation', requireAuth, (req, res) => {
    const { scanId, findingId } = req.params;
    const { status, note } = req.body as { status?: string; note?: string };
    const valid = ['open', 'in_progress', 'fixed', 'verified'];
    if (!status || !valid.includes(status)) {
      return res.status(400).json({ error: `status must be one of: ${valid.join(', ')}` });
    }
    const scan = dbInstance.getScan(scanId);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    const updated = dbInstance.updateFinding(scanId, findingId, {
      remediationStatus: status as RemediationStatus,
      remediationNote: typeof note === 'string' ? note : undefined,
      remediationUpdatedAt: new Date().toISOString(),
    });
    if (!updated) return res.status(404).json({ error: 'Finding not found.' });
    res.json({ status: 'ok', finding: updated.findings?.find(f => f.id === findingId) });
  });

  // Re-check a single finding — re-run the real scan pipeline and confirm if the fix landed
  app.post('/api/scans/:scanId/findings/:findingId/recheck', requireAuth, async (req, res) => {
    const { scanId, findingId } = req.params;
    const scan = dbInstance.getScan(scanId);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    const finding = scan.findings?.find(f => f.id === findingId);
    if (!finding) return res.status(404).json({ error: 'Finding not found.' });
    try {
      const result = await recheckFinding(scan.url, finding, scan.authHeader);
      const patch: Partial<Finding> = {
        lastVerifiedAt: result.checkedAt,
        verificationResult: result.stillPresent ? 'still_present' : 'resolved',
      };
      // A clean re-test promotes the finding to "verified"; a positive re-test
      // drops a premature "fixed" back to "in_progress".
      if (!result.stillPresent) patch.remediationStatus = 'verified';
      else if (finding.remediationStatus === 'fixed') patch.remediationStatus = 'in_progress';
      const updated = dbInstance.updateFinding(scanId, findingId, patch);
      res.json({
        status: 'ok',
        stillPresent: result.stillPresent,
        detail: result.detail,
        finding: updated?.findings?.find(f => f.id === findingId),
      });
    } catch (err: any) {
      res.status(502).json({ error: err.message || 'Re-check failed.' });
    }
  });
}
