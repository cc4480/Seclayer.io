import { Express } from 'express';
import { LocalFileDb } from '../db.js';
import { selectAutoFixFile, generateAutoFixPatch } from '../ai.js';
import * as github from '../github.js';
import { requireAuth, scanLimiter } from '../middleware.js';

/** GitHub repo connection management and the AI-driven auto-fix PR pipeline. */
export function registerGithubRoutes(app: Express, dbInstance: LocalFileDb) {
  app.get('/api/github/connection', requireAuth, (req, res) => {
    const conn = dbInstance.getGithubConnection(req.userId!);
    res.json({ connection: conn ? { repoFullName: conn.repoFullName, createdAt: conn.createdAt } : null });
  });

  app.post('/api/github/connect', requireAuth, async (req, res) => {
    const { repoFullName, token } = req.body as { repoFullName?: string; token?: string };
    if (!repoFullName || !token) return res.status(400).json({ error: 'repoFullName and token are required.' });
    if (!/^[\w.-]+\/[\w.-]+$/.test(repoFullName)) {
      return res.status(400).json({ error: 'repoFullName must be in "owner/repo" format.' });
    }
    const access = await github.validateRepoAccess(token, repoFullName);
    if (access.ok === false) return res.status(400).json({ error: access.error });
    const conn = dbInstance.setGithubConnection(req.userId!, repoFullName, token);
    res.json({ status: 'ok', connection: conn });
  });

  app.delete('/api/github/connection', requireAuth, (req, res) => {
    const success = dbInstance.removeGithubConnection(req.userId!);
    if (!success) return res.status(404).json({ error: 'No GitHub connection found.' });
    res.json({ status: 'ok' });
  });

  app.post('/api/scans/:scanId/findings/:findingId/auto-fix', requireAuth, scanLimiter, async (req, res) => {
    const { scanId, findingId } = req.params;
    const scan = dbInstance.getScan(scanId);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    const finding = scan.findings?.find(f => f.id === findingId);
    if (!finding) return res.status(404).json({ error: 'Finding not found.' });
    const conn = dbInstance.getGithubConnection(req.userId!);
    if (!conn) return res.status(400).json({ error: 'No GitHub repository connected. Connect one first.' });

    const fail = (detail: string) => {
      const updated = dbInstance.updateFinding(scanId, findingId, { autoFixStatus: 'failed', autoFixDetail: detail });
      res.json({ status: 'failed', detail, finding: updated?.findings?.find(f => f.id === findingId) });
    };
    const skip = (detail: string) => {
      const updated = dbInstance.updateFinding(scanId, findingId, { autoFixStatus: 'skipped', autoFixDetail: detail });
      res.json({ status: 'skipped', detail, finding: updated?.findings?.find(f => f.id === findingId) });
    };

    try {
      const access = await github.validateRepoAccess(conn.token, conn.repoFullName);
      if (access.ok === false) return fail(access.error);

      const filePaths = await github.getRepoTree(conn.token, conn.repoFullName, access.defaultBranch);
      if (filePaths.length === 0) return skip('Repository has no scannable text files.');

      const selection = await selectAutoFixFile(finding, filePaths);
      if (!selection) return skip('AI could not confidently match this finding to a file in the repository.');

      const file = await github.getFileContent(conn.token, conn.repoFullName, selection.targetFile, access.defaultBranch);
      if (!file) return skip(`Could not read "${selection.targetFile}" from the repository.`);

      const patch = await generateAutoFixPatch(finding, selection.targetFile, file.content);
      if (!patch) return skip('AI could not generate a safe patch for this finding.');

      const branchName = `seclayer/autofix-${findingId.slice(0, 8)}`;
      const fromSha = await github.getBranchSha(conn.token, conn.repoFullName, access.defaultBranch);
      await github.createBranch(conn.token, conn.repoFullName, branchName, fromSha);
      await github.upsertFile(
        conn.token, conn.repoFullName, selection.targetFile, patch.newContent,
        `Security fix: ${finding.title}`, branchName, file.sha,
      );
      const pr = await github.createPullRequest(
        conn.token, conn.repoFullName, patch.prTitle, patch.prBody, branchName, access.defaultBranch,
      );

      const updated = dbInstance.updateFinding(scanId, findingId, {
        autoFixStatus: 'opened',
        autoFixPrUrl: pr.url,
        autoFixDetail: undefined,
      });
      res.json({ status: 'ok', prUrl: pr.url, finding: updated?.findings?.find(f => f.id === findingId) });
    } catch (err: any) {
      fail(err.message || 'Auto-fix failed.');
    }
  });
}
