import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import { makeTestApp, registerAndLogin } from '../helpers.js';
import type { Express } from 'express';
import type { LocalFileDb } from '../../server/db.js';

let app: Express;
let db: LocalFileDb;
let cleanup: () => void;

beforeEach(() => { ({ app, db, cleanup } = makeTestApp()); });
afterEach(() => cleanup());

function seedScanWithFinding() {
  const { token, user } = registerAndLogin(db);
  const scan = db.createScan(user.id, 'https://example.com');
  db.updateScan(scan.id, {
    status: 'complete',
    findings: [{
      id: 'f_rem001',
      title: 'Missing CSP',
      description: 'No CSP header',
      severity: 'high',
      fix: 'Add CSP header',
      category: 'DAST',
    }],
  });
  return { token, user, scan };
}

describe('PATCH /api/scans/:scanId/findings/:findingId/remediation', () => {
  it('sets a finding remediation status', async () => {
    const { token, scan } = seedScanWithFinding();
    const res = await request(app)
      .patch(`/api/scans/${scan.id}/findings/f_rem001/remediation`)
      .set('Authorization', `Bearer ${token}`)
      .send({ status: 'in_progress', note: 'working on it' });

    expect(res.status).toBe(200);
    expect(res.body.finding.remediationStatus).toBe('in_progress');
    expect(res.body.finding.remediationNote).toBe('working on it');
    expect(res.body.finding.remediationUpdatedAt).toBeDefined();
  });

  it('persists the status on the stored scan', async () => {
    const { token, scan } = seedScanWithFinding();
    await request(app)
      .patch(`/api/scans/${scan.id}/findings/f_rem001/remediation`)
      .set('Authorization', `Bearer ${token}`)
      .send({ status: 'fixed' });

    const stored = db.getScan(scan.id);
    expect(stored?.findings?.[0].remediationStatus).toBe('fixed');
  });

  it('rejects an invalid status', async () => {
    const { token, scan } = seedScanWithFinding();
    const res = await request(app)
      .patch(`/api/scans/${scan.id}/findings/f_rem001/remediation`)
      .set('Authorization', `Bearer ${token}`)
      .send({ status: 'banana' });
    expect(res.status).toBe(400);
  });

  it('returns 404 for an unknown finding', async () => {
    const { token, scan } = seedScanWithFinding();
    const res = await request(app)
      .patch(`/api/scans/${scan.id}/findings/f_nope/remediation`)
      .set('Authorization', `Bearer ${token}`)
      .send({ status: 'open' });
    expect(res.status).toBe(404);
  });

  it("returns 404 for another user's scan", async () => {
    const { scan } = seedScanWithFinding();
    const { token: otherToken } = registerAndLogin(db, 'other@example.com');
    const res = await request(app)
      .patch(`/api/scans/${scan.id}/findings/f_rem001/remediation`)
      .set('Authorization', `Bearer ${otherToken}`)
      .send({ status: 'open' });
    expect(res.status).toBe(404);
  });

  it('returns 401 without auth', async () => {
    const { scan } = seedScanWithFinding();
    const res = await request(app)
      .patch(`/api/scans/${scan.id}/findings/f_rem001/remediation`)
      .send({ status: 'open' });
    expect(res.status).toBe(401);
  });
});

describe('POST /api/scans/:scanId/findings/:findingId/recheck (guards)', () => {
  it('returns 404 for an unknown finding', async () => {
    const { token, scan } = seedScanWithFinding();
    const res = await request(app)
      .post(`/api/scans/${scan.id}/findings/f_nope/recheck`)
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });

  it('returns 401 without auth', async () => {
    const { scan } = seedScanWithFinding();
    const res = await request(app)
      .post(`/api/scans/${scan.id}/findings/f_rem001/recheck`);
    expect(res.status).toBe(401);
  });
});
