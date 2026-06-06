import { describe, it, expect } from 'vitest';
import { normalizeCategory, generateAiReport } from '../../server/ai.js';
import type { DiagnosticResult } from '../../server/scanner.js';
import { compileStaticFindings } from '../../server/scanner.js';

// ─── normalizeCategory ───────────────────────────────────────────────────────

describe('normalizeCategory', () => {
  it('passes through valid categories unchanged', () => {
    expect(normalizeCategory('DAST')).toBe('DAST');
    expect(normalizeCategory('SAST')).toBe('SAST');
    expect(normalizeCategory('IAST')).toBe('IAST');
    expect(normalizeCategory('SCA')).toBe('SCA');
    expect(normalizeCategory('EASM')).toBe('EASM');
    expect(normalizeCategory('RED_TEAM')).toBe('RED_TEAM');
  });

  it('normalises lowercase input', () => {
    expect(normalizeCategory('dast')).toBe('DAST');
    expect(normalizeCategory('sast')).toBe('SAST');
  });

  it('maps static-analysis keywords to SAST', () => {
    expect(normalizeCategory('static analysis')).toBe('SAST');
    expect(normalizeCategory('secret scanning')).toBe('SAST');
    expect(normalizeCategory('code review')).toBe('SAST');
  });

  it('maps dependency keywords to SCA', () => {
    expect(normalizeCategory('dependency check')).toBe('SCA');
    expect(normalizeCategory('library vulnerability')).toBe('SCA');
    expect(normalizeCategory('software composition')).toBe('SCA');
  });

  it('maps interactive/cookie keywords to IAST', () => {
    expect(normalizeCategory('interactive testing')).toBe('IAST');
    expect(normalizeCategory('cookie security')).toBe('IAST');
    expect(normalizeCategory('session management')).toBe('IAST');
  });

  it('maps DNS/SSL/surface keywords to EASM', () => {
    expect(normalizeCategory('dns enumeration')).toBe('EASM');
    expect(normalizeCategory('ssl certificate')).toBe('EASM');
    expect(normalizeCategory('attack surface')).toBe('EASM');
    expect(normalizeCategory('port scan')).toBe('EASM');
  });

  it('maps exploit/fuzz/red keywords to RED_TEAM', () => {
    expect(normalizeCategory('red team')).toBe('RED_TEAM');
    expect(normalizeCategory('exploit chain')).toBe('RED_TEAM');
    expect(normalizeCategory('fuzzing')).toBe('RED_TEAM');
  });

  it('falls back to DAST for unknown categories', () => {
    expect(normalizeCategory('unknown category')).toBe('DAST');
    expect(normalizeCategory('')).toBe('DAST');
  });
});

// ─── generateAiReport fallback (no API key) ──────────────────────────────────

function makeDiag(): DiagnosticResult {
  return {
    url: 'https://target.example.com',
    scannedAt: new Date().toISOString(),
    responseStatus: 200,
    sslSecure: false,
    headers: {},
    missingHeaders: ['content-security-policy', 'strict-transport-security'],
    techLeaked: [],
    probedPaths: [],
    cookieIssues: [],
    sastFindings: [],
    scaLibraries: [],
    easmPerimeter: { subdomains: [], ip: '1.2.3.4', nameserver: 'ns1', protocol: 'http' },
    dastInputs: [],
  };
}

describe('generateAiReport (no API key — local fallback)', () => {
  it('returns a complete result shape', async () => {
    delete process.env.DEEPSEEK_API_KEY;
    const diag = makeDiag();
    const staticCompiled = compileStaticFindings(diag);
    const result = await generateAiReport('https://target.example.com', diag, staticCompiled);

    expect(typeof result.score).toBe('number');
    expect(result.score).toBeGreaterThanOrEqual(10);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(typeof result.aiSummary).toBe('string');
    expect(result.aiSummary.length).toBeGreaterThan(20);
    expect(Array.isArray(result.findings)).toBe(true);
    expect(['info', 'low', 'medium', 'high', 'critical']).toContain(result.severity);
  });

  it('includes the target URL in the fallback summary for critical/high severity', async () => {
    delete process.env.DEEPSEEK_API_KEY;
    const diag = makeDiag();
    const staticCompiled = compileStaticFindings(diag);
    const result = await generateAiReport('https://target.example.com', diag, staticCompiled);
    // Fallback summary should mention the URL
    expect(result.aiSummary).toContain('https://target.example.com');
  });

  it('propagates static findings when AI is unavailable', async () => {
    delete process.env.DEEPSEEK_API_KEY;
    const diag = makeDiag();
    const staticCompiled = compileStaticFindings(diag);
    const result = await generateAiReport('https://target.example.com', diag, staticCompiled);
    expect(result.findings.length).toBe(staticCompiled.findings.length);
  });
});
