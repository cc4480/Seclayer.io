import { describe, it, expect } from 'vitest';
import { compileStaticFindings } from '../../server/scanner.js';
import type { DiagnosticResult } from '../../server/scanner.js';

function baseDiag(overrides: Partial<DiagnosticResult> = {}): DiagnosticResult {
  return {
    url: 'https://example.com',
    scannedAt: new Date().toISOString(),
    responseStatus: 200,
    sslSecure: true,
    headers: {},
    missingHeaders: [],
    techLeaked: [],
    probedPaths: [],
    cookieIssues: [],
    sastFindings: [],
    scaLibraries: [],
    easmPerimeter: { subdomains: [], ip: '1.2.3.4', nameserver: 'ns1.example.com', protocol: 'https' },
    dastInputs: [],
    ...overrides,
  };
}

describe('compileStaticFindings', () => {
  it('returns score 100 and no findings for a clean target', () => {
    const result = compileStaticFindings(baseDiag());
    expect(result.score).toBe(100);
    expect(result.findings).toHaveLength(0);
  });

  it('adds EASM finding and deducts 30 for HTTP-only target', () => {
    const result = compileStaticFindings(baseDiag({ sslSecure: false }));
    const easm = result.findings.find(f => f.category === 'EASM' && f.title.includes('Insecure'));
    expect(easm).toBeDefined();
    expect(easm!.severity).toBe('high');
    expect(result.score).toBe(70);
  });

  it('adds EASM finding when tech headers are leaked', () => {
    const result = compileStaticFindings(baseDiag({ techLeaked: ['Express', 'Node.js'] }));
    const finding = result.findings.find(f => f.title.includes('Signature'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('low');
    expect(result.score).toBe(95);
  });

  it('adds IAST finding for missing CSP header', () => {
    const result = compileStaticFindings(baseDiag({ missingHeaders: ['content-security-policy'] }));
    const csp = result.findings.find(f => f.title.includes('Content-Security-Policy'));
    expect(csp).toBeDefined();
    expect(csp!.severity).toBe('high');
    expect(csp!.category).toBe('IAST');
  });

  it('adds IAST finding for missing HSTS header', () => {
    const result = compileStaticFindings(baseDiag({ missingHeaders: ['strict-transport-security'] }));
    const hsts = result.findings.find(f => f.title.includes('HSTS'));
    expect(hsts).toBeDefined();
    expect(hsts!.severity).toBe('medium');
  });

  it('adds IAST finding for missing X-Frame-Options', () => {
    const result = compileStaticFindings(baseDiag({ missingHeaders: ['x-frame-options'] }));
    const xfo = result.findings.find(f => f.title.includes('X-Frame-Options'));
    expect(xfo).toBeDefined();
    expect(xfo!.severity).toBe('medium');
  });

  it('adds EASM finding for live subdomains', () => {
    const result = compileStaticFindings(baseDiag({
      easmPerimeter: {
        subdomains: [
          { domain: 'staging.example.com', status: 'live', port: '443' },
          { domain: 'dev.example.com', status: 'live', port: '80' },
        ],
        ip: '1.2.3.4', nameserver: 'ns1', protocol: 'https',
      },
    }));
    const subFinding = result.findings.find(f => f.title.includes('Subdomain'));
    expect(subFinding).toBeDefined();
    expect(subFinding!.severity).toBe('medium');
  });

  it('exposes sensitive paths as high severity findings', () => {
    const result = compileStaticFindings(baseDiag({
      probedPaths: [
        { path: '/.env', status: 200, exposed: true },
      ],
    }));
    const env = result.findings.find(f => f.title.includes('Exposed Sensitive Path') || f.description.includes('.env'));
    expect(env).toBeDefined();
    expect(['high', 'critical']).toContain(env!.severity);
  });

  it('reflects SAST findings from diagnostics', () => {
    const result = compileStaticFindings(baseDiag({
      sastFindings: [{
        file: 'app.js',
        issue: 'Hardcoded secret',
        severity: 'critical',
        type: 'secret',
        fix: 'Move to env vars',
        description: 'Hardcoded API key found',
      }],
    }));
    const sast = result.findings.find(f => f.category === 'SAST');
    expect(sast).toBeDefined();
    expect(sast!.severity).toBe('critical');
  });

  it('reflects SCA library findings', () => {
    const result = compileStaticFindings(baseDiag({
      scaLibraries: [{
        name: 'lodash',
        version: '4.17.15',
        status: 'vuln',
        advisories: ['CVE-2021-23337'],
        severity: 'high',
        description: 'Prototype pollution',
        fix: 'Upgrade to 4.17.21',
      }],
    }));
    const sca = result.findings.find(f => f.category === 'SCA');
    expect(sca).toBeDefined();
    expect(sca!.title).toContain('lodash');
  });

  it('accumulates score deductions from multiple issues', () => {
    const result = compileStaticFindings(baseDiag({
      sslSecure: false,
      missingHeaders: ['content-security-policy', 'strict-transport-security'],
    }));
    // -30 (SSL) -20 (CSP) -10 (HSTS) = 40
    expect(result.score).toBe(40);
  });

  it('floors score at 12 regardless of how many issues are found', () => {
    const result = compileStaticFindings(baseDiag({
      sslSecure: false,
      missingHeaders: ['content-security-policy', 'strict-transport-security', 'x-frame-options'],
      techLeaked: ['Express'],
      cookieIssues: ['session cookie missing Secure flag', 'session cookie missing HttpOnly flag'],
      probedPaths: [
        { path: '/.env', status: 200, exposed: true },
        { path: '/.git/HEAD', status: 200, exposed: true },
      ],
    }));
    expect(result.score).toBeGreaterThanOrEqual(12);
  });

  it('assigns severity based on the worst active finding', () => {
    const result = compileStaticFindings(baseDiag({
      sslSecure: false,
      missingHeaders: ['content-security-policy'],
    }));
    expect(['high', 'critical']).toContain(result.severity);
  });

  it('all findings have required fields', () => {
    const result = compileStaticFindings(baseDiag({
      sslSecure: false,
      missingHeaders: ['content-security-policy'],
    }));
    for (const f of result.findings) {
      expect(f.id).toBeTruthy();
      expect(f.title).toBeTruthy();
      expect(f.description).toBeTruthy();
      expect(f.severity).toBeTruthy();
      expect(f.fix).toBeTruthy();
      expect(f.category).toBeTruthy();
    }
  });
});
