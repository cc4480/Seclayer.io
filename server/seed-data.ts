import { Scan } from '../src/types.js';

/** Seed scans so a fresh datastore looks populated out-of-the-box. */
export const INITIAL_DEMO_SCANS: Record<string, Scan> = {
  'demo-scan-1': {
    id: 'demo-scan-1',
    userId: 'user_default',
    url: 'https://seclayer.io',
    status: 'complete',
    score: 94,
    severity: 'low',
    createdAt: new Date(Date.now() - 3600000 * 48).toISOString(), // 2 days ago
    completedAt: new Date(Date.now() - 3600000 * 47.9).toISOString(),
    aiSummary: "The target website is exceptionally well-secured. All standard security headers are present with secure configurations. SSL/TLS is modern and correctly configured. The server does not leak technological implementations, which limits vector fingerprinting. Minor adjustments are suggested for Subresource Integrity (SRI) on external scripts.",
    findings: [
      {
        id: 'finding-1',
        title: 'Missing Subresource Integrity (SRI) on external vendor assets',
        description: 'Several script tags loaded from third-party CDNs (including analytical resources) do not feature integrity hashes. If these vendors are compromised, malicious code could run in visitors\' browser context.',
        severity: 'low',
        fix: 'Add the integrity="" attribute with correct SHA-384 hashes and crossorigin="anonymous" to all external script and stylesheet links.',
        category: 'Client-side Security'
      },
      {
        id: 'finding-2',
        title: 'TLS 1.2 Suite with mild preference for CBC ciphers',
        description: 'The server supports TLS 1.2 with certain Cipher-Block Chaining (CBC) suites enabled. While not actively exploitable, transitioning to fully authenticated AEAD ciphers represents superior hygiene.',
        severity: 'info',
        fix: 'Update the server TLS cipher string to prefer GCM/CHACHA20 suites and deprecate CBC-mode ciphers where legacy client compatibility allows.',
        category: 'Cryptography'
      }
    ]
  },
  'demo-scan-2': {
    id: 'demo-scan-2',
    userId: 'user_default',
    url: 'https://vulnerable-test-shop.org',
    status: 'complete',
    score: 41,
    severity: 'high',
    createdAt: new Date(Date.now() - 3600000 * 120).toISOString(), // 5 days ago
    completedAt: new Date(Date.now() - 3600000 * 119.8).toISOString(),
    aiSummary: "The application exhibits severe perimeter exposures. Multiple critical issues were uncovered, including high-risk directory listing, sensitive file leakage (.env containing database credentials), and completely missing anti-framing and modern script protection policies (missing Content-Security-Policy). Remediation represents an urgent requirement to avoid data exfiltration or site hijacking.",
    findings: [
      {
        id: 'finding-3',
        title: 'Exposed Environment Configuration File (.env)',
        description: 'A raw /.env configuration file was detected and read via root directory probing. This file contains active credentials, including database passwords, Stripe private keys, and SMTP server logins.',
        severity: 'critical',
        fix: 'Immediately change all leaked credentials. Move the .env file completely out of the public serving directory (web root) and verify server configuration rules block requests to dotfiles.',
        category: 'Information Leakage'
      },
      {
        id: 'finding-4',
        title: 'Directory Listing Enabled on /uploads',
        description: 'Requesting /uploads returns a directory index listing all raw filenames. This allows unauthorized exploration of customer assets, user attachments, and server filesystem details.',
        severity: 'medium',
        fix: 'Disable index lists globally in the HTTP server configuration (e.g., `Options -Indexes` in Apache or removing `autoindex on;` in nginx).',
        category: 'Access Control'
      },
      {
        id: 'finding-5',
        title: 'Missing Content-Security-Policy (CSP) Header',
        description: 'The response does not contain a Content-Security-Policy header. Browsers are left vulnerable to Cross-Site Scripting (XSS) and data injection attacks.',
        severity: 'high',
        fix: 'Implement a strict CSP header declaring trusted sources for scripts, styles, images, and frame origins. Utilize nonces or hashes for inline content.',
        category: 'Headers Security'
      },
      {
        id: 'finding-6',
        title: 'X-Powered-By Exposure: PHP 7.4.3',
        description: 'The server response header leaks both technology and precise versioning strings (PHP/7.4.3). This aids malicous operators in target matching against known platform CVEs.',
        severity: 'low',
        fix: 'Disable the X-Powered-By header via server configuration or runtime flags (e.g., set expose_php = Off in php.ini).',
        category: 'Information Leakage'
      }
    ]
  }
};
