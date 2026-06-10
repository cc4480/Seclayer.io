import type { DiagnosticResult } from './scanner.js';

/** A single row in the Hadrian API security probe matrix. */
export interface HadrianMatrixEntry {
  endpoint: string;
  methods: string[];
  rolesResult: Record<string, { status: string; color: string }>;
  vulnerability: string | null;
}

/** Best-effort service label for a discovered subdomain, based on its probed port and name. */
export function inferServiceFromPort(port: string, subdomain: string): string {
  switch (port) {
    case '1194':
      return 'OpenVPN Daemon';
    case '25':
      return 'SMTP Mail Relay';
    case '443':
      if (/^api\./.test(subdomain)) return 'HTTPS API Endpoint';
      if (/^admin\./.test(subdomain)) return 'HTTPS Admin Portal';
      if (/^(staging|dev|test|qa)\./.test(subdomain)) return 'HTTPS Non-Production Environment';
      return 'HTTPS Web Service';
    default:
      return 'Unresponsive / Filtered';
  }
}

/** Build the per-endpoint role/authorization matrix for the Hadrian API security probe. */
export function buildHadrianMatrix(
  diag: DiagnosticResult,
  target: string,
  authHeader?: string,
): HadrianMatrixEntry[] {
  const matrix: HadrianMatrixEntry[] = [];

  (diag.apiSecFindings ?? []).forEach((f) => {
    matrix.push({
      endpoint: f.endpoint,
      methods: ['GET', 'POST'],
      rolesResult: {
        'Unauthenticated Request': { status: 'Allow (Vulnerable)', color: 'text-red-500 font-bold' },
        'Supplied Credentials': authHeader
          ? { status: 'Allow', color: 'text-amber-400' }
          : { status: 'Not Tested (No Credentials Supplied)', color: 'text-zinc-500' },
        'Object/Schema Access': { status: 'Exposed', color: 'text-red-500 font-bold' },
      },
      vulnerability: `${f.testName}: ${f.description}`,
    });
  });

  diag.dastInputs.forEach((d) => {
    matrix.push({
      endpoint: d.formAction,
      methods: [d.method],
      rolesResult: {
        'Unauthenticated Request': { status: 'Allow', color: 'text-amber-400' },
        'Supplied Credentials': authHeader
          ? { status: 'Allow', color: 'text-amber-400' }
          : { status: 'Not Tested (No Credentials Supplied)', color: 'text-zinc-500' },
        'CSRF Token Check': d.csrfPresent
          ? { status: 'Present', color: 'text-[#22c55e]' }
          : { status: 'Missing', color: 'text-red-500 font-bold' },
      },
      vulnerability: d.csrfPresent ? null : `${d.vulnerability}: ${d.description}`,
    });
  });

  diag.probedPaths
    .filter((p) => p.exposed)
    .forEach((p) => {
      matrix.push({
        endpoint: p.path,
        methods: ['GET'],
        rolesResult: {
          'Unauthenticated Request': { status: `Allow (HTTP ${p.status})`, color: 'text-red-500 font-bold' },
          'Supplied Credentials': authHeader
            ? { status: `Allow (HTTP ${p.status})`, color: 'text-red-500 font-bold' }
            : { status: 'Not Tested (No Credentials Supplied)', color: 'text-zinc-500' },
          'Resource Exposure': { status: 'Publicly Accessible', color: 'text-red-500 font-bold' },
        },
        vulnerability: `Sensitive resource "${p.path}" is publicly accessible (HTTP ${p.status}) on "${target}". This may expose configuration, credentials, or version-control metadata.`,
      });
    });

  if (matrix.length === 0) {
    matrix.push({
      endpoint: new URL(target).pathname || '/',
      methods: ['GET'],
      rolesResult: {
        'Unauthenticated Request': { status: `HTTP ${diag.responseStatus || 'N/A'}`, color: 'text-zinc-300' },
        'Supplied Credentials': authHeader
          ? { status: `HTTP ${diag.responseStatus || 'N/A'}`, color: 'text-zinc-300' }
          : { status: 'Not Tested (No Credentials Supplied)', color: 'text-zinc-500' },
        'Object/Schema Access': { status: 'Not Exposed', color: 'text-[#22c55e]' },
      },
      vulnerability: null,
    });
  }

  return matrix;
}
