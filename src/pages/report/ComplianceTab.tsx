import { Scan, Finding } from '../../types.js';

interface ComplianceTabProps {
  scan: Scan;
  findings: Finding[];
}

type ComplianceStatus = 'PASS' | 'FAIL' | 'WARN';
type ComplianceReq = { id: string; name: string; status: ComplianceStatus; auto?: string };

const badgeClass = (status: ComplianceStatus) => {
  if (status === 'PASS') return 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/20';
  if (status === 'FAIL') return 'bg-red-900/20 text-[#f87171] border border-red-900/40';
  return 'bg-amber-900/20 text-amber-400 border border-amber-900/40';
};

function ComplianceTable({ rows }: { rows: ComplianceReq[] }) {
  return (
    <table className="w-full text-xs font-mono border-collapse">
      <thead>
        <tr className="border-b border-[#27272a]">
          <th className="text-left py-2 px-3 text-[#52525b] uppercase tracking-wider text-[10px] font-bold w-28">Req ID</th>
          <th className="text-left py-2 px-3 text-[#52525b] uppercase tracking-wider text-[10px] font-bold">Criterion</th>
          <th className="text-right py-2 px-3 text-[#52525b] uppercase tracking-wider text-[10px] font-bold w-24">Status</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(req => (
          <tr key={req.id} className="border-b border-[#27272a]/40 hover:bg-black/20 transition-colors">
            <td className="py-2.5 px-3 text-[#a1a1aa]">{req.id}</td>
            <td className="py-2.5 px-3 text-[#a1a1aa]">
              {req.name}
              {req.auto && (
                <span className="ml-2 text-[#52525b] text-[10px]">— {req.auto}</span>
              )}
            </td>
            <td className="py-2.5 px-3 text-right">
              <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${badgeClass(req.status)}`}>
                {req.status}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * PCI-DSS 4.0 / SOC2 compliance mapping tab, derived entirely from the
 * scan's non-suppressed findings and overall score.
 */
export default function ComplianceTab({ scan, findings }: ComplianceTabProps) {
  const activeFindings = findings.filter(f => !f.isFalsePositive);

  // Helper: check if any finding matches keyword list at high/critical severity
  const checkFail = (keywords: string[]) =>
    activeFindings.some(f =>
      (f.severity === 'high' || f.severity === 'critical') &&
      keywords.some(kw =>
        f.title.toLowerCase().includes(kw.toLowerCase()) ||
        f.description.toLowerCase().includes(kw.toLowerCase())
      )
    );

  // PCI-DSS 4.0 requirements
  const pciReqs: ComplianceReq[] = [
    {
      id: 'Req 4.2.1',
      name: 'Strong Cryptography',
      status: checkFail(['TLS', 'SSL', 'certificate', 'HSTS', 'expired']) ? 'FAIL' : 'PASS',
    },
    {
      id: 'Req 6.2.4',
      name: 'Protect Against Known Attacks',
      status: checkFail(['injection', 'XSS', 'cross-site', 'SSTI', 'template', 'traversal', 'command']) ? 'FAIL' : 'PASS',
    },
    {
      id: 'Req 6.3.2',
      name: 'Software Component Inventory',
      status: checkFail(['jQuery', 'Bootstrap', 'Lodash', 'AngularJS', 'outdated', 'library']) ? 'FAIL' : 'PASS',
    },
    {
      id: 'Req 8.2.1',
      name: 'User Authentication Controls',
      status: checkFail(['CORS', 'cookie', 'session', 'authentication', 'bypass', 'credential']) ? 'FAIL' : 'PASS',
    },
    {
      id: 'Req 11.3.2',
      name: 'External Vulnerability Scans',
      status: 'PASS',
      auto: 'This scan satisfies the requirement',
    },
    {
      id: 'Req 11.4.1',
      name: 'Penetration Testing',
      status: 'PASS',
      auto: 'This scan satisfies the requirement',
    },
  ];

  // SOC2 Trust Service Criteria
  const soc2Reqs: ComplianceReq[] = [
    {
      id: 'CC6.1',
      name: 'Logical Access Controls',
      status: checkFail(['CORS', 'authentication', 'bypass', 'IDOR', 'access control']) ? 'FAIL' : 'PASS',
    },
    {
      id: 'CC6.6',
      name: 'Logical Access Threats',
      status: checkFail(['injection', 'XSS', 'SSRF', 'traversal', 'command']) ? 'FAIL' : 'PASS',
    },
    {
      id: 'CC7.1',
      name: 'Vulnerability Detection',
      status: 'PASS',
      auto: 'This scan satisfies the requirement',
    },
    {
      id: 'CC8.1',
      name: 'Change Management',
      status: checkFail(['outdated', 'library', 'jQuery', 'Bootstrap', 'SCA']) ? 'FAIL' : 'PASS',
    },
    {
      id: 'CC9.2',
      name: 'Risk Monitoring',
      status: (scan.score ?? 100) >= 70 ? 'PASS' : 'WARN',
      auto: (scan.score ?? 100) >= 70 ? 'Score meets threshold' : `Score ${scan.score ?? 100}/100 is below the 70-point threshold`,
    },
  ];

  const pciFails = pciReqs.filter(r => r.status === 'FAIL').length;
  const soc2Fails = soc2Reqs.filter(r => r.status === 'FAIL').length;

  return (
    <div className="space-y-8 animate-fade-in">

      {/* PCI-DSS 4.0 Section */}
      <div className="bg-[#0c0c0e] border border-[#27272a] rounded overflow-hidden">
        <div className="px-5 py-4 border-b border-[#27272a] flex items-center justify-between">
          <div>
            <h4 className="text-white text-xs font-bold font-mono uppercase tracking-wider">PCI-DSS 4.0 Requirements</h4>
            <p className="text-[#52525b] text-[10px] font-mono mt-0.5">Payment Card Industry Data Security Standard — mapped from scan findings</p>
          </div>
          {pciFails > 0 ? (
            <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-red-900/20 text-[#f87171] border border-red-900/40 font-bold">
              {pciFails} failing requirement{pciFails !== 1 ? 's' : ''}
            </span>
          ) : (
            <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/20 font-bold">
              All requirements passing
            </span>
          )}
        </div>
        <div className="px-2 py-2">
          <ComplianceTable rows={pciReqs} />
        </div>
      </div>

      {/* SOC2 Section */}
      <div className="bg-[#0c0c0e] border border-[#27272a] rounded overflow-hidden">
        <div className="px-5 py-4 border-b border-[#27272a] flex items-center justify-between">
          <div>
            <h4 className="text-white text-xs font-bold font-mono uppercase tracking-wider">SOC2 Trust Service Criteria</h4>
            <p className="text-[#52525b] text-[10px] font-mono mt-0.5">Service Organization Controls — mapped from scan findings</p>
          </div>
          {soc2Fails > 0 ? (
            <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-red-900/20 text-[#f87171] border border-red-900/40 font-bold">
              {soc2Fails} failing criterion{soc2Fails !== 1 ? 'a' : ''}
            </span>
          ) : (
            <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/20 font-bold">
              All criteria passing
            </span>
          )}
        </div>
        <div className="px-2 py-2">
          <ComplianceTable rows={soc2Reqs} />
        </div>
      </div>

      {/* Export disclaimer */}
      <p className="text-[#52525b] text-[10px] font-mono text-center leading-relaxed">
        This compliance mapping is auto-generated from scan findings. Engage a qualified assessor for formal certification.
      </p>

    </div>
  );
}
