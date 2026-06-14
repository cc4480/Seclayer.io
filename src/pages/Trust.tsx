import React from 'react';
import {
  Shield, Lock, Database, FileCheck, AlertTriangle, ArrowLeft,
  Eye, Server, ScrollText, CheckCircle2, Mail, ShieldCheck,
} from 'lucide-react';

interface TrustProps {
  onNavigate: (view: string, arg?: string) => void;
}

const PROBE_CATEGORIES = [
  'DNS & email security (SPF/DMARC/DKIM/CAA)',
  'Subdomain enumeration & takeover',
  'TLS/SSL configuration & transport security',
  'Security header analysis (HSTS, CSP, X-Frame, CORS)',
  'Injection probes (SQLi, XSS, SSTI, CRLF, LFI, command)',
  'SSRF incl. cloud-metadata reachability',
  'Authenticated deep crawl & application surface mapping',
  'Business-logic checks (CSRF, IDOR/BOLA, mixed content)',
  'Sensitive path & backup file discovery',
  'GraphQL introspection & API exposure',
  'Dependency / outdated-library analysis (SCA)',
  'Secret & misconfiguration detection (SAST signals)',
];

export default function Trust({ onNavigate }: TrustProps) {
  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-16 px-6">
      <div className="max-w-4xl mx-auto space-y-10">

        {/* Header */}
        <div className="space-y-4">
          <button
            onClick={() => onNavigate('landing')}
            className="flex items-center gap-2 text-xs font-mono text-[#52525b] hover:text-white transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to home
          </button>
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded bg-[#22c55e]/10 border border-[#22c55e]/30 flex items-center justify-center shrink-0">
              <ShieldCheck className="w-6 h-6 text-[#22c55e]" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white font-mono tracking-tight">Security &amp; Trust Center</h1>
              <p className="text-xs font-mono text-[#52525b] mt-1">How Seclayer tests, what we store, and how to report a vulnerability.</p>
            </div>
          </div>
          <p className="text-[11px] font-mono text-[#52525b]">Last updated: June 2026</p>
        </div>

        {/* Honest posture banner */}
        <div className="bg-amber-500/5 border border-amber-500/15 rounded p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
          <p className="text-[12px] font-mono text-[#a1a1aa] leading-relaxed">
            We believe trust is earned with candor. Where a control is in progress rather than certified, we say so
            on this page rather than implying otherwise.
          </p>
        </div>

        {/* Methodology */}
        <Section icon={Eye} title="Our Testing Methodology">
          <p>
            Seclayer runs an automated black-box assessment from the outside in — the same vantage point a real
            attacker has. Every scan combines passive reconnaissance, active probing, and an authenticated deep crawl
            of your application surface, then maps the results to severity and concrete remediation.
          </p>
          <p className="mt-3">Each assessment exercises 70+ distinct checks across these areas:</p>
          <div className="grid sm:grid-cols-2 gap-2 mt-3">
            {PROBE_CATEGORIES.map((c) => (
              <div key={c} className="flex items-start gap-2 text-[11px]">
                <CheckCircle2 className="w-3.5 h-3.5 text-[#22c55e] shrink-0 mt-0.5" />
                <span>{c}</span>
              </div>
            ))}
          </div>
          <p className="mt-4 text-[11px] text-[#52525b]">
            Checks are aligned to the OWASP Top 10 and OWASP API Security Top 10. Findings include an evidence trail,
            a plain-English impact statement, and a tech-stack-specific code fix.
          </p>
        </Section>

        {/* Authorization / ethics */}
        <Section icon={Shield} title="Authorized Testing Only">
          <p>
            You may only scan systems you own or are explicitly authorized to test. Seclayer enforces SSRF protections
            and refuses targets that resolve to private, loopback, or link-local address ranges. By starting a scan you
            confirm you have permission to assess the target. Unauthorized scanning may violate computer-misuse laws and
            is grounds for account termination.
          </p>
        </Section>

        {/* Data handling */}
        <Section icon={Database} title="Data Handling &amp; Retention">
          <ul className="space-y-2.5">
            <Bullet><strong className="text-zinc-300">What we store:</strong> your account email, a hashed password
              (bcrypt — never plaintext), scan targets, scan results/findings, and API keys you generate.</Bullet>
            <Bullet><strong className="text-zinc-300">Where it lives:</strong> in a SQLite database on infrastructure
              under our control. Passwords are hashed; session tokens are signed JWTs.</Bullet>
            <Bullet><strong className="text-zinc-300">We do not sell your data.</strong> Scan results are yours. We do
              not share them with third parties except the AI provider used to generate your report narrative.</Bullet>
            <Bullet><strong className="text-zinc-300">AI processing:</strong> report summaries are generated by DeepSeek
              from your scan diagnostics. Target URLs and finding metadata are sent to produce the write-up; we do not
              send your credentials.</Bullet>
            <Bullet><strong className="text-zinc-300">Deletion:</strong> email <span className="text-[#22c55e]">privacy@seclayer.io</span> to
              request export or deletion of your account and associated scan data.</Bullet>
          </ul>
        </Section>

        {/* Account security */}
        <Section icon={Lock} title="Account &amp; Platform Security">
          <ul className="space-y-2.5">
            <Bullet>Passwords hashed with bcrypt; authentication via signed, expiring JWT session tokens.</Bullet>
            <Bullet>API keys are scoped per account, individually revocable, and never displayed again after creation.</Bullet>
            <Bullet>Rate limiting protects authentication and scan-initiation endpoints against abuse.</Bullet>
            <Bullet>All finding-suppression and remediation actions are recorded with a timestamped audit trail.</Bullet>
          </ul>
        </Section>

        {/* Compliance mapping — honest framing */}
        <Section icon={FileCheck} title="Compliance Mapping">
          <p>
            Every report includes a compliance summary that maps your findings to <strong className="text-zinc-300">PCI-DSS 4.0</strong> and
            <strong className="text-zinc-300"> SOC 2</strong> control families, so you can see which requirements your
            current posture supports.
          </p>
          <div className="bg-amber-500/5 border border-amber-500/15 rounded p-3.5 mt-3 flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
            <p className="text-[11px] leading-relaxed">
              This is a <strong className="text-zinc-300">mapping aid, not a certification</strong>. Seclayer reports
              help you prepare for an audit; they are not a substitute for a formal PCI-DSS or SOC 2 assessment by a
              qualified assessor. Seclayer itself is building toward SOC 2 — we will publish our status here as it
              progresses rather than claim it prematurely.
            </p>
          </div>
        </Section>

        {/* Responsible disclosure */}
        <Section icon={ScrollText} title="Responsible Disclosure">
          <p>
            If you discover a security vulnerability in Seclayer itself, we want to hear from you. Report it privately to
            our security team and give us a reasonable window to remediate before any public disclosure.
          </p>
          <div className="bg-black border border-[#27272a] rounded p-4 mt-3 space-y-2 font-mono text-[12px]">
            <div className="flex items-center gap-2 text-[#22c55e]">
              <Mail className="w-4 h-4 shrink-0" />
              <span className="text-white font-bold select-all">security@seclayer.io</span>
            </div>
            <p className="text-[11px] text-[#52525b] leading-relaxed">
              Safe harbor: we will not pursue legal action against good-faith research that respects user privacy,
              avoids service degradation, does not access or modify data beyond what is needed to demonstrate the issue,
              and gives us time to fix before disclosure.
            </p>
          </div>
        </Section>

        {/* Infra */}
        <Section icon={Server} title="Infrastructure">
          <p>
            Seclayer runs on a Node.js / Express backend with a SQLite datastore and a React front end. Scans execute
            server-side from our scanning infrastructure; your browser never probes the target directly. We continuously
            run an automated test suite (200+ tests) against the platform before deploying changes.
          </p>
        </Section>

        {/* Footer CTA */}
        <div className="border-t border-[#27272a] pt-8 text-center space-y-3">
          <p className="text-[12px] font-mono text-[#52525b]">
            Questions about our security practices? Reach us at <span className="text-[#22c55e]">security@seclayer.io</span>.
          </p>
          <button
            onClick={() => onNavigate('landing')}
            className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono tracking-wider font-bold rounded transition-all"
          >
            Back to Seclayer
          </button>
        </div>

      </div>
    </div>
  );
}

function Section({ icon: Icon, title, children }: { icon: React.ElementType; title: string; children: React.ReactNode }) {
  return (
    <section className="bg-[#0c0c0e] border border-[#27272a] rounded-lg p-6 space-y-3">
      <h2 className="flex items-center gap-2.5 text-white font-mono font-bold text-sm tracking-tight">
        <Icon className="w-4.5 h-4.5 text-[#22c55e]" />
        {title}
      </h2>
      <div className="text-[12px] font-mono leading-relaxed text-[#a1a1aa]">{children}</div>
    </section>
  );
}

function Bullet({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex items-start gap-2.5 text-[11px] leading-relaxed">
      <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e]/60 shrink-0 mt-1.5" />
      <span>{children}</span>
    </li>
  );
}
