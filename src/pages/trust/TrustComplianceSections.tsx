import React from 'react';
import { AlertTriangle, FileCheck, ScrollText, Mail, Server } from 'lucide-react';
import { Section } from './Section';

export function TrustComplianceSections() {
  return (
    <>
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
    </>
  );
}
