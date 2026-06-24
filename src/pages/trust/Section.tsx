import React from 'react';

export function Section({ icon: Icon, title, children }: { icon: React.ElementType; title: string; children: React.ReactNode }) {
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

export function Bullet({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex items-start gap-2.5 text-[11px] leading-relaxed">
      <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e]/60 shrink-0 mt-1.5" />
      <span>{children}</span>
    </li>
  );
}
