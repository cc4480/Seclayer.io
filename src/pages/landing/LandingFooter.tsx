interface LandingFooterProps {
  onNavigate: (view: string, arg?: string) => void;
}

export default function LandingFooter({ onNavigate }: LandingFooterProps) {
  return (
    <footer className="border-t border-[#27272a] bg-[#0c0c0e] py-12 text-[#a1a1aa] text-xs font-mono text-center">
      <div className="max-w-7xl mx-auto px-6 space-y-4">
        <div className="flex items-center justify-center gap-5 flex-wrap">
          <button onClick={() => onNavigate('trust')} className="text-[#a1a1aa] hover:text-[#22c55e] transition-colors cursor-pointer uppercase tracking-widest text-[11px]">
            Security &amp; Trust
          </button>
          <span className="text-[#27272a]">•</span>
          <a href="mailto:security@seclayer.io" className="text-[#a1a1aa] hover:text-[#22c55e] transition-colors uppercase tracking-widest text-[11px]">
            Report a Vulnerability
          </a>
        </div>
        <p className="text-[11px]">Domain: <strong className="text-white">seclayer.io</strong> • Stack: React + Express + SQLite + DeepSeek AI</p>
        <p className="text-[#52525b]">© 2026 Seclayer Penetration Technologies. All rights reserved. Support: hello@seclayer.io</p>
      </div>
    </footer>
  );
}
