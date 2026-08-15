import React from 'react';

export default function LandingFooter() {
  return (
    <footer className="border-t border-[#27272a] bg-[#0c0c0e] py-12 text-[#a1a1aa] text-xs font-mono text-center">
      <div className="max-w-7xl mx-auto px-6 space-y-4">
        <p className="text-[11px]">Domain: <strong className="text-white">seclayer.io</strong> • Stack: React + Express + DeepSeek AI</p>
        <p className="text-[#52525b]">© 2026 Seclayer Penetration Technologies. All rights reserved. Support: hello@seclayer.io</p>
      </div>
    </footer>
  );
}
