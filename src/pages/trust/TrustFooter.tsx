import React from 'react';

interface TrustFooterProps {
  onNavigate: (view: string, arg?: string) => void;
}

export function TrustFooter({ onNavigate }: TrustFooterProps) {
  return (
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
  );
}
