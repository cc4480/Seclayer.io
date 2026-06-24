import React from 'react';
import { AlertTriangle, ArrowLeft, ShieldCheck } from 'lucide-react';

interface TrustHeaderProps {
  onNavigate: (view: string, arg?: string) => void;
}

export function TrustHeader({ onNavigate }: TrustHeaderProps) {
  return (
    <>
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
    </>
  );
}
