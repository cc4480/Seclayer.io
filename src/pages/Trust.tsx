import React from 'react';
import { TrustHeader } from './trust/TrustHeader';
import { TrustFooter } from './trust/TrustFooter';
import { TrustPolicySections } from './trust/TrustPolicySections';
import { TrustComplianceSections } from './trust/TrustComplianceSections';

interface TrustProps {
  onNavigate: (view: string, arg?: string) => void;
}

export default function Trust({ onNavigate }: TrustProps) {
  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-16 px-6">
      <div className="max-w-4xl mx-auto space-y-10">
        <TrustHeader onNavigate={onNavigate} />
        <TrustPolicySections />
        <TrustComplianceSections />
        <TrustFooter onNavigate={onNavigate} />
      </div>
    </div>
  );
}
