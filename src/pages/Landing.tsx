import React from 'react';
import HeroSection from './landing/HeroSection.js';
import PricingSection from './landing/PricingSection.js';
import McpSection from './landing/McpSection.js';
import SampleReportSection from './landing/SampleReportSection.js';
import LandingFooter from './landing/LandingFooter.js';

interface LandingProps {
  onStartTrial: (initialUrl: string) => void;
  onNavigate: (view: string, arg?: string) => void;
  onSelectPack: (packName: 'single' | 'pack5' | 'pack20') => void;
  userEmail: string;
}

export default function Landing({ onStartTrial, onNavigate, onSelectPack }: LandingProps) {
  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] selection:bg-[#22c55e]/30 selection:text-[#22c55e]">
      <HeroSection onStartTrial={onStartTrial} />
      <PricingSection onSelectPack={onSelectPack} />
      <McpSection onNavigate={onNavigate} />
      <SampleReportSection />
      <LandingFooter />
    </div>
  );
}
