import HeroPentagiSection from './landing/HeroPentagiSection.js';
import McpPitchSection from './landing/McpPitchSection.js';
import SampleReportCard from './landing/SampleReportCard.js';
import LandingFooter from './landing/LandingFooter.js';

interface LandingProps {
  onStartTrial: (initialUrl: string) => void;
  onNavigate: (view: string, arg?: string) => void;
  userEmail: string;
}

export default function Landing({ onStartTrial, onNavigate, userEmail }: LandingProps) {
  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] selection:bg-[#22c55e]/30 selection:text-[#22c55e]">
      <HeroPentagiSection onStartTrial={onStartTrial} userEmail={userEmail} />
      <McpPitchSection onNavigate={onNavigate} />
      <SampleReportCard />
      <LandingFooter onNavigate={onNavigate} />
    </div>
  );
}
