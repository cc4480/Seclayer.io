import React, { useState } from 'react';
import { ArrowRight, Globe } from 'lucide-react';
import { motion } from 'motion/react';
import PentagiDemoSection from './landing/PentagiDemoSection.js';
import PricingSection from './landing/PricingSection.js';
import McpIntegrationTabs from './landing/McpIntegrationTabs.js';
import SampleReportSection from './landing/SampleReportSection.js';

interface LandingProps {
  onStartTrial: (initialUrl: string) => void;
  onNavigate: (view: string, arg?: string) => void;
  onSelectPack: (packName: 'single' | 'pack5' | 'pack20') => void;
  userEmail: string;
}

export default function Landing({ onStartTrial, onNavigate, onSelectPack, userEmail }: LandingProps) {
  const [targetUrl, setTargetUrl] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;
    onStartTrial(targetUrl.trim());
  };

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] selection:bg-[#22c55e]/30 selection:text-[#22c55e]">

      {/* Hero & Background Ambient Grid */}
      <div className="relative py-24 px-6 overflow-hidden border-b border-[#27272a] bg-[radial-gradient(120%_120%_at_50%_0%,rgba(34,197,94,0.05)_0%,rgba(9,9,11,0)_80%)]">
        {/* Aesthetic background matrix layout */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.01)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.01)_1px,transparent_1px)] bg-[size:48px_48px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none" />

        <div className="max-w-4xl mx-auto text-center relative z-10 flex flex-col items-center">

          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="inline-flex items-center space-x-2 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded py-1.5 px-3 mb-8"
          >
            <span className="w-2 h-2 rounded-full bg-[#22c55e] animate-pulse" />
            <span className="text-[#22c55e] font-mono text-xs uppercase tracking-widest pl-1">Seclayer v2.0 is now live</span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.1 }}
            className="text-4xl sm:text-6xl font-mono tracking-tighter font-bold max-w-3xl mb-6 text-white leading-[1.1]"
          >
            Security layer for <br />
            <span className="text-[#22c55e]">
              every single deploy
            </span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.2 }}
            className="text-[#a1a1aa] text-base max-w-xl mb-12 font-mono"
          >
            A black-box penetration testing platform. Submit a URL, purchase scan credits, and receive a plain-English AI-generated penetration testing report.
            <strong className="text-white"> Zero setup, zero subscription required.</strong>
          </motion.p>

          {/* Core URL scan trigger input */}
          <motion.form
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            onSubmit={handleSubmit}
            className="w-full max-w-2xl bg-[#0c0c0e] border border-[#27272a] rounded p-2.5 flex flex-col sm:flex-row items-center space-y-3 sm:space-y-0 sm:space-x-3 shadow-xl mb-8 hover:border-[#3f3f46] transition-colors"
          >
            <div className="relative flex-1 w-full pl-3 flex items-center">
              <Globe className="w-5 h-5 text-[#52525b] mr-3 shrink-0" />
              <input
                type="text"
                placeholder="Enter workspace, API or site URL (e.g., test-app.dev)..."
                className="bg-transparent text-white text-sm font-mono w-full focus:outline-none placeholder-[#52525b]"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                id="landing-url-input"
              />
            </div>
            <button
              type="submit"
              className="w-full sm:w-auto px-6 py-3 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded transition-all flex items-center justify-center space-x-2 shrink-0 active:scale-98 cursor-pointer"
              id="landing-url-submit"
            >
              <span>Audit Now</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </motion.form>

          {/* Quick Stats Banner */}
          <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-3 font-mono text-[10px] uppercase text-[#52525b] tracking-widest bg-[#0c0c0e] py-1.5 px-4 rounded border border-[#27272a] mb-8">
            <span>[+] Over 12,480 security audits executed</span>
            <span className="text-[#27272a]">|</span>
            <span>[+] PentAGI Autonomous Engine</span>
            <span className="text-[#27272a]">|</span>
            <span>[+] API Endpoint coverage up to TLS 1.3</span>
          </div>

          {/* Autonomous AI PentAGI Section */}
          <PentagiDemoSection onStartTrial={onStartTrial} />

        </div>
      </div>

      {/* Core Pay-Per-Scan Pricing Cards */}
      <PricingSection onSelectPack={onSelectPack} />

      {/* Dual Distribution Pitch: MCP Server for Developer Ecosystem */}
      <McpIntegrationTabs onNavigate={onNavigate} />

      {/* Trust Signpost / Interactive sample report previewer */}
      <SampleReportSection />

      {/* Footer */}
      <footer className="border-t border-[#27272a] bg-[#0c0c0e] py-12 text-[#a1a1aa] text-xs font-mono text-center">
        <div className="max-w-7xl mx-auto px-6 space-y-4">
          <p className="text-[11px]">Domain: <strong className="text-white">seclayer.io</strong> • Stack: React + Express 5 + SQLite + DeepSeek AI</p>
          <p className="text-[#52525b]">© 2026 Seclayer Penetration Technologies. All rights reserved. Support: hello@seclayer.io</p>
        </div>
      </footer>

    </div>
  );
}
