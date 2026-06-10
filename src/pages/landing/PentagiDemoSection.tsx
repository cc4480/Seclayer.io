import React, { useState } from 'react';
import { Terminal, Play, CheckCircle } from 'lucide-react';
import { motion } from 'motion/react';

interface PentagiDemoSectionProps {
  onStartTrial: (initialUrl: string) => void;
}

/** Interactive PentAGI demo console: streams simulated agent logs for a target URL. */
export default function PentagiDemoSection({ onStartTrial }: PentagiDemoSectionProps) {
  const [pentagiTargetUrl, setPentagiTargetUrl] = useState('');
  const [pentagiRunning, setPentagiRunning] = useState(false);
  const [pentagiLogs, setPentagiLogs] = useState<any[]>([]);
  const [pentagiComplete, setPentagiComplete] = useState(false);

  const runLandingPentagi = async () => {
    if (!pentagiTargetUrl.trim()) return;
    setPentagiRunning(true);
    setPentagiLogs([]);
    setPentagiComplete(false);

    try {
      const res = await fetch(`/api/enterprise/pentagi/logs?url=${encodeURIComponent(pentagiTargetUrl.trim())}`);
      if (res.ok) {
        const data = await res.json();
        let idx = 0;
        const interval = setInterval(() => {
          if (idx < data.logs.length) {
            setPentagiLogs((prev) => [...prev, data.logs[idx]]);
            idx++;
          } else {
            clearInterval(interval);
            setPentagiRunning(false);
            setPentagiComplete(true);
          }
        }, 1200);
      } else {
        setPentagiRunning(false);
      }
    } catch (err) {
      setPentagiRunning(false);
    }
  };

  const handlePentagiSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runLandingPentagi();
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.7, delay: 0.4 }}
      className="w-full max-w-4xl p-6 bg-[#0c0c0e] border border-[#22c55e]/30 rounded shadow-[0_0_20px_rgba(34,197,94,0.05)] text-left flex flex-col md:flex-row items-center gap-8 relative overflow-hidden"
    >
      <div className="absolute top-0 right-0 w-64 h-64 bg-[#22c55e]/5 rounded-full blur-[80px] pointer-events-none" />
      <div className="flex-1 relative z-10">
        <h3 className="text-white font-mono font-bold text-lg mb-3 flex items-center space-x-2">
          <Terminal className="w-5 h-5 text-[#22c55e]" />
          <span>Autonomous AI Exploitation (PentAGI)</span>
        </h3>
        <p className="text-[#a1a1aa] font-mono text-[11.5px] leading-relaxed mb-4">
          Experience next-generation vulnerability discovery. Seclayer utilizes a collaborative swarm of LLM-powered AI agents (Scout, Exploiter, and Reporter) to discover, test, and safely exploit vulnerabilities in real-time, matching the persistence and creativity of a human red team.
        </p>
        <ul className="space-y-2 text-[#52525b] font-mono text-[10px] uppercase tracking-wider">
          <li className="flex items-center space-x-2">
            <CheckCircle className="w-3 h-3 text-[#22c55e]" />
            <span>Dynamic Exploitation & Chain Chasing</span>
          </li>
          <li className="flex items-center space-x-2">
            <CheckCircle className="w-3 h-3 text-[#22c55e]" />
            <span>Interactive Real-time Console</span>
          </li>
          <li className="flex items-center space-x-2">
            <CheckCircle className="w-3 h-3 text-[#22c55e]" />
            <span>Instant CVSS Severity Verification</span>
          </li>
        </ul>
      </div>
      <div className="w-full md:w-[400px] bg-black p-4 rounded border border-[#27272a] shadow-inner relative z-10 font-mono text-[10px] text-[#a1a1aa] flex flex-col space-y-3 min-h-[220px]">
        <p className="border-b border-[#27272a] pb-2 text-[#52525b] flex justify-between items-center">
          <span>Interactive Agentic Console</span>
          {pentagiRunning && <span className="text-[#22c55e] animate-pulse">Running...</span>}
        </p>

        {!pentagiRunning && !pentagiComplete && (
          <form onSubmit={handlePentagiSubmit} className="space-y-3 flex-1 flex flex-col justify-center">
            <div>
              <label className="text-[10px] text-[#52525b] mb-1.5 block">Target URL to Attack</label>
              <div className="flex bg-[#0c0c0e] border border-[#27272a] rounded overflow-hidden focus-within:border-[#22c55e]">
                <input
                  type="text"
                  value={pentagiTargetUrl}
                  onChange={(e) => setPentagiTargetUrl(e.target.value)}
                  placeholder="test.vuln-demo.com"
                  className="bg-transparent px-3 py-2 text-white w-full focus:outline-none"
                />
              </div>
            </div>
            <button type="submit" disabled={!pentagiTargetUrl.trim()} className="bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/20 hover:bg-[#22c55e]/20 py-2 rounded flex items-center justify-center space-x-2 transition-colors disabled:opacity-50">
              <Play className="w-3 h-3 fill-[#22c55e]" />
              <span>Initialize Test Swarm</span>
            </button>
          </form>
        )}

        {pentagiRunning && (
          <div className="space-y-2 overflow-y-auto max-h-[160px] flex-1">
            {pentagiLogs.map((log, i) => (
              <p key={i} className="animate-fade-in text-zinc-300">
                <span className="text-[#22c55e] font-bold">[{log.time}] {log.agent}:</span> <span className="text-[#a1a1aa]">{log.msg}</span>
              </p>
            ))}
            <p className="text-[#52525b] animate-pulse">...</p>
          </div>
        )}

        {pentagiComplete && (
          <div className="flex-1 flex flex-col space-y-3">
            <div className="space-y-2 overflow-y-auto max-h-[100px] mb-2 opacity-50">
              {pentagiLogs.slice(-3).map((log, i) => (
                <p key={i}>
                  <span className="text-[#22c55e] font-bold">[{log.time}] {log.agent}:</span> <span className="text-[#a1a1aa]">{log.msg}</span>
                </p>
              ))}
            </div>
            <div className="border border-[#22c55e]/20 bg-[#22c55e]/5 p-3 rounded text-center mb-2">
              <span className="text-[#22c55e] font-bold block mb-1">Exploitation Chain Validated</span>
              <span className="text-zinc-400">High severity vectors confirmed on target network.</span>
            </div>
            <button
              onClick={() => onStartTrial(pentagiTargetUrl)}
              className="w-full bg-[#22c55e] hover:bg-[#4ade80] text-black font-bold uppercase tracking-wider py-2 rounded transition-colors"
            >
              View Official Security Report
            </button>
          </div>
        )}
      </div>
    </motion.div>
  );
}
