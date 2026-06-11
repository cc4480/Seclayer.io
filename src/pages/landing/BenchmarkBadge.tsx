import React from 'react';
import { Target, ShieldCheck, BadgeCheck, Lock } from 'lucide-react';
import { motion } from 'motion/react';
import { BENCHMARK_STATS, BENCHMARK_DISPLAY } from '../../lib/benchmark-stats.js';

/**
 * Verifiable accuracy trust signal. The numbers come from `benchmark-stats`,
 * which a CI test asserts against the live scanner — so this can't drift from
 * what the engine actually does.
 */
export default function BenchmarkBadge() {
  const stats = [
    { icon: Target, value: BENCHMARK_DISPLAY.detection, label: `Detection rate · ${BENCHMARK_DISPLAY.checks} vuln classes` },
    { icon: ShieldCheck, value: BENCHMARK_DISPLAY.falsePositives, label: 'False positives' },
    { icon: BadgeCheck, value: BENCHMARK_DISPLAY.validated, label: 'Validated exploit PoCs' },
    { icon: Lock, value: BENCHMARK_STATS.authenticatedScanning ? 'Yes' : 'No', label: 'Authenticated scanning' },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.35 }}
      className="w-full max-w-2xl mb-8"
      id="landing-benchmark-badge"
    >
      <div className="flex items-center justify-center space-x-2 mb-3">
        <ShieldCheck className="w-3.5 h-3.5 text-[#22c55e]" />
        <span className="text-[10px] font-mono uppercase tracking-widest text-[#22c55e]">
          Benchmark-verified accuracy
        </span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {stats.map((s) => (
          <div
            key={s.label}
            className="bg-[#0c0c0e] border border-[#27272a] rounded p-3 text-center hover:border-[#22c55e]/30 transition-colors"
          >
            <s.icon className="w-4 h-4 text-[#22c55e] mx-auto mb-1.5" />
            <div className="text-xl font-mono font-bold text-white leading-none">{s.value}</div>
            <div className="text-[9px] font-mono text-[#52525b] uppercase tracking-wide mt-1.5 leading-tight">{s.label}</div>
          </div>
        ))}
      </div>
      <p className="text-[9px] font-mono text-[#52525b] text-center mt-2.5 tracking-wide">
        Measured on a reproducible, labeled benchmark (CI-enforced · <span className="text-[#a1a1aa]">npm run benchmark</span>).
      </p>
    </motion.div>
  );
}
