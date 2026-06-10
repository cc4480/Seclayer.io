import React from 'react';
import { Terminal, Coins, ArrowRight } from 'lucide-react';
import { User } from '../../types.js';

interface DashboardHeaderProps {
  user: User;
  credits: number;
  onOpenPentagi: () => void;
}

/** Console header banner: account context, PentAGI shortcut, and credit balance. */
export default function DashboardHeader({ user, credits, onOpenPentagi }: DashboardHeaderProps) {
  return (
    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-[#0c0c0e] p-6 rounded border border-[#27272a] relative overflow-hidden">
      <div className="absolute top-0 right-0 w-80 h-80 bg-[#22c55e]/5 rounded-full blur-[80px] pointer-events-none" />

      <div className="relative z-10 w-full md:w-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
        <div>
          <h1 className="text-2xl font-mono font-bold tracking-tighter text-white mb-1">Developer Console</h1>
          <p className="text-[#a1a1aa] text-xs font-mono">
            Account context: <span className="text-white">{user.email}</span>
          </p>
        </div>
      </div>

      <div className="flex flex-col md:flex-row items-center space-y-4 md:space-y-0 md:space-x-6 relative z-10 w-full md:w-auto">
        <button
          onClick={onOpenPentagi}
          className="w-full md:w-auto relative group overflow-hidden bg-black border border-[#22c55e]/40 rounded hover:border-[#22c55e] transition-colors p-3 flex items-center space-x-3 cursor-pointer"
        >
          <div className="absolute inset-0 bg-[#22c55e]/10 translate-y-full group-hover:translate-y-0 transition-transform duration-300 ease-out" />
          <div className="relative flex items-center justify-center bg-[#09090b] border border-[#27272a] rounded p-1.5 w-10 h-10 shrink-0">
            <Terminal className="w-5 h-5 text-[#22c55e] animate-pulse" />
          </div>
          <div className="relative text-left pr-2">
            <span className="block text-xs font-bold text-white uppercase tracking-wider">PentAGI Audit</span>
            <span className="block text-[10px] text-[#22c55e] font-mono mt-0.5">Autonomous AI Agents</span>
          </div>
          <ArrowRight className="w-4 h-4 text-[#52525b] group-hover:text-[#22c55e] transition-colors absolute right-4 opacity-0 group-hover:opacity-100 hidden sm:block" />
        </button>

        <div className="text-right flex items-center justify-between w-full md:w-auto md:block pt-4 border-t border-[#27272a]/40 md:pt-0 md:border-0">
          <span className="text-[10px] font-mono text-[#52525b] uppercase block md:mb-0.5">Available Balance</span>
          <span className="text-2xl font-mono font-black text-[#22c55e] flex items-center space-x-2">
            <Coins className="w-5 h-5 text-[#22c55e] shrink-0" />
            <span>{credits} <span className="text-xs font-normal text-[#52525b] font-mono">scans</span></span>
          </span>
        </div>
      </div>
    </div>
  );
}
