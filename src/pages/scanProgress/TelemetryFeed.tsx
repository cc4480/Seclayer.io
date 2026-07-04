import React from 'react';

// Live "microcheck" activity feed of timestamped pipeline events.
export default function TelemetryFeed({ activeEvents }: { activeEvents: { time: string; msg: string }[] }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between border-b border-[#27272a]/20 pb-1.5">
        <span className="text-[10px] font-mono text-[#22c55e] uppercase tracking-widest flex items-center gap-1.5 font-bold">
          <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] inline-block animate-ping" />
          <span>Live Pipeline Microcheck Activity</span>
        </span>
        <span className="text-[9px] text-[#52525b] font-bold">REAL-TIME FEED</span>
      </div>

      <div className="bg-black/80 border border-[#27272a]/60 rounded p-3 h-28 overflow-y-auto space-y-1.5 scrollbar-thin select-all">
        {activeEvents.length === 0 ? (
          <div className="text-[#52525b] text-[10px] animate-pulse">Establishing pipeline trace stream...</div>
        ) : (
          activeEvents.map((ev, idx) => (
            <div key={idx} className="flex gap-2 text-[10px] items-start transition-opacity duration-300">
              <span className="text-zinc-500 shrink-0 font-bold">[{ev.time}]</span>
              <span className="text-[#22c55e] shrink-0 font-bold select-none">●</span>
              <span className="text-zinc-300 leading-tight">{ev.msg}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
