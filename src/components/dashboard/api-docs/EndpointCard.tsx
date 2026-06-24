import React from 'react';

interface EndpointCardProps {
  method: string;
  path: string;
  children: React.ReactNode;
}

export default function EndpointCard({ method, path, children }: EndpointCardProps) {
  return (
    <div className="bg-black border border-[#27272a] rounded overflow-hidden">
      <div className="bg-[#0c0c0e] px-4 py-3 border-b border-[#27272a] flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <span className="bg-[#22c55e]/10 text-[#22c55e] px-2 py-0.5 rounded font-mono text-[9px] uppercase font-bold tracking-wider">{method}</span>
          <h3 className="text-white font-mono text-xs font-bold sm:text-sm">{path}</h3>
        </div>
      </div>
      {children}
    </div>
  );
}
