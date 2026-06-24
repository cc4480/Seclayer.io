import React from 'react';
import { FileText } from 'lucide-react';

interface SnippetCardProps {
  title: string;
  children: React.ReactNode;
}

export default function SnippetCard({ title, children }: SnippetCardProps) {
  return (
    <div className="bg-black border border-[#27272a] rounded overflow-hidden">
      <div className="bg-[#0c0c0e] px-4 py-3 border-b border-[#27272a] flex items-center">
        <FileText className="w-3.5 h-3.5 text-[#52525b] mr-2" />
        <h3 className="text-white font-mono text-xs font-bold sm:text-sm">{title}</h3>
      </div>
      <div className="p-5">
        {children}
      </div>
    </div>
  );
}
