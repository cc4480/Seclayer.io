import React from 'react';
import { Copy } from 'lucide-react';

interface CodeBlockProps {
  code: string;
  onCopy: () => void;
  variant?: 'dim' | 'terminal';
  wrapInCode?: boolean;
}

const VARIANT_CLASSES: Record<'dim' | 'terminal', string> = {
  dim: 'bg-[#09090b] border border-[#27272a]/40 text-[#a1a1aa]',
  terminal: 'bg-[#18181b] border border-[#27272a] text-[#22c55e]',
};

export default function CodeBlock({ code, onCopy, variant = 'dim', wrapInCode = false }: CodeBlockProps) {
  const preClassName = `${VARIANT_CLASSES[variant]} p-4 rounded text-[10px] overflow-x-auto`;

  return (
    <div className="relative group">
      <pre className={preClassName}>
        {wrapInCode ? <code>{code}</code> : code}
      </pre>
      <button
        className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
        onClick={onCopy}
      >
        <Copy className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}
