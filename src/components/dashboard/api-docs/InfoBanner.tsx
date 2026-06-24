import React from 'react';

interface InfoBannerProps {
  icon: React.ReactNode;
  title: string;
  description: React.ReactNode;
  className?: string;
}

export default function InfoBanner({ icon, title, description, className = '' }: InfoBannerProps) {
  return (
    <div className={`bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5 ${className}`.trim()}>
      {icon}
      <div className="space-y-1">
        <h4 className="text-white text-xs uppercase font-bold">{title}</h4>
        <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
          {description}
        </p>
      </div>
    </div>
  );
}
