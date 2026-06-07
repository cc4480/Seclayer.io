import React, { useState } from 'react';
import { Play, Globe, ArrowRight, AlertTriangle } from 'lucide-react';
import { AuthProfile } from '../../types.js';

interface ScanLauncherProps {
  onInitiateScan: (url: string, authProfileId?: string, authHeader?: string) => Promise<void>;
  isPerformingAction: boolean;
  authProfiles: AuthProfile[];
}

export default function ScanLauncher({ onInitiateScan, isPerformingAction, authProfiles }: ScanLauncherProps) {
  const [scanUrl, setScanUrl] = useState('');
  const [selectedProfileId, setSelectedProfileId] = useState<string>('');
  const [customAuthHeader, setCustomAuthHeader] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [errorText, setErrorText] = useState('');

  const isCustomHeader = selectedProfileId === '__custom__';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorText('');
    const urlStr = scanUrl.trim();
    if (!urlStr) return;
    try {
      const profileId = selectedProfileId && selectedProfileId !== '__custom__' ? selectedProfileId : undefined;
      const authHeader = isCustomHeader ? (customAuthHeader.trim() || undefined) : undefined;
      await onInitiateScan(urlStr, profileId, authHeader);
      setScanUrl('');
      setSelectedProfileId('');
      setCustomAuthHeader('');
    } catch (err: any) {
      setErrorText(err.message || 'Scan initiation failed.');
    }
  };

  return (
    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
      <div className="flex items-center space-x-2.5 mb-4">
        <div className="p-1.5 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded text-[#22c55e]">
          <Play className="w-4 h-4" />
        </div>
        <h2 className="text-sm font-bold font-mono text-white">Trigger Penetration Test</h2>
      </div>
      <p className="text-[#a1a1aa] text-xs font-mono mb-6">
        Enter any public staging, production or application URL. Seclayer runs modern black-box scans checking HTTP headers security, technology signatures leakage, directory exposures, SSL certificate validity, and cookie flags.
      </p>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="text-[11px] font-mono uppercase tracking-wider text-[#52525b] ml-1 block mb-2">Target URL</label>
          <div className="flex bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors">
            <div className="flex items-center text-[#52525b] pl-3 pr-1.5 font-mono text-xs">
              <Globe className="w-4 h-4 text-[#52525b] mr-1.5" />
              <span>https://</span>
            </div>
            <input
              type="text"
              className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 placeholder-[#52525b]"
              placeholder="test-shop-staging.mydomain.io"
              value={scanUrl}
              onChange={(e) => setScanUrl(e.target.value)}
              disabled={isPerformingAction}
              id="target-url-input"
            />
          </div>
        </div>

        <div>
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="text-[11px] font-mono text-[#52525b] hover:text-white uppercase tracking-wider flex items-center space-x-1 transition-colors"
          >
            <span>{showAdvanced ? '- Hide Advanced Options' : '+ Show Advanced Options (Authenticated Scans)'}</span>
          </button>

          {showAdvanced && (
            <div className="mt-3 p-3 bg-black/40 border border-[#27272a] rounded space-y-3">
              <div>
                <label className="text-[10px] font-mono uppercase tracking-wider text-[#52525b] block mb-1">
                  Auth Profile
                </label>
                <p className="text-[10px] font-mono text-[#a1a1aa] mb-2">
                  Select a saved credential profile for authenticated scanning, or enter a raw Authorization header.
                </p>
                <select
                  className="bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono w-full focus:outline-none p-2 rounded transition-colors cursor-pointer"
                  value={selectedProfileId}
                  onChange={(e) => setSelectedProfileId(e.target.value)}
                  disabled={isPerformingAction}
                  id="auth-profile-select"
                >
                  <option value="">None (unauthenticated)</option>
                  {authProfiles.map(profile => (
                    <option key={profile.id} value={profile.id}>
                      {profile.name} — {profile.type.toUpperCase()}
                    </option>
                  ))}
                  <option value="__custom__">Custom Authorization Header...</option>
                </select>
              </div>

              {isCustomHeader && (
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-wider text-[#52525b] block mb-1">
                    Authorization Header Value
                  </label>
                  <input
                    type="text"
                    className="bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono w-full focus:outline-none p-2 rounded placeholder-[#52525b] transition-colors"
                    placeholder="Bearer eyJhbGciOiJIUzI1..."
                    value={customAuthHeader}
                    onChange={(e) => setCustomAuthHeader(e.target.value)}
                    disabled={isPerformingAction}
                    id="auth-header-input"
                  />
                </div>
              )}
            </div>
          )}
        </div>

        {errorText && (
          <div className="bg-[#f87171]/10 border border-[#f87171]/20 text-[#f87171] text-xs p-3 rounded flex items-center space-x-2 font-mono">
            <AlertTriangle className="w-4 h-4 text-[#f87171] shrink-0" />
            <span>{errorText}</span>
          </div>
        )}

        <div className="flex items-center justify-end pt-2">
          <button
            type="submit"
            disabled={isPerformingAction || !scanUrl.trim()}
            className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center space-x-2 shrink-0 cursor-pointer"
            id="trigger-scan-btn"
          >
            <span>Execute audit</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </form>
    </div>
  );
}
