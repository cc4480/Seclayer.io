import React from 'react';
import { Plug, AlertTriangle, Eye, EyeOff, RefreshCw } from 'lucide-react';
import { inputClass, labelClass } from './styles.js';

interface ConnectRepoFormProps {
  repoFullName: string;
  setRepoFullName: (value: string) => void;
  token: string;
  setToken: (value: string) => void;
  showToken: boolean;
  setShowToken: (value: boolean) => void;
  connecting: boolean;
  connectError: string | null;
  onSubmit: (e: React.FormEvent) => void;
}

export default function ConnectRepoForm({
  repoFullName,
  setRepoFullName,
  token,
  setToken,
  showToken,
  setShowToken,
  connecting,
  connectError,
  onSubmit,
}: ConnectRepoFormProps) {
  return (
    <form onSubmit={onSubmit} className="bg-black/40 border border-[#27272a] rounded p-6 space-y-4">
      <h4 className="text-white font-bold uppercase tracking-tight text-xs mb-2">Connect a Repository</h4>

      <div>
        <label className={labelClass}>Repository</label>
        <input
          type="text"
          className={inputClass}
          placeholder="owner/repo"
          value={repoFullName}
          onChange={e => setRepoFullName(e.target.value)}
        />
      </div>

      <div>
        <label className={labelClass}>Personal Access Token</label>
        <div className="relative">
          <input
            type={showToken ? 'text' : 'password'}
            className={inputClass + ' pr-9'}
            placeholder="ghp_..."
            value={token}
            onChange={e => setToken(e.target.value)}
          />
          <button
            type="button"
            onClick={() => setShowToken(!showToken)}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-[#52525b] hover:text-[#a1a1aa] transition-colors cursor-pointer"
          >
            {showToken ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
        </div>
        <p className="text-[10px] text-[#52525b] mt-1.5">
          Needs "Contents" (read/write) and "Pull requests" (write) permissions on the target repo.
        </p>
      </div>

      {connectError && (
        <div className="flex items-center gap-2 text-[#f87171] bg-[#f87171]/5 border border-[#f87171]/20 rounded p-3 text-[11px]">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {connectError}
        </div>
      )}

      <div className="flex items-center justify-end gap-3 pt-1">
        <button
          type="submit"
          disabled={connecting}
          className="px-4 py-2 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center space-x-1.5 cursor-pointer"
        >
          {connecting ? (
            <><RefreshCw className="w-3.5 h-3.5 animate-spin" /><span>Connecting...</span></>
          ) : (
            <><Plug className="w-3.5 h-3.5" /><span>Connect</span></>
          )}
        </button>
      </div>
    </form>
  );
}
