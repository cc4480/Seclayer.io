import React from 'react';
import { Github, Trash2, CheckCircle, RefreshCw } from 'lucide-react';
import { GithubConnection } from '../../../types.js';

interface ConnectedRepoCardProps {
  connection: GithubConnection;
  disconnecting: boolean;
  onDisconnect: () => void;
}

export default function ConnectedRepoCard({ connection, disconnecting, onDisconnect }: ConnectedRepoCardProps) {
  return (
    <div className="bg-black/80 border border-[#27272a] rounded p-5 space-y-4 hover:border-[#3f3f46] transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <Github className="w-3.5 h-3.5 text-[#a1a1aa]" />
            <span className="text-white font-bold text-xs">{connection.repoFullName}</span>
            <span className="flex items-center gap-1 text-[9px] text-[#22c55e]">
              <CheckCircle className="w-3 h-3" />
              Connected
            </span>
          </div>
          <p className="text-[#52525b] text-[10px]">
            Connected {new Date(connection.createdAt).toLocaleString()}
          </p>
        </div>
        <button
          onClick={onDisconnect}
          disabled={disconnecting}
          className="shrink-0 px-3 py-1.5 border border-[#f87171]/30 text-[#f87171] hover:bg-[#f87171]/10 rounded text-[10px] font-mono uppercase tracking-wider transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer flex items-center gap-1.5"
        >
          {disconnecting ? (
            <><RefreshCw className="w-3 h-3 animate-spin" /><span>Disconnecting...</span></>
          ) : (
            <><Trash2 className="w-3 h-3" /><span>Disconnect</span></>
          )}
        </button>
      </div>
    </div>
  );
}
