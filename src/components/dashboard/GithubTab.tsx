import React from 'react';
import { Github, AlertTriangle, RefreshCw } from 'lucide-react';
import { useGithubConnection } from './github/useGithubConnection.js';
import ConnectedRepoCard from './github/ConnectedRepoCard.js';
import ConnectRepoForm from './github/ConnectRepoForm.js';

export default function GithubTab() {
  const {
    connection,
    loading,
    fetchError,
    repoFullName,
    setRepoFullName,
    token,
    setToken,
    showToken,
    setShowToken,
    connecting,
    connectError,
    disconnecting,
    handleConnect,
    handleDisconnect,
  } = useGithubConnection();

  return (
    <div className="space-y-6 text-xs font-mono">
      {/* Info banner */}
      <div className="bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5">
        <Github className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5" />
        <div className="space-y-1">
          <h4 className="text-white text-xs uppercase font-bold">GitHub Auto-Fix</h4>
          <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
            Connect a repository to let Seclayer open real pull requests for findings it can confidently patch.
            We never expose your access token after it's saved, and no PR is opened unless the AI produces a
            real, validated patch against an actual file in your repo.
          </p>
        </div>
      </div>

      {fetchError && (
        <div className="flex items-center gap-2 text-[#f87171] bg-[#f87171]/5 border border-[#f87171]/20 rounded p-3 text-[11px]">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {fetchError}
        </div>
      )}

      {loading && (
        <div className="flex items-center justify-center py-16 text-[#52525b]">
          <RefreshCw className="w-5 h-5 animate-spin mr-2" />
          <span className="text-xs uppercase tracking-wider">Loading connection...</span>
        </div>
      )}

      {!loading && connection && (
        <ConnectedRepoCard connection={connection} disconnecting={disconnecting} onDisconnect={handleDisconnect} />
      )}

      {!loading && !connection && (
        <ConnectRepoForm
          repoFullName={repoFullName}
          setRepoFullName={setRepoFullName}
          token={token}
          setToken={setToken}
          showToken={showToken}
          setShowToken={setShowToken}
          connecting={connecting}
          connectError={connectError}
          onSubmit={handleConnect}
        />
      )}
    </div>
  );
}
