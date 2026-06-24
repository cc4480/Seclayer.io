import React, { useState, useEffect } from 'react';
import { Github, Plug, Trash2, CheckCircle, AlertTriangle, Eye, EyeOff, RefreshCw } from 'lucide-react';
import { apiFetch } from '../../lib/api.js';
import { GithubConnection } from '../../types.js';

export default function GithubTab() {
  const [connection, setConnection] = useState<GithubConnection | null>(null);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const [repoFullName, setRepoFullName] = useState('');
  const [token, setToken] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);

  const fetchConnection = async () => {
    setLoading(true);
    setFetchError(null);
    try {
      const res = await apiFetch('/api/github/connection');
      const data = await res.json();
      if (res.ok) {
        setConnection(data.connection || null);
      } else {
        setFetchError(data.error || 'Failed to load GitHub connection.');
      }
    } catch (err: any) {
      setFetchError(err.message || 'Network error.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConnection();
  }, []);

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoFullName.trim() || !token.trim()) {
      setConnectError('Repository and access token are both required.');
      return;
    }
    setConnecting(true);
    setConnectError(null);
    try {
      const res = await apiFetch('/api/github/connect', {
        method: 'POST',
        body: JSON.stringify({ repoFullName: repoFullName.trim(), token: token.trim() }),
      });
      const data = await res.json();
      if (res.ok) {
        setConnection(data.connection);
        setRepoFullName('');
        setToken('');
      } else {
        setConnectError(data.error || 'Failed to connect repository.');
      }
    } catch (err: any) {
      setConnectError(err.message || 'Network error.');
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    setDisconnecting(true);
    try {
      const res = await apiFetch('/api/github/connection', { method: 'DELETE' });
      if (res.ok) setConnection(null);
    } catch (err) {
      console.error('Failed to disconnect GitHub repository:', err);
    } finally {
      setDisconnecting(false);
    }
  };

  const inputClass =
    'bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono p-2 rounded w-full focus:outline-none transition-colors placeholder-[#52525b]';
  const labelClass = 'text-[10px] font-mono uppercase tracking-wider text-[#52525b] block mb-1';

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
              onClick={handleDisconnect}
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
      )}

      {!loading && !connection && (
        <form
          onSubmit={handleConnect}
          className="bg-black/40 border border-[#27272a] rounded p-6 space-y-4"
        >
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
      )}
    </div>
  );
}
