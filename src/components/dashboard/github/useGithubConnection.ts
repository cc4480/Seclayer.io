import React, { useState, useEffect } from 'react';
import { apiFetch } from '../../../lib/api.js';
import { GithubConnection } from '../../../types.js';

export function useGithubConnection() {
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

  return {
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
  };
}
