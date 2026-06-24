import { useState, useEffect } from 'react';
import { User, Scan, ApiKey, AuthProfile } from '../types.js';
import { apiFetch, setToken, clearToken, getToken } from '../lib/api.js';

export function useAppState() {
  const [user, setUser] = useState<User | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [authProfiles, setAuthProfiles] = useState<AuthProfile[]>([]);
  const [currentView, setCurrentView] = useState<'landing' | 'dashboard' | 'progress' | 'report' | 'trust'>('landing');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [isPerformingAction, setIsPerformingAction] = useState(false);

  // On mount: restore session from stored token
  useEffect(() => {
    const token = getToken();
    if (token) {
      loadUserContext();
    }
  }, []);

  const loadUserContext = async () => {
    setIsPerformingAction(true);
    try {
      const userRes = await apiFetch('/api/auth/me');
      if (!userRes.ok) {
        // Token invalid or expired — clear it
        clearToken();
        setUser(null);
        return;
      }
      const userData = await userRes.json();
      setUser(userData.user);

      const [scansRes, keysRes, profilesRes] = await Promise.all([
        apiFetch('/api/scans'),
        apiFetch('/api/keys'),
        apiFetch('/api/auth-profiles'),
      ]);

      if (scansRes.ok) setScans((await scansRes.json()).scans);
      if (keysRes.ok) setApiKeys((await keysRes.json()).keys);
      if (profilesRes.ok) {
        const profilesData = await profilesRes.json();
        setAuthProfiles(profilesData.profiles || profilesData || []);
      }
    } catch (err) {
      console.error('Error loading user context:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const handleNavigate = (view: string, arg?: string) => {
    if (view === 'report' && arg) {
      setSelectedScanId(arg);
      setCurrentView('report');
    } else {
      setSelectedScanId(null);
      setCurrentView(view as any);
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleStartTrial = (initialUrl: string) => {
    if (!user) {
      setShowLogin(true);
      return;
    }
    setCurrentView('dashboard');
    setTimeout(() => onInitiateScan(initialUrl), 400);
  };

  const onInitiateScan = async (url: string, authProfileId?: string, authHeader?: string) => {
    if (!user) { setShowLogin(true); return; }

    setIsPerformingAction(true);
    try {
      const res = await apiFetch('/api/scans', {
        method: 'POST',
        body: JSON.stringify({ url, authProfileId, authHeader }),
      });

      if (res.ok) {
        const data = await res.json();
        setScans(prev => [data.scan, ...prev]);
        setSelectedScanId(data.scan.id);
        setCurrentView('progress');
        setTimeout(() => loadUserContext(), 1000);
      } else {
        const errData = await res.json();
        throw new Error(errData.message || 'Scan initiation failed.');
      }
    } finally {
      setIsPerformingAction(false);
    }
  };

  const onGenerateKey = async () => {
    if (!user) return;
    setIsPerformingAction(true);
    try {
      const res = await apiFetch('/api/keys', { method: 'POST', body: JSON.stringify({}) });
      if (res.ok) loadUserContext();
    } catch (err) {
      console.error('Key generation error:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const onRevokeKey = async (keyId: string) => {
    if (!user) return;
    setIsPerformingAction(true);
    try {
      const res = await apiFetch(`/api/keys/${keyId}`, { method: 'DELETE' });
      if (res.ok) loadUserContext();
    } catch (err) {
      console.error('Key revoke error:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const handleLoginSuccess = async (token: string, userData: User) => {
    setToken(token);
    setUser(userData);
    await loadUserContext();
    setCurrentView('dashboard');
  };

  const handleLogout = async () => {
    try { await apiFetch('/api/auth/logout', { method: 'POST' }); } catch {}
    clearToken();
    setUser(null);
    setScans([]);
    setApiKeys([]);
    setAuthProfiles([]);
    setCurrentView('landing');
  };

  const activeScan = scans.find(s => s.id === selectedScanId);

  return {
    user,
    scans,
    apiKeys,
    authProfiles,
    currentView,
    setCurrentView,
    selectedScanId,
    setSelectedScanId,
    showLogin,
    setShowLogin,
    isPerformingAction,
    activeScan,
    loadUserContext,
    handleNavigate,
    handleStartTrial,
    onInitiateScan,
    onGenerateKey,
    onRevokeKey,
    handleLoginSuccess,
    handleLogout,
  };
}
