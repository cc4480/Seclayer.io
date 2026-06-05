import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar.js';
import Landing from './pages/Landing.js';
import Dashboard from './pages/Dashboard.js';
import ReportViewer from './pages/ReportViewer.js';
import ScanProgress from './pages/ScanProgress.js';
import LoginModal from './components/LoginModal.js';
import { User, Scan, ApiKey } from './types.js';
import { apiFetch, setToken, clearToken, getToken } from './lib/api.js';

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [credits, setCredits] = useState(0);
  const [transactions, setTransactions] = useState<any[]>([]);

  const [currentView, setCurrentView] = useState<'landing' | 'dashboard' | 'progress' | 'report'>('landing');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [isPerformingAction, setIsPerformingAction] = useState(false);

  // On mount: restore session from stored token, handle Stripe return
  useEffect(() => {
    const token = getToken();
    if (token) {
      loadUserContext();
    }

    // Handle Stripe checkout success redirect
    const params = new URLSearchParams(window.location.search);
    if (params.get('checkout_success') === 'true') {
      window.history.replaceState({}, '', window.location.pathname);
      if (token) {
        // Small delay to ensure webhook has processed
        setTimeout(() => loadUserContext(), 1500);
      }
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
      setCredits(userData.user.credits);

      const [scansRes, keysRes, creditsRes] = await Promise.all([
        apiFetch('/api/scans'),
        apiFetch('/api/keys'),
        apiFetch('/api/credits'),
      ]);

      if (scansRes.ok) setScans((await scansRes.json()).scans);
      if (keysRes.ok) setApiKeys((await keysRes.json()).keys);
      if (creditsRes.ok) {
        const c = await creditsRes.json();
        setTransactions(c.transactions || []);
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

  const onInitiateScan = async (url: string, authHeader?: string) => {
    if (!user) { setShowLogin(true); return; }

    setIsPerformingAction(true);
    try {
      const res = await apiFetch('/api/scans', {
        method: 'POST',
        body: JSON.stringify({ url, authHeader }),
      });

      if (res.ok) {
        const data = await res.json();
        setCredits(prev => Math.max(0, prev - 1));
        setScans(prev => [data.scan, ...prev]);
        setSelectedScanId(data.scan.id);
        setCurrentView('progress');
        setTimeout(() => loadUserContext(), 1000);
      } else {
        const errData = await res.json();
        alert(errData.message || 'Scan initiation failed');
      }
    } catch (err) {
      console.error('Scan launch error:', err);
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

  const onPurchaseCredits = async (packName: 'single' | 'pack5' | 'pack20') => {
    if (!user) { setShowLogin(true); return; }
    setIsPerformingAction(true);
    try {
      const res = await apiFetch('/api/credits/checkout', {
        method: 'POST',
        body: JSON.stringify({ pack: packName }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.url) {
          // Redirect to Stripe hosted checkout
          window.location.href = data.url;
        }
      } else {
        const err = await res.json();
        alert(err.message || 'Checkout failed. Please try again.');
      }
    } catch (err) {
      console.error('Purchase error:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const handleLoginSuccess = async (token: string, userData: User) => {
    setToken(token);
    setUser(userData);
    setCredits(userData.credits);
    await loadUserContext();
    setCurrentView('dashboard');
  };

  const handleLogout = async () => {
    try { await apiFetch('/api/auth/logout', { method: 'POST' }); } catch {}
    clearToken();
    setUser(null);
    setScans([]);
    setApiKeys([]);
    setCredits(0);
    setCurrentView('landing');
  };

  const activeScan = scans.find(s => s.id === selectedScanId);

  return (
    <div className="bg-zinc-950 min-h-screen flex flex-col font-sans">
      <Navbar
        currentView={currentView}
        onNavigate={handleNavigate}
        userEmail={user?.email || ''}
        credits={credits}
        onLogout={handleLogout}
        onLoginClick={() => setShowLogin(true)}
      />

      <main className="flex-1">
        {currentView === 'landing' && (
          <Landing
            onStartTrial={handleStartTrial}
            onNavigate={handleNavigate}
            onSelectPack={(pack) => {
              if (!user) { setShowLogin(true); return; }
              onPurchaseCredits(pack);
              setCurrentView('dashboard');
            }}
            userEmail={user?.email || ''}
          />
        )}

        {currentView === 'dashboard' && user && (
          <Dashboard
            user={user}
            scans={scans}
            apiKeys={apiKeys}
            credits={credits}
            transactions={transactions}
            onInitiateScan={onInitiateScan}
            onGenerateKey={onGenerateKey}
            onRevokeKey={onRevokeKey}
            onPurchaseCredits={onPurchaseCredits}
            onViewReport={(scanId) => {
              const checkScan = scans.find(s => s.id === scanId);
              if (checkScan && ['queued', 'scanning', 'analyzing'].includes(checkScan.status)) {
                setSelectedScanId(scanId);
                setCurrentView('progress');
              } else {
                handleNavigate('report', scanId);
              }
            }}
            isPerformingAction={isPerformingAction}
          />
        )}

        {currentView === 'progress' && selectedScanId && (
          <ScanProgress
            scanId={selectedScanId}
            onScanFinished={(scanId) => {
              loadUserContext();
              handleNavigate('report', scanId);
            }}
            onCancel={() => {
              setCurrentView('dashboard');
              setSelectedScanId(null);
            }}
          />
        )}

        {currentView === 'report' && activeScan && (
          <ReportViewer
            scan={activeScan}
            previousScan={scans
              .filter(s => s.url === activeScan.url && s.id !== activeScan.id && new Date(s.createdAt).getTime() < new Date(activeScan.createdAt).getTime())
              .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]}
            onBack={() => handleNavigate('dashboard')}
            onRefreshScans={() => loadUserContext()}
          />
        )}
      </main>

      {showLogin && (
        <LoginModal
          onClose={() => setShowLogin(false)}
          onLoginSuccess={handleLoginSuccess}
        />
      )}
    </div>
  );
}
