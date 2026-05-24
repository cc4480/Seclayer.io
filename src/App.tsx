import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar.js';
import Landing from './pages/Landing.js';
import Dashboard from './pages/Dashboard.js';
import ReportViewer from './pages/ReportViewer.js';
import ScanProgress from './pages/ScanProgress.js';
import LoginModal from './components/LoginModal.js';
import { User, Scan, ApiKey } from './types.js';
import { ShieldAlert, RefreshCw } from 'lucide-react';

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [credits, setCredits] = useState(0);
  const [transactions, setTransactions] = useState<any[]>([]);
  
  // Navigation states
  const [currentView, setCurrentView] = useState<'landing' | 'dashboard' | 'progress' | 'report'>('landing');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [isPerformingAction, setIsPerformingAction] = useState(false);
  
  // Fetch initial profile & stats (automatically uses user_default out of the box)
  useEffect(() => {
    loadUserContext('user_default');
  }, []);

  const loadUserContext = async (userId: string) => {
    setIsPerformingAction(true);
    try {
      // 1. Fetch user profile
      const userRes = await fetch(`/api/auth/me?userId=${userId}`);
      if (userRes.ok) {
        const userData = await userRes.json();
        setUser(userData.user);
        setCredits(userData.user.credits);

        // 2. Fetch user's scans list
        const scansRes = await fetch(`/api/scans?userId=${userId}`);
        if (scansRes.ok) {
          const scansData = await scansRes.json();
          setScans(scansData.scans);
        }

        // 3. Fetch user's developer keys
        const keysRes = await fetch(`/api/keys?userId=${userId}`);
        if (keysRes.ok) {
          const keysData = await keysRes.json();
          setApiKeys(keysData.keys);
        }

        // 4. Fetch user credit transactions
        const creditsRes = await fetch(`/api/credits?userId=${userId}`);
        if (creditsRes.ok) {
          const creditsData = await creditsRes.json();
          setTransactions(creditsData.transactions || []);
        }
      }
    } catch (err) {
      console.error('Error loading user dashboard metrics:', err);
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
    // Scroll smoothly back to top on transitions
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleStartTrial = (initialUrl: string) => {
    // If guest clicks landing page audit input, we route them into console 
    // and trigger the scan immediately! Outstanding, frictionless signup flow.
    if (!user) {
      setShowLogin(true);
      return;
    }
    setCurrentView('dashboard');
    setTimeout(() => {
      onInitiateScan(initialUrl);
    }, 400);
  };

  const onInitiateScan = async (url: string) => {
    if (!user) {
      setShowLogin(true);
      return;
    }

    setIsPerformingAction(true);
    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, userId: user.id })
      });

      if (res.ok) {
        const data = await res.json();
        // Optimistically deduct credit locally & add scan to list
        setCredits(prev => Math.max(0, prev - 1));
        setScans(prev => [data.scan, ...prev]);
        
        // Open scanning terminal screen
        setSelectedScanId(data.scan.id);
        setCurrentView('progress');
        
        // Refresh full state background metrics in parallel
        setTimeout(() => loadUserContext(user.id), 1000);
      } else {
        const errData = await res.json();
        alert(errData.message || 'Scanning initiation failed');
      }
    } catch (err) {
      console.error('Core scan launch err:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const onGenerateKey = async () => {
    if (!user) return;
    setIsPerformingAction(true);
    try {
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: user.id })
      });
      if (res.ok) {
        // Reload keys listing
        loadUserContext(user.id);
      }
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
      const res = await fetch(`/api/keys/${keyId}?userId=${user.id}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        // Reload keys listing
        loadUserContext(user.id);
      }
    } catch (err) {
      console.error('Key revoking error:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const onPurchaseCredits = async (packName: 'single' | 'pack5' | 'pack20') => {
    if (!user) {
      setShowLogin(true);
      return;
    }
    setIsPerformingAction(true);
    try {
      const res = await fetch('/api/credits/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: user.id, pack: packName })
      });
      if (res.ok) {
        const data = await res.json();
        // Immediately reload user credentials containing topped-up values
        await loadUserContext(user.id);
      }
    } catch (err) {
      console.error('Purchase transactions simulation failed:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const handleLoginSuccess = async (email: string) => {
    setIsPerformingAction(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        
        // Load credits and list scans belonging to this freshly authorized user profile
        await loadUserContext(data.user.id);
        setCurrentView('dashboard');
      }
    } catch (err) {
      console.error('Sign-in synchronization failure:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch {}
    setUser(null);
    setScans([]);
    setApiKeys([]);
    setCredits(0);
    setCurrentView('landing');
  };

  // Find active scan we are polling/viewing
  const activeScan = scans.find(s => s.id === selectedScanId);

  return (
    <div className="bg-zinc-950 min-h-screen flex flex-col font-sans">
      
      {/* Universal navigation bar */}
      <Navbar
        currentView={currentView}
        onNavigate={handleNavigate}
        userEmail={user?.email || ''}
        credits={credits}
        onLogout={handleLogout}
        onLoginClick={() => setShowLogin(true)}
      />

      {/* Primary Page views router mapping */}
      <main className="flex-1">
        {currentView === 'landing' && (
          <Landing 
            onStartTrial={handleStartTrial}
            onNavigate={handleNavigate}
            onSelectPack={(pack) => {
              if (!user) {
                setShowLogin(true);
                return;
              }
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
              if (checkScan && (checkScan.status === 'queued' || checkScan.status === 'scanning' || checkScan.status === 'analyzing')) {
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
              // Refresh history lists & immediately route to viewer page
              if (user) loadUserContext(user.id);
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
            onBack={() => handleNavigate('dashboard')}
            onRefreshScans={() => loadUserContext(user?.id || 'user_default')}
          />
        )}
      </main>

      {/* Passwordless Magic Sign-in popup option */}
      {showLogin && (
        <LoginModal
          onClose={() => setShowLogin(false)}
          onLoginSuccess={handleLoginSuccess}
        />
      )}

    </div>
  );
}
