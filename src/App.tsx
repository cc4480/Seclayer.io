import React, { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';
import Navbar from './components/Navbar.js';
import Landing from './pages/Landing.js';
import Dashboard from './pages/Dashboard.js';
import ReportViewer from './pages/ReportViewer.js';
import ScanProgress from './pages/ScanProgress.js';
import LoginModal from './components/LoginModal.js';
import { useAppData } from './hooks/useAppData.js';
import { Scan } from './types.js';

const REPORT_PATH_PREFIX = '/reports/';

/** Map a browser pathname to the view/scan it represents. */
function parseLocationPath(pathname: string): { view: 'landing' | 'dashboard' | 'report'; scanId: string | null } {
  if (pathname.startsWith(REPORT_PATH_PREFIX)) {
    const scanId = pathname.slice(REPORT_PATH_PREFIX.length);
    if (scanId) return { view: 'report', scanId };
  }
  if (pathname === '/dashboard') return { view: 'dashboard', scanId: null };
  return { view: 'landing', scanId: null };
}

/** Map a view/scan back to the shareable path, or null if it has no URL of its own. */
function pathForView(view: string, scanId: string | null): string | null {
  if (view === 'report' && scanId) return `${REPORT_PATH_PREFIX}${scanId}`;
  if (view === 'dashboard') return '/dashboard';
  if (view === 'landing') return '/';
  return null;
}

export default function App() {
  const {
    user,
    scans,
    apiKeys,
    credits,
    transactions,
    isPerformingAction,
    loadUserContext,
    initiateScan,
    generateKey,
    revokeKey,
    purchaseCredits,
    login,
    logout,
  } = useAppData();

  // Navigation states
  const [currentView, setCurrentView] = useState<'landing' | 'dashboard' | 'progress' | 'report'>(
    () => parseLocationPath(window.location.pathname).view
  );
  const [selectedScanId, setSelectedScanId] = useState<string | null>(
    () => parseLocationPath(window.location.pathname).scanId
  );
  const [showLogin, setShowLogin] = useState(false);

  // Shared report lookup: used when a /reports/:id link points at a scan
  // that isn't in the current user's own scan list.
  const [sharedScan, setSharedScan] = useState<Scan | null>(null);
  const [sharedScanError, setSharedScanError] = useState<string | null>(null);

  const handleNavigate = (view: string, arg?: string) => {
    const nextScanId = view === 'report' && arg ? arg : null;
    if (view === 'report' && arg) {
      setSelectedScanId(arg);
      setCurrentView('report');
    } else {
      setSelectedScanId(null);
      setCurrentView(view as any);
    }

    // Keep the address bar in sync so report links can be shared/bookmarked.
    const path = pathForView(view, nextScanId);
    if (path && path !== window.location.pathname) {
      window.history.pushState(null, '', path);
    }

    // Scroll smoothly back to top on transitions
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Sync state with browser back/forward navigation.
  useEffect(() => {
    const onPopState = () => {
      const { view, scanId } = parseLocationPath(window.location.pathname);
      setSelectedScanId(scanId);
      setCurrentView(view);
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

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

  const onInitiateScan = async (url: string, authHeader?: string) => {
    if (!user) {
      setShowLogin(true);
      return;
    }
    const scan = await initiateScan(url, authHeader);
    if (scan) {
      // Open scanning terminal screen
      setSelectedScanId(scan.id);
      setCurrentView('progress');
    }
  };

  const onPurchaseCredits = async (packName: 'single' | 'pack5' | 'pack20') => {
    if (!user) {
      setShowLogin(true);
      return;
    }
    await purchaseCredits(packName);
  };

  const handleLoginSuccess = async (email: string) => {
    const loggedIn = await login(email);
    if (loggedIn) {
      setCurrentView('dashboard');
    }
  };

  const handleLogout = async () => {
    await logout();
    setCurrentView('landing');
  };

  // Find active scan we are polling/viewing
  const activeScan = scans.find(s => s.id === selectedScanId);
  const reportScan = activeScan || sharedScan;

  // /reports/:id links should resolve even when the scan isn't in the
  // current user's own list (e.g. a report shared by another account).
  useEffect(() => {
    if (currentView !== 'report' || !selectedScanId || activeScan) {
      return;
    }
    let cancelled = false;
    setSharedScan(null);
    setSharedScanError(null);
    fetch(`/api/scans/${selectedScanId}`)
      .then(async (res) => {
        if (!res.ok) throw new Error('This report does not exist or is no longer available.');
        const data = await res.json();
        return data.scan as Scan;
      })
      .then((scan) => {
        if (!cancelled) setSharedScan(scan);
      })
      .catch((err) => {
        if (!cancelled) setSharedScanError(err.message || 'This report does not exist or is no longer available.');
      });
    return () => { cancelled = true; };
  }, [currentView, selectedScanId, activeScan]);

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
            onGenerateKey={generateKey}
            onRevokeKey={revokeKey}
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

        {currentView === 'report' && selectedScanId && reportScan && (
          <ReportViewer
            scan={reportScan}
            previousScan={activeScan
              ? scans.filter(s => s.url === activeScan.url && s.id !== activeScan.id && new Date(s.createdAt).getTime() < new Date(activeScan.createdAt).getTime()).sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]
              : undefined}
            onBack={() => handleNavigate(user ? 'dashboard' : 'landing')}
            onRefreshScans={() => loadUserContext(user?.id || 'user_default')}
          />
        )}

        {currentView === 'report' && selectedScanId && !reportScan && (
          <div className="min-h-[60vh] flex items-center justify-center px-6">
            <div className="text-center space-y-3 max-w-sm">
              <Shield className="w-8 h-8 text-[#52525b] mx-auto" />
              <h2 className="text-white font-mono text-sm font-bold uppercase tracking-wider">
                {sharedScanError ? 'Report Not Found' : 'Loading Report...'}
              </h2>
              <p className="text-[#71717a] font-mono text-xs">
                {sharedScanError || 'Fetching shared audit report...'}
              </p>
              {sharedScanError && (
                <button
                  onClick={() => handleNavigate(user ? 'dashboard' : 'landing')}
                  className="text-[#22c55e] font-mono text-xs uppercase tracking-wider hover:underline cursor-pointer"
                >
                  {user ? 'Back to dashboard' : 'Back to home'}
                </button>
              )}
            </div>
          </div>
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
