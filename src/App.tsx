import React, { useState } from 'react';
import Navbar from './components/Navbar.js';
import Landing from './pages/Landing.js';
import Dashboard from './pages/Dashboard.js';
import ReportViewer from './pages/ReportViewer.js';
import ScanProgress from './pages/ScanProgress.js';
import LoginModal from './components/LoginModal.js';
import { useAppData } from './hooks/useAppData.js';

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
  const [currentView, setCurrentView] = useState<'landing' | 'dashboard' | 'progress' | 'report'>('landing');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showLogin, setShowLogin] = useState(false);

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

        {currentView === 'report' && activeScan && (
          <ReportViewer
            scan={activeScan}
            previousScan={scans.filter(s => s.url === activeScan.url && s.id !== activeScan.id && new Date(s.createdAt).getTime() < new Date(activeScan.createdAt).getTime()).sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]}
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
