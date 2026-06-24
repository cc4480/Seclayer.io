import React from 'react';
import Navbar from './components/Navbar.js';
import Landing from './pages/Landing.js';
import Dashboard from './pages/Dashboard.js';
import ReportViewer from './pages/ReportViewer.js';
import ScanProgress from './pages/ScanProgress.js';
import Trust from './pages/Trust.js';
import LoginModal from './components/LoginModal.js';
import { useAppState } from './app/useAppState.js';

export default function App() {
  const {
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
  } = useAppState();

  return (
    <div className="bg-zinc-950 min-h-screen flex flex-col font-sans">
      <Navbar
        currentView={currentView}
        onNavigate={handleNavigate}
        userEmail={user?.email || ''}
        onLogout={handleLogout}
        onLoginClick={() => setShowLogin(true)}
      />

      <main className="flex-1">
        {currentView === 'landing' && (
          <Landing
            onStartTrial={handleStartTrial}
            onNavigate={handleNavigate}
            userEmail={user?.email || ''}
          />
        )}

        {currentView === 'trust' && (
          <Trust onNavigate={handleNavigate} />
        )}

        {currentView === 'dashboard' && user && (
          <Dashboard
            user={user}
            scans={scans}
            apiKeys={apiKeys}
            authProfiles={authProfiles}
            onInitiateScan={onInitiateScan}
            onGenerateKey={onGenerateKey}
            onRevokeKey={onRevokeKey}
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
