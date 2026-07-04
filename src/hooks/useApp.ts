import { useState, useEffect } from 'react';
import { User, Scan, ApiKey } from '../types.js';
import { api } from '../api/client.js';
import { loadUserContext as loadContext } from '../api/loadContext.js';

export type AppView = 'landing' | 'dashboard' | 'progress' | 'report';

// Central application controller: session data, navigation state, and the
// action handlers wired to the backend. Kept as a hook so App.tsx stays a thin
// view. Behaviour mirrors the original inline implementation exactly.
export function useApp() {
  const [user, setUser] = useState<User | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [credits, setCredits] = useState(0);
  const [transactions, setTransactions] = useState<any[]>([]);

  // Navigation states
  const [currentView, setCurrentView] = useState<AppView>('landing');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [isPerformingAction, setIsPerformingAction] = useState(false);

  // Restore the session (if any) on load. Identity comes from the httpOnly
  // session cookie, so no userId is ever passed from the client.
  useEffect(() => {
    loadUserContext();
  }, []);

  const loadUserContext = () => loadContext({
    setUser, setCredits, setScans, setApiKeys, setTransactions,
    setCurrentView, setIsPerformingAction,
  });

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

    setIsPerformingAction(true);
    try {
      const res = await api.createScan(url, authHeader);

      if (res.ok) {
        const data = await res.json();
        // Optimistically deduct credit locally & add scan to list
        setCredits(prev => Math.max(0, prev - 1));
        setScans(prev => [data.scan, ...prev]);

        // Open scanning terminal screen
        setSelectedScanId(data.scan.id);
        setCurrentView('progress');

        // Refresh full state background metrics in parallel
        setTimeout(() => loadUserContext(), 1000);
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
      const res = await api.generateKey();
      if (res.ok) {
        // Reload keys listing
        loadUserContext();
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
      const res = await api.revokeKey(keyId);
      if (res.ok) {
        // Reload keys listing
        loadUserContext();
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
      const res = await api.checkout(packName);
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.url) {
        // Redirect to Stripe's hosted checkout. Credits are granted by the
        // webhook after payment; we return to /dashboard?checkout_success=true.
        window.location.href = data.url;
        return;
      }
      alert(data.message || 'Checkout is currently unavailable. Please try again later.');
    } catch (err) {
      console.error('Purchase transactions failed:', err);
      alert('Could not start checkout. Please try again.');
    } finally {
      setIsPerformingAction(false);
    }
  };

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch {}
    setUser(null);
    setScans([]);
    setApiKeys([]);
    setCredits(0);
    setCurrentView('landing');
  };

  // Find active scan we are polling/viewing
  const activeScan = scans.find(s => s.id === selectedScanId);

  return {
    user, scans, apiKeys, credits, transactions,
    currentView, selectedScanId, showLogin, isPerformingAction, activeScan,
    setCurrentView, setSelectedScanId, setShowLogin,
    loadUserContext, handleNavigate, handleStartTrial,
    onInitiateScan, onGenerateKey, onRevokeKey, onPurchaseCredits, handleLogout,
  };
}
