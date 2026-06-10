import { useState, useEffect } from 'react';
import { User, Scan, ApiKey } from '../types.js';

/**
 * Owns the authenticated user's data state (profile, scans, keys, credits,
 * transactions) and every server call that mutates it. Navigation state stays
 * in App; actions return enough information for the caller to route.
 */
export function useAppData() {
  const [user, setUser] = useState<User | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [credits, setCredits] = useState(0);
  const [transactions, setTransactions] = useState<any[]>([]);
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

  /** Launch a scan; returns the created scan so the caller can route to it. */
  const initiateScan = async (url: string, authHeader?: string): Promise<Scan | null> => {
    if (!user) return null;

    setIsPerformingAction(true);
    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, userId: user.id, authHeader })
      });

      if (res.ok) {
        const data = await res.json();
        // Optimistically deduct credit locally & add scan to list
        setCredits(prev => Math.max(0, prev - 1));
        setScans(prev => [data.scan, ...prev]);

        // Refresh full state background metrics in parallel
        setTimeout(() => loadUserContext(user.id), 1000);

        return data.scan;
      } else {
        const errData = await res.json();
        alert(errData.message || 'Scanning initiation failed');
      }
    } catch (err) {
      console.error('Core scan launch err:', err);
    } finally {
      setIsPerformingAction(false);
    }
    return null;
  };

  const generateKey = async () => {
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

  const revokeKey = async (keyId: string) => {
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

  const purchaseCredits = async (packName: 'single' | 'pack5' | 'pack20') => {
    if (!user) return;
    setIsPerformingAction(true);
    try {
      const res = await fetch('/api/credits/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: user.id, pack: packName })
      });
      if (res.ok) {
        await res.json();
        // Immediately reload user credentials containing topped-up values
        await loadUserContext(user.id);
      }
    } catch (err) {
      console.error('Purchase transactions failed:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  /** Sign in by email; returns the user so the caller can route to the dashboard. */
  const login = async (email: string): Promise<User | null> => {
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
        return data.user;
      }
    } catch (err) {
      console.error('Sign-in synchronization failure:', err);
    } finally {
      setIsPerformingAction(false);
    }
    return null;
  };

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch {}
    setUser(null);
    setScans([]);
    setApiKeys([]);
    setCredits(0);
  };

  return {
    user, scans, apiKeys, credits, transactions, isPerformingAction,
    loadUserContext, initiateScan, generateKey, revokeKey, purchaseCredits, login, logout,
  };
}
