import { User, Scan, ApiKey } from '../types.js';
import { api } from './client.js';

export interface ContextSetters {
  setUser: (u: User | null) => void;
  setCredits: (n: number) => void;
  setScans: (s: Scan[]) => void;
  setApiKeys: (k: ApiKey[]) => void;
  setTransactions: (t: any[]) => void;
  setCurrentView: (v: 'landing' | 'dashboard' | 'progress' | 'report') => void;
  setIsPerformingAction: (b: boolean) => void;
}

// Restores the session and hydrates all dashboard state from the backend.
// Identity comes from the httpOnly session cookie, so no userId is passed from
// the client. Also handles the post-Stripe-Checkout return by routing to the
// dashboard and cleaning the query string.
export async function loadUserContext(s: ContextSetters): Promise<void> {
  s.setIsPerformingAction(true);
  try {
    // 1. Fetch user profile from the session cookie.
    const userRes = await api.me();
    if (userRes.ok) {
      const userData = await userRes.json();
      s.setUser(userData.user);
      s.setCredits(userData.user.credits);

      // 2. Fetch user's scans list
      const scansRes = await api.scans();
      if (scansRes.ok) {
        const scansData = await scansRes.json();
        s.setScans(scansData.scans);
      }

      // 3. Fetch user's developer keys
      const keysRes = await api.keys();
      if (keysRes.ok) {
        const keysData = await keysRes.json();
        s.setApiKeys(keysData.keys);
      }

      // 4. Fetch user credit transactions
      const creditsRes = await api.credits();
      if (creditsRes.ok) {
        const creditsData = await creditsRes.json();
        s.setTransactions(creditsData.transactions || []);
      }
    } else {
      // No valid session — present the app in a logged-out state.
      s.setUser(null);
      s.setScans([]);
      s.setApiKeys([]);
      s.setCredits(0);
    }

    // Handle return from Stripe Checkout: land on the dashboard and clean the
    // query string. Credits arrive via the webhook, reflected by this reload.
    const params = new URLSearchParams(window.location.search);
    if (params.has('checkout_success') || params.has('checkout_canceled')) {
      if (userRes.ok) s.setCurrentView('dashboard');
      window.history.replaceState({}, '', window.location.pathname);
    }
  } catch (err) {
    console.error('Error loading user dashboard metrics:', err);
  } finally {
    s.setIsPerformingAction(false);
  }
}
