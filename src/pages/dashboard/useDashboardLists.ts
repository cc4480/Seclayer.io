import { useState, useEffect } from 'react';
import { Scan } from '../../types.js';

/** Loads and refreshes the suppression rules and monitored targets lists. */
export function useDashboardLists(userId: string, scans: Scan[]) {
  const [suppressRules, setSuppressRules] = useState<any[]>([]);
  const [monitoredTargets, setMonitoredTargets] = useState<any[]>([]);

  const fetchSuppressRules = async () => {
    try {
      const res = await fetch(`/api/suppressions?userId=${userId || 'user_default'}`);
      if (res.ok) {
        const data = await res.json();
        setSuppressRules(data.suppressions || []);
      }
    } catch (err) {
      console.error('Error loading exclusion rules:', err);
    }
  };

  const fetchMonitoredTargets = async () => {
    try {
      const res = await fetch(`/api/monitoring?userId=${userId || 'user_default'}`);
      if (res.ok) {
        const data = await res.json();
        setMonitoredTargets(data.monitoredTargets || []);
      }
    } catch (err) {
      console.error('Error loading monitoring targets:', err);
    }
  };

  useEffect(() => {
    fetchSuppressRules();
    fetchMonitoredTargets();
  }, [userId, scans]);

  return { suppressRules, fetchSuppressRules, monitoredTargets, fetchMonitoredTargets };
}
