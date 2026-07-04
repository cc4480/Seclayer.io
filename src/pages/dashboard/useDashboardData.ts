import React, { useState, useEffect } from 'react';
import { Scan, User } from '../../types.js';

// Owns the dashboard's server-backed panels: suppression rules, monitored
// targets (plus the add-target form fields), and the alert webhook. Fetches on
// mount and whenever the user or their scans change.
export function useDashboardData(user: User, scans: Scan[]) {
  const [suppressRules, setSuppressRules] = useState<any[]>([]);
  const [isDeletingRule, setIsDeletingRule] = useState<string | null>(null);

  const [monitoredTargets, setMonitoredTargets] = useState<any[]>([]);
  const [monitorUrl, setMonitorUrl] = useState('');
  const [monitorFreq, setMonitorFreq] = useState(7);
  const [monitorDay, setMonitorDay] = useState('Monday');
  const [monitorTime, setMonitorTime] = useState('09:00');
  const [isAddingMonitor, setIsAddingMonitor] = useState(false);

  const [webhookUrl, setWebhookUrl] = useState(user.notifyWebhook || '');
  const [webhookSaving, setWebhookSaving] = useState(false);
  const [webhookSaved, setWebhookSaved] = useState(false);

  const fetchSuppressRules = async () => {
    try {
      const res = await fetch(`/api/suppressions`);
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
      const res = await fetch(`/api/monitoring`);
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
  }, [user.id, scans]);

  const saveWebhook = async () => {
    setWebhookSaving(true);
    setWebhookSaved(false);
    try {
      const res = await fetch('/api/user/webhook', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: webhookUrl.trim() })
      });
      if (res.ok) {
        setWebhookSaved(true);
        setTimeout(() => setWebhookSaved(false), 2500);
      }
    } catch (err) {
      console.error('Error saving webhook:', err);
    } finally {
      setWebhookSaving(false);
    }
  };

  const handleAddMonitor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!monitorUrl.trim()) return;
    setIsAddingMonitor(true);

    let scheduleString = `Every day at ${monitorTime}`;
    if (monitorFreq === 7) {
      scheduleString = `Every ${monitorDay} at ${monitorTime}`;
    } else if (monitorFreq === 30) {
      scheduleString = `Monthly on the 1st at ${monitorTime}`;
    }

    try {
      const res = await fetch('/api/monitoring', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: monitorUrl, frequencyDays: monitorFreq, scheduleString })
      });
      if (res.ok) {
        setMonitorUrl('');
        fetchMonitoredTargets();
      }
    } finally {
      setIsAddingMonitor(false);
    }
  };

  const handleDeleteMonitor = async (id: string) => {
    try {
      const res = await fetch(`/api/monitoring/${id}`, { method: 'DELETE' });
      if (res.ok) {
        fetchMonitoredTargets();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleRevokeSuppression = async (ruleId: string) => {
    setIsDeletingRule(ruleId);
    try {
      const delRes = await fetch(`/api/suppressions/${ruleId}`, { method: 'DELETE' });
      if (delRes.ok) {
        fetchSuppressRules();
      }
    } catch (err) {
      console.error('Failed to revoke suppression:', err);
    } finally {
      setIsDeletingRule(null);
    }
  };

  return {
    suppressRules, isDeletingRule, handleRevokeSuppression,
    monitoredTargets, handleDeleteMonitor,
    monitorUrl, setMonitorUrl, monitorFreq, setMonitorFreq,
    monitorDay, setMonitorDay, monitorTime, setMonitorTime,
    isAddingMonitor, handleAddMonitor,
    webhookUrl, setWebhookUrl, webhookSaving, webhookSaved, saveWebhook,
  };
}

export type DashboardData = ReturnType<typeof useDashboardData>;
