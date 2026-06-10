import React, { useState } from 'react';

/**
 * Add-monitor form state and handlers. Lifted to the Dashboard level so the
 * form keeps its values when the user switches tabs, as it did pre-split.
 */
export function useMonitorForm(userId: string, refreshTargets: () => void) {
  const [monitorUrl, setMonitorUrl] = useState('');
  const [monitorFreq, setMonitorFreq] = useState(7);
  const [monitorDay, setMonitorDay] = useState('Monday');
  const [monitorTime, setMonitorTime] = useState('09:00');
  const [isAddingMonitor, setIsAddingMonitor] = useState(false);

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
        body: JSON.stringify({ url: monitorUrl, frequencyDays: monitorFreq, scheduleString, userId })
      });
      if (res.ok) {
        setMonitorUrl('');
        refreshTargets();
      }
    } finally {
      setIsAddingMonitor(false);
    }
  };

  const handleDeleteMonitor = async (id: string) => {
    try {
      const res = await fetch(`/api/monitoring/${id}?userId=${userId || 'user_default'}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        refreshTargets();
      }
    } catch (err) {
      console.error(err);
    }
  };

  return {
    monitorUrl, setMonitorUrl,
    monitorFreq, setMonitorFreq,
    monitorDay, setMonitorDay,
    monitorTime, setMonitorTime,
    isAddingMonitor,
    handleAddMonitor,
    handleDeleteMonitor,
  };
}

export type MonitorFormState = ReturnType<typeof useMonitorForm>;
