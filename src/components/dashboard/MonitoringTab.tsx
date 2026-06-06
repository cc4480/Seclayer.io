import React, { useState, useEffect } from 'react';
import { Clock, Globe, Plus, RefreshCw } from 'lucide-react';
import { apiFetch } from '../../lib/api.js';

interface MonitoredTarget {
  id: string;
  url: string;
  frequencyDays: number;
  scheduleString?: string;
  nextScanAt?: string;
}

interface MonitoringTabProps {
  userId: string;
}

export default function MonitoringTab({ userId }: MonitoringTabProps) {
  const [monitoredTargets, setMonitoredTargets] = useState<MonitoredTarget[]>([]);
  const [monitorUrl, setMonitorUrl] = useState('');
  const [monitorFreq, setMonitorFreq] = useState(7);
  const [monitorDay, setMonitorDay] = useState('Monday');
  const [monitorTime, setMonitorTime] = useState('09:00');
  const [isAddingMonitor, setIsAddingMonitor] = useState(false);

  const fetchMonitoredTargets = async () => {
    try {
      const res = await apiFetch('/api/monitoring');
      if (res.ok) setMonitoredTargets((await res.json()).monitoredTargets || []);
    } catch (err) {
      console.error('Error loading monitoring targets:', err);
    }
  };

  useEffect(() => {
    fetchMonitoredTargets();
  }, [userId]);

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
      const res = await apiFetch('/api/monitoring', {
        method: 'POST',
        body: JSON.stringify({ url: monitorUrl, frequencyDays: monitorFreq, scheduleString }),
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
      const res = await apiFetch(`/api/monitoring/${id}`, { method: 'DELETE' });
      if (res.ok) fetchMonitoredTargets();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6 text-xs font-mono">
      <div className="bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5">
        <Clock className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5" />
        <div className="space-y-1">
          <h4 className="text-white text-xs uppercase font-bold">Continuous Security Monitoring</h4>
          <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
            Set up automated, recurring scans for your critical infrastructure. Monitoring tasks run on schedule against your registered targets.
          </p>
        </div>
      </div>

      <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5">
        <h3 className="text-sm font-bold font-mono text-white mb-4">Add Monitor Target</h3>
        <form onSubmit={handleAddMonitor} className="flex flex-col gap-3">
          <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
            <Globe className="w-4 h-4 text-[#52525b] mx-2" />
            <input
              type="text"
              className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
              placeholder="https://production.api.yoursite.com"
              value={monitorUrl}
              onChange={(e) => setMonitorUrl(e.target.value)}
              disabled={isAddingMonitor}
            />
          </div>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="w-full sm:w-auto bg-black border border-[#27272a] rounded p-1.5 flex items-center">
              <select
                value={monitorFreq}
                onChange={(e) => setMonitorFreq(Number(e.target.value))}
                className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 cursor-pointer"
                disabled={isAddingMonitor}
              >
                <option value={1} className="bg-black">Daily</option>
                <option value={7} className="bg-black">Weekly</option>
                <option value={30} className="bg-black">Monthly</option>
              </select>
            </div>

            {monitorFreq === 7 && (
              <div className="w-full sm:w-auto bg-black border border-[#27272a] rounded p-1.5 flex items-center">
                <select
                  value={monitorDay}
                  onChange={(e) => setMonitorDay(e.target.value)}
                  className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 cursor-pointer"
                  disabled={isAddingMonitor}
                >
                  {['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'].map(d => (
                    <option key={d} value={d} className="bg-black">{d}</option>
                  ))}
                </select>
              </div>
            )}

            <div className="w-full sm:w-auto bg-black border border-[#27272a] rounded p-1.5 flex items-center">
              <input
                type="time"
                value={monitorTime}
                onChange={(e) => setMonitorTime(e.target.value)}
                className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 cursor-pointer [color-scheme:dark]"
                disabled={isAddingMonitor}
              />
            </div>

            <button
              type="submit"
              disabled={isAddingMonitor || !monitorUrl.trim()}
              className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 shrink-0 cursor-pointer w-full sm:w-auto ml-auto"
            >
              {isAddingMonitor ? <RefreshCw className="w-4 h-4 animate-spin text-black" /> : <Plus className="w-4 h-4 text-black" />}
              <span>Add Monitor</span>
            </button>
          </div>
        </form>
      </div>

      <div className="space-y-3">
        {monitoredTargets.length === 0 ? (
          <div className="text-center py-8 bg-black rounded border border-[#27272a]">
            <span className="text-xs text-[#52525b] font-mono">No active monitoring targets configured</span>
          </div>
        ) : (
          monitoredTargets.map((target) => (
            <div key={target.id} className="p-4 bg-black border border-[#27272a] rounded flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1.5">
                <div className="flex items-center space-x-2">
                  <Globe className="w-4 h-4 text-[#52525b]" />
                  <span className="text-white font-bold uppercase text-xs">{target.url}</span>
                  <span className="bg-[#22c55e]/10 text-[#22c55e] text-[9px] px-2 py-0.5 rounded border border-[#22c55e]/30">ACTIVE</span>
                </div>
                <div className="text-[#a1a1aa] text-[10px] flex items-center space-x-3">
                  <span>Schedule: {target.scheduleString || `Every ${target.frequencyDays} ${target.frequencyDays === 1 ? 'day' : 'days'}`}</span>
                  <span>&bull;</span>
                  <span>Next scan: {target.nextScanAt ? new Date(target.nextScanAt).toLocaleDateString() : 'N/A'}</span>
                </div>
              </div>
              <button
                onClick={() => handleDeleteMonitor(target.id)}
                className="px-3 py-1.5 bg-[#18181b] border border-[#27272a] hover:bg-[#f87171] hover:text-white text-[#f87171] rounded text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer w-fit"
              >
                Remove
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
