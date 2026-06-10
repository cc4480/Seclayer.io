import { useState } from 'react';

export type Notify = (msg: string, variant?: 'success' | 'error') => void;

/**
 * Shared POST-action pattern used by the orchestrator microservice panels:
 * tracks an in-flight flag and the JSON result, surfacing failures via toast.
 */
export function useApiAction<T = any>(notify: Notify) {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<T | null>(null);

  const run = async (url: string, body: any, errorMessage: string) => {
    setRunning(true);
    setResult(null);
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (res.ok) {
        setResult(data);
      } else {
        notify(data?.message || errorMessage, 'error');
      }
    } catch (err) {
      console.error(err);
      notify(errorMessage, 'error');
    } finally {
      setRunning(false);
    }
  };

  return { running, result, run };
}
