import { useState, useEffect, useRef, useCallback } from 'react';
import { api } from '../api/client';
import type { HealthStatus } from '../types/threat';

export type HealthDotStatus = 'healthy' | 'degraded' | 'offline' | 'checking';

export interface HealthState {
  status: HealthDotStatus;
  data: HealthStatus | null;
  error: Error | null;
  lastChecked: Date | null;
  checkNow: () => Promise<void>;
}

export function useHealth(enabled: boolean = true): HealthState {
  const [data, setData] = useState<HealthStatus | null>(null);
  const [status, setStatus] = useState<HealthDotStatus>('checking');
  const [error, setError] = useState<Error | null>(null);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const backoffDelayRef = useRef<number>(15000); // 15s normal
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isMountedRef = useRef<boolean>(true);

  const fetchHealth = useCallback(async () => {
    if (!enabled) return;

    try {
      const res = await api.getHealth();
      if (!isMountedRef.current) return;

      setData(res);
      setError(null);
      setLastChecked(new Date());

      // Check if degraded (some sources disabled or status not ok)
      if (res.status === 'ok') {
        const sources = res.configured_sources ? Object.values(res.configured_sources) : [];
        const allSourcesActive = sources.length > 0 && sources.every(Boolean);
        setStatus(allSourcesActive ? 'healthy' : 'degraded');
      } else {
        setStatus('degraded');
      }

      // Reset interval to default 15s on success
      backoffDelayRef.current = 15000;
    } catch (err: unknown) {
      if (!isMountedRef.current) return;
      const errObj = err instanceof Error ? err : new Error(String(err));
      setError(errObj);
      setStatus('offline');
      setLastChecked(new Date());

      // Exponential backoff up to 60s
      backoffDelayRef.current = Math.min(backoffDelayRef.current * 1.5, 60000);
    }
  }, [enabled]);

  const scheduleNext = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    if (!enabled) return;

    timerRef.current = setTimeout(async () => {
      await fetchHealth();
      scheduleNext();
    }, backoffDelayRef.current);
  }, [enabled, fetchHealth]);

  useEffect(() => {
    isMountedRef.current = true;
    fetchHealth().then(() => {
      scheduleNext();
    });

    return () => {
      isMountedRef.current = false;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [fetchHealth, scheduleNext]);

  return {
    status,
    data,
    error,
    lastChecked,
    checkNow: fetchHealth,
  };
}
