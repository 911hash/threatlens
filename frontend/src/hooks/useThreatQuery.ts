import { useState, useEffect, useRef, useCallback } from 'react';

export type QueryStatus = 'idle' | 'loading' | 'success' | 'error';

export interface ThreatQueryOptions<T> {
  staleMs?: number; // Time in ms before cache entry is considered stale. Default: 30000 (30s)
  revalidateOnFocus?: boolean; // Whether to refetch on window focus. Default: true
  enabled?: boolean; // Whether query is enabled. Default: true
  initialData?: T;
  onSuccess?: (data: T) => void;
  onError?: (err: Error) => void;
}

export interface ThreatQueryResult<T> {
  data: T | undefined;
  error: Error | null;
  status: QueryStatus;
  isLoading: boolean;
  isRefetching: boolean;
  isSuccess: boolean;
  isError: boolean;
  refetch: () => Promise<T | undefined>;
  setData: (updater: T | ((prev: T | undefined) => T)) => void;
}

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

// Global in-memory cache and in-flight promise map
const memoryCache = new Map<string, CacheEntry<unknown>>();
const inFlightRequests = new Map<string, Promise<unknown>>();

export function useThreatQuery<T>(
  queryKey: string | null | undefined,
  queryFn: (signal?: AbortSignal) => Promise<T>,
  options: ThreatQueryOptions<T> = {}
): ThreatQueryResult<T> {
  const {
    staleMs = 30000,
    revalidateOnFocus = true,
    enabled = true,
    initialData,
    onSuccess,
    onError,
  } = options;

  const key = queryKey || '';

  // Initialize data from cache if present
  const initialCache = key ? (memoryCache.get(key) as CacheEntry<T> | undefined) : undefined;
  const [data, setDataState] = useState<T | undefined>(() => initialCache?.data ?? initialData);
  const [error, setError] = useState<Error | null>(null);
  const [status, setStatus] = useState<QueryStatus>(() => {
    if (!enabled || !key) return 'idle';
    if (initialCache) return 'success';
    return 'loading';
  });
  const [isRefetching, setIsRefetching] = useState<boolean>(false);

  const abortControllerRef = useRef<AbortController | null>(null);
  const isMountedRef = useRef<boolean>(true);
  const queryFnRef = useRef(queryFn);
  queryFnRef.current = queryFn;

  const executeFetch = useCallback(
    async (isBackground: boolean = false): Promise<T | undefined> => {
      if (!key || !enabled) return undefined;

      // Abort previous in-flight request for this component
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      const abortController = new AbortController();
      abortControllerRef.current = abortController;

      if (!isBackground) {
        setStatus('loading');
      } else {
        setIsRefetching(true);
      }
      setError(null);

      try {
        // Check if an identical request is already in-flight across the app
        let promise = inFlightRequests.get(key) as Promise<T> | undefined;

        if (!promise) {
          promise = queryFnRef.current(abortController.signal).finally(() => {
            inFlightRequests.delete(key);
          });
          inFlightRequests.set(key, promise);
        }

        const result = await promise;

        if (!isMountedRef.current || abortController.signal.aborted) {
          return undefined;
        }

        // Cache the successful result
        memoryCache.set(key, {
          data: result,
          timestamp: Date.now(),
        });

        setDataState(result);
        setStatus('success');
        setIsRefetching(false);
        onSuccess?.(result);
        return result;
      } catch (err: unknown) {
        if (!isMountedRef.current || abortController.signal.aborted) {
          return undefined;
        }

        const errorObj = err instanceof Error ? err : new Error(String(err));
        setError(errorObj);
        setStatus('error');
        setIsRefetching(false);
        onError?.(errorObj);
        return undefined;
      }
    },
    [key, enabled, onSuccess, onError]
  );

  const refetch = useCallback(() => {
    return executeFetch(data !== undefined);
  }, [executeFetch, data]);

  const setData = useCallback(
    (updater: T | ((prev: T | undefined) => T)) => {
      setDataState(prev => {
        const next = typeof updater === 'function' ? (updater as (prev: T | undefined) => T)(prev) : updater;
        if (key) {
          memoryCache.set(key, {
            data: next,
            timestamp: Date.now(),
          });
        }
        return next;
      });
    },
    [key]
  );

  // Main fetch effect
  useEffect(() => {
    isMountedRef.current = true;

    if (!enabled || !key) {
      setStatus('idle');
      return;
    }

    const cached = memoryCache.get(key) as CacheEntry<T> | undefined;
    const isStale = !cached || Date.now() - cached.timestamp > staleMs;

    if (cached) {
      setDataState(cached.data);
      setStatus('success');
      if (isStale) {
        // Stale-while-revalidate background refresh
        executeFetch(true);
      }
    } else {
      executeFetch(false);
    }

    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [key, enabled, staleMs, executeFetch]);

  // Window focus revalidation
  useEffect(() => {
    if (!revalidateOnFocus || !enabled || !key) return;

    const handleFocus = () => {
      const cached = memoryCache.get(key) as CacheEntry<T> | undefined;
      const isStale = !cached || Date.now() - cached.timestamp > staleMs;
      if (isStale) {
        executeFetch(true);
      }
    };

    window.addEventListener('focus', handleFocus);
    return () => {
      window.removeEventListener('focus', handleFocus);
    };
  }, [revalidateOnFocus, enabled, key, staleMs, executeFetch]);

  useEffect(() => {
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  return {
    data,
    error,
    status,
    isLoading: status === 'loading',
    isRefetching,
    isSuccess: status === 'success',
    isError: status === 'error',
    refetch,
    setData,
  };
}
