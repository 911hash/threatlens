import { useState, useEffect, useCallback } from 'react';

export function useLocalStorage<T>(key: string, initialValue: T): [T, (value: T | ((prev: T) => T)) => void] {
  // Get initial value from localStorage or fallback
  const readValue = useCallback((): T => {
    if (typeof window === 'undefined') {
      return initialValue;
    }

    try {
      const item = window.localStorage.getItem(key);
      return item ? (JSON.parse(item) as T) : initialValue;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.warn(`[useLocalStorage] Error reading key "${key}":`, error);
      }
      return initialValue;
    }
  }, [key, initialValue]);

  const [storedValue, setStoredValue] = useState<T>(readValue);

  const setValue = useCallback(
    (value: T | ((prev: T) => T)) => {
      try {
        setStoredValue(prev => {
          const nextValue = value instanceof Function ? value(prev) : value;
          if (typeof window !== 'undefined') {
            window.localStorage.setItem(key, JSON.stringify(nextValue));
            window.dispatchEvent(new CustomEvent('local-storage-update', { detail: { key, nextValue } }));
          }
          return nextValue;
        });
      } catch (error) {
        if (import.meta.env.DEV) {
          console.warn(`[useLocalStorage] Error setting key "${key}":`, error);
        }
      }
    },
    [key]
  );

  useEffect(() => {
    setStoredValue(readValue());

    const handleStorageChange = (e: StorageEvent | CustomEvent) => {
      if ('key' in e && e.key && e.key !== key) {
        return;
      }
      if ('detail' in e && e.detail && e.detail.key !== key) {
        return;
      }
      setStoredValue(readValue());
    };

    window.addEventListener('storage', handleStorageChange as EventListener);
    window.addEventListener('local-storage-update', handleStorageChange as EventListener);

    return () => {
      window.removeEventListener('storage', handleStorageChange as EventListener);
      window.removeEventListener('local-storage-update', handleStorageChange as EventListener);
    };
  }, [key, readValue]);

  return [storedValue, setValue];
}
