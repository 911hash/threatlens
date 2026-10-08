import React, { createContext, useContext, useCallback, useMemo, useRef } from 'react';
import { useLocalStorage } from '../hooks/useLocalStorage';

export interface DefangContextType {
  isDefanged: boolean;
  setDefanged: (defanged: boolean) => void;
  toggleDefanged: () => void;
  defang: (target: string) => string;
  refang: (target: string) => string;
  formatIndicator: (target: string) => string;
  copyIndicator: (target: string, options?: { live?: boolean; onCopy?: (isLive: boolean) => void }) => Promise<boolean>;
  onLiveCopy: (callback: () => void) => () => void;
}

const DefangContext = createContext<DefangContextType | undefined>(undefined);

export function defangIndicator(target: string): string {
  if (!target || typeof target !== 'string') return '';
  let res = target.trim();

  // If already defanged, avoid double bracket
  if (res.includes('[.]') || res.startsWith('hxxp')) {
    return res;
  }

  // Scheme defanging
  res = res.replace(/^https:\/\//i, 'hxxps://');
  res = res.replace(/^http:\/\//i, 'hxxp://');
  res = res.replace(/^ftp:\/\//i, 'fxp://');

  // Dot defanging in domain / IP / host
  if (res.startsWith('hxxp://') || res.startsWith('hxxps://')) {
    const schemePrefix = res.startsWith('hxxps://') ? 'hxxps://' : 'hxxp://';
    const rest = res.slice(schemePrefix.length);
    const slashIdx = rest.indexOf('/');
    if (slashIdx === -1) {
      res = schemePrefix + rest.replace(/\./g, '[.]');
    } else {
      const host = rest.slice(0, slashIdx);
      const path = rest.slice(slashIdx);
      res = schemePrefix + host.replace(/\./g, '[.]') + path;
    }
  } else {
    // Plain domain, IP, or email
    const slashIdx = res.indexOf('/');
    if (slashIdx === -1) {
      res = res.replace(/\./g, '[.]').replace(/@/g, '[@]');
    } else {
      const host = res.slice(0, slashIdx);
      const path = res.slice(slashIdx);
      res = host.replace(/\./g, '[.]').replace(/@/g, '[@]') + path;
    }
  }

  return res;
}

export function refangIndicator(target: string): string {
  if (!target || typeof target !== 'string') return '';
  let res = target.trim();
  res = res.replace(/^hxxps:\/\//i, 'https://');
  res = res.replace(/^hxxp:\/\//i, 'http://');
  res = res.replace(/^fxp:\/\//i, 'ftp://');
  res = res.replace(/\[\.\]/g, '.');
  res = res.replace(/\[@\]/g, '@');
  return res;
}

export const DefangProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isDefanged, setDefanged] = useLocalStorage<boolean>('threatlens_defang_pref', true);
  const liveCopyListenersRef = useRef<Set<() => void>>(new Set());

  const toggleDefanged = useCallback(() => {
    setDefanged(prev => !prev);
  }, [setDefanged]);

  const defang = useCallback((target: string) => {
    return defangIndicator(target);
  }, []);

  const refang = useCallback((target: string) => {
    return refangIndicator(target);
  }, []);

  const formatIndicator = useCallback(
    (target: string) => {
      if (!isDefanged) {
        return refangIndicator(target);
      }
      return defangIndicator(target);
    },
    [isDefanged]
  );

  const onLiveCopy = useCallback((callback: () => void) => {
    liveCopyListenersRef.current.add(callback);
    return () => {
      liveCopyListenersRef.current.delete(callback);
    };
  }, []);

  const copyIndicator = useCallback(
    async (target: string, options?: { live?: boolean; onCopy?: (isLive: boolean) => void }): Promise<boolean> => {
      const isLive = Boolean(options?.live);
      const textToCopy = isLive ? refangIndicator(target) : defangIndicator(target);

      try {
        let copied = false;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          try {
            await navigator.clipboard.writeText(textToCopy);
            copied = true;
          } catch {
            // Document might not be focused or clipboard permissions restricted; fallback below
          }
        }

        if (!copied) {
          const textarea = document.createElement('textarea');
          textarea.value = textToCopy;
          textarea.style.position = 'fixed';
          textarea.style.opacity = '0';
          document.body.appendChild(textarea);
          textarea.select();
          document.execCommand('copy');
          document.body.removeChild(textarea);
        }

        if (options?.onCopy) {
          options.onCopy(isLive);
        }

        if (isLive) {
          liveCopyListenersRef.current.forEach(listener => {
            try {
              listener();
            } catch (err) {
              if (import.meta.env.DEV) {
                console.error('Error in onLiveCopy listener:', err);
              }
            }
          });
        }

        return true;
      } catch (err) {
        if (import.meta.env.DEV) {
          console.error('Failed to copy indicator:', err);
        }
        return false;
      }
    },
    []
  );

  const value = useMemo(
    () => ({
      isDefanged,
      setDefanged,
      toggleDefanged,
      defang,
      refang,
      formatIndicator,
      copyIndicator,
      onLiveCopy,
    }),
    [isDefanged, setDefanged, toggleDefanged, defang, refang, formatIndicator, copyIndicator, onLiveCopy]
  );

  return <DefangContext.Provider value={value}>{children}</DefangContext.Provider>;
};

export function useDefang(): DefangContextType {
  const context = useContext(DefangContext);
  if (!context) {
    throw new Error('useDefang must be used within a DefangProvider');
  }
  return context;
}
