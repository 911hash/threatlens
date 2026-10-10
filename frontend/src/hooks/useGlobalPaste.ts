import { useEffect } from 'react';

export interface PastedTarget {
  target: string;
  type: 'url' | 'hash' | 'email' | 'text';
}

export function detectIndicatorType(text: string): 'url' | 'hash' | 'email' | 'text' {
  const clean = text.trim();
  // Hash detection (MD5 32 hex, SHA1 40 hex, SHA256 64 hex)
  if (/^[a-fA-F0-9]{32}$/.test(clean) || /^[a-fA-F0-9]{40}$/.test(clean) || /^[a-fA-F0-9]{64}$/.test(clean)) {
    return 'hash';
  }
  // Email detection
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean) || clean.startsWith('mailto:')) {
    return 'email';
  }
  // URL detection (http, https, hxxp, domain pattern)
  if (
    clean.startsWith('http://') ||
    clean.startsWith('https://') ||
    clean.startsWith('hxxp://') ||
    clean.startsWith('hxxps://') ||
    clean.includes('[.]') ||
    /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$/.test(clean)
  ) {
    return 'url';
  }
  return 'text';
}

export function useGlobalPaste(onPaste: (data: PastedTarget) => void, enabled: boolean = true) {
  useEffect(() => {
    if (!enabled || typeof window === 'undefined') return;

    const handlePaste = (e: ClipboardEvent) => {
      // If active element is an input or textarea, let default typing behavior occur
      const activeEl = document.activeElement;
      if (
        activeEl &&
        (activeEl.tagName === 'INPUT' ||
          activeEl.tagName === 'TEXTAREA' ||
          (activeEl as HTMLElement).isContentEditable)
      ) {
        return;
      }

      const text = e.clipboardData?.getData('text');
      if (!text || !text.trim()) return;

      const trimmed = text.trim();
      const detectedType = detectIndicatorType(trimmed);

      // Only trigger if recognized as url or hash or email
      if (detectedType === 'url' || detectedType === 'hash' || detectedType === 'email') {
        e.preventDefault();
        onPaste({
          target: trimmed,
          type: detectedType,
        });
      }
    };

    window.addEventListener('paste', handlePaste);
    return () => {
      window.removeEventListener('paste', handlePaste);
    };
  }, [enabled, onPaste]);
}
