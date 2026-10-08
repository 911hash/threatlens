import { useEffect, useCallback } from 'react';

export interface ShortcutKeyConfig {
  key: string;
  ctrl?: boolean;
  meta?: boolean;
  shift?: boolean;
  alt?: boolean;
  mod?: boolean; // Matches ctrl on Windows/Linux, cmd on Mac
}

export type ShortcutDefinition = string | ShortcutKeyConfig;

export interface ShortcutOptions {
  enabled?: boolean;
  preventDefault?: boolean;
  stopPropagation?: boolean;
  target?: HTMLElement | Document | Window;
}

export function useKeyboardShortcut(
  shortcut: ShortcutDefinition,
  handler: (e: KeyboardEvent) => void,
  options: ShortcutOptions = {}
) {
  const { enabled = true, preventDefault = true, stopPropagation = false, target } = options;

  const matchesShortcut = useCallback(
    (e: KeyboardEvent): boolean => {
      const isMac = typeof navigator !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform);

      if (typeof shortcut === 'string') {
        const lowerDef = shortcut.toLowerCase();
        // Support syntax like 'mod+k', 'ctrl+k', 'shift+/', 'Escape'
        const parts = lowerDef.split('+').map(p => p.trim());
        const mainKey = parts[parts.length - 1];
        const wantsMod = parts.includes('mod');
        const wantsCtrl = parts.includes('ctrl');
        const wantsMeta = parts.includes('meta') || parts.includes('cmd');
        const wantsShift = parts.includes('shift');
        const wantsAlt = parts.includes('alt');

        const pressedKey = e.key.toLowerCase();
        if (pressedKey !== mainKey) {
          // Special case for '/' if shifted or standard
          if (mainKey === '?' && (pressedKey === '?' || (e.shiftKey && pressedKey === '/'))) {
            // matches
          } else {
            return false;
          }
        }

        if (wantsMod) {
          const modPressed = isMac ? e.metaKey : e.ctrlKey;
          if (!modPressed) return false;
        } else {
          if (wantsCtrl && !e.ctrlKey) return false;
          if (wantsMeta && !e.metaKey) return false;
        }

        if (wantsShift && !e.shiftKey) return false;
        if (wantsAlt && !e.altKey) return false;

        return true;
      }

      // Object config
      if (e.key.toLowerCase() !== shortcut.key.toLowerCase()) return false;

      if (shortcut.mod) {
        const modPressed = isMac ? e.metaKey : e.ctrlKey;
        if (!modPressed) return false;
      }
      if (shortcut.ctrl !== undefined && e.ctrlKey !== shortcut.ctrl) return false;
      if (shortcut.meta !== undefined && e.metaKey !== shortcut.meta) return false;
      if (shortcut.shift !== undefined && e.shiftKey !== shortcut.shift) return false;
      if (shortcut.alt !== undefined && e.altKey !== shortcut.alt) return false;

      return true;
    },
    [shortcut]
  );

  useEffect(() => {
    if (!enabled || typeof window === 'undefined') return;

    const eventListener = (e: KeyboardEvent) => {
      // Don't trigger standard single-character shortcuts if focused inside input/textarea/select/contentEditable
      // Unless modifier like mod/ctrl/meta is held
      const activeEl = document.activeElement;
      const isInput =
        activeEl &&
        (activeEl.tagName === 'INPUT' ||
          activeEl.tagName === 'TEXTAREA' ||
          activeEl.tagName === 'SELECT' ||
          (activeEl as HTMLElement).isContentEditable);

      const isSingleKey = typeof shortcut === 'string' && !shortcut.includes('+') && !['escape', 'tab', 'enter'].includes(shortcut.toLowerCase());
      if (isInput && isSingleKey) {
        return;
      }

      if (matchesShortcut(e)) {
        if (preventDefault) e.preventDefault();
        if (stopPropagation) e.stopPropagation();
        handler(e);
      }
    };

    const targetElement = target || window;
    targetElement.addEventListener('keydown', eventListener as EventListener);

    return () => {
      targetElement.removeEventListener('keydown', eventListener as EventListener);
    };
  }, [enabled, matchesShortcut, preventDefault, stopPropagation, handler, target, shortcut]);
}
