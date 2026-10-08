import React, { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { useDrawer } from '../../context/DrawerContext';
import { IconButton } from '../primitives/IconButton';

export const DetailDrawer: React.FC = () => {
  const { isOpen, content, options, close } = useDrawer();
  const drawerRef = useRef<HTMLDivElement>(null);
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!isOpen) return;

    previouslyFocusedRef.current = document.activeElement as HTMLElement;

    const getFocusables = () => {
      if (!drawerRef.current) return [];
      return Array.from(
        drawerRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        )
      ).filter(el => !el.hasAttribute('disabled') && el.offsetParent !== null);
    };

    const timer = setTimeout(() => {
      const focusables = getFocusables();
      if (focusables.length > 0) {
        focusables[0].focus();
      }
    }, 50);

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        close();
        return;
      }

      if (e.key === 'Tab') {
        const focusables = getFocusables();
        if (focusables.length === 0) return;

        const first = focusables[0];
        const last = focusables[focusables.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);

    return () => {
      clearTimeout(timer);
      window.removeEventListener('keydown', handleKeyDown);
      previouslyFocusedRef.current?.focus?.();
    };
  }, [isOpen, close]);

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={typeof options.title === 'string' ? options.title : 'Detail Drawer'}
      className="fixed inset-0 z-50 overflow-hidden"
    >
      {/* Non-blocking / click-outside dismissal backdrop */}
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity animate-in fade-in duration-150"
        onClick={close}
        aria-hidden="true"
      />

      {/* Drawer Surface: 400px on desktop, full width minus 24px on mobile */}
      <div
        ref={drawerRef}
        className="fixed right-0 top-0 bottom-0 w-[calc(100vw-24px)] sm:w-[400px] flex flex-col bg-[var(--bg-elevated)] text-[var(--text-primary)] border-l border-[var(--border-strong)] shadow-2xl z-50 animate-in slide-in-from-right duration-200"
      >
        {/* Header with Title, Optional Full-Page Action, and Close Button */}
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-4 py-3 shrink-0 bg-[var(--bg-panel)]">
          <div className="flex items-center gap-2 truncate pr-2">
            {options.title ? (
              <div className="text-sm font-semibold text-[var(--text-primary)] truncate">
                {options.title}
              </div>
            ) : (
              <span className="text-sm font-semibold text-[var(--text-primary)]">Details</span>
            )}
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {options.fullPageAction}
            <IconButton
              icon={<X className="w-4 h-4" />}
              aria-label="Close details drawer"
              variant="tertiary"
              size="xs"
              onClick={close}
            />
          </div>
        </div>

        {/* Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 overscroll-contain">
          {content}
        </div>
      </div>
    </div>
  );
};
