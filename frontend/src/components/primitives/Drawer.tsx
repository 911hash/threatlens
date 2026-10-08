import React, { useEffect } from 'react';
import { X } from 'lucide-react';
import { IconButton } from './IconButton';

export type DrawerSize = 'sm' | 'md' | 'lg' | 'xl';
export type DrawerSide = 'right' | 'left' | 'bottom';

export interface DrawerProps {
  isOpen: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  size?: DrawerSize;
  side?: DrawerSide;
  className?: string;
}

export const Drawer: React.FC<DrawerProps> = ({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  footer,
  size = 'md',
  side = 'right',
  className = '',
}) => {
  const drawerRef = React.useRef<HTMLDivElement>(null);
  const previouslyFocusedRef = React.useRef<HTMLElement | null>(null);

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
        onClose();
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

    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', handleKeyDown);

    return () => {
      clearTimeout(timer);
      document.body.style.overflow = '';
      window.removeEventListener('keydown', handleKeyDown);
      previouslyFocusedRef.current?.focus?.();
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const sizeStyles: Record<DrawerSize, string> = {
    sm: 'max-w-xs',
    md: 'max-w-md',
    lg: 'max-w-xl',
    xl: 'max-w-2xl',
  };

  const sideAnimation = {
    right: 'right-0 top-0 bottom-0 animate-in slide-in-from-right duration-200 border-l',
    left: 'left-0 top-0 bottom-0 animate-in slide-in-from-left duration-200 border-r',
    bottom: 'bottom-0 left-0 right-0 max-h-[85vh] animate-in slide-in-from-bottom duration-200 border-t',
  }[side];

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 overflow-hidden"
    >
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity animate-in fade-in duration-200"
        onClick={onClose}
      />

      {/* Drawer Surface */}
      <div
        ref={drawerRef}
        className={`fixed flex flex-col w-full bg-[var(--bg-elevated)] text-[var(--text-primary)] border-[var(--border-strong)] shadow-2xl ${
          side === 'bottom' ? '' : sizeStyles[size]
        } ${sideAnimation} ${className}`}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-4 py-3 shrink-0">
          <div className="flex flex-col gap-0.5 pr-4">
            {title && (
              <h2 className="text-sm font-semibold text-[var(--text-primary)] leading-tight">{title}</h2>
            )}
            {subtitle && (
              <p className="text-xs text-[var(--text-tertiary)]">{subtitle}</p>
            )}
          </div>
          <IconButton
            icon={<X className="w-4 h-4" />}
            aria-label="Close drawer"
            variant="tertiary"
            size="xs"
            onClick={onClose}
          />
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-4">{children}</div>

        {/* Footer */}
        {footer && (
          <div className="flex items-center justify-end gap-2 border-t border-[var(--border-subtle)] bg-[var(--bg-panel)] px-4 py-3 shrink-0">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};
