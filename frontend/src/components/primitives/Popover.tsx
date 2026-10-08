import React, { useState, useRef, useEffect } from 'react';

export type PopoverAlign = 'start' | 'end' | 'center';
export type PopoverSide = 'top' | 'bottom';

export interface PopoverProps {
  trigger: React.ReactNode;
  children: React.ReactNode | ((close: () => void) => React.ReactNode);
  align?: PopoverAlign;
  side?: PopoverSide;
  className?: string;
}

export const Popover: React.FC<PopoverProps> = ({
  trigger,
  children,
  align = 'start',
  side = 'bottom',
  className = '',
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const triggerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        setIsOpen(false);
        const focusable = triggerRef.current?.querySelector<HTMLElement>('button, a, input, [tabindex="0"]');
        if (focusable) {
          focusable.focus();
        } else {
          triggerRef.current?.focus();
        }
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleOutsideClick);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  const alignClasses = {
    start: 'left-0',
    end: 'right-0',
    center: 'left-1/2 -translate-x-1/2',
  }[align];

  const sideClasses = {
    top: 'bottom-full mb-1.5',
    bottom: 'top-full mt-1.5',
  }[side];

  return (
    <div className="relative inline-block" ref={containerRef}>
      <div
        ref={triggerRef}
        onClick={() => setIsOpen(!isOpen)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setIsOpen(!isOpen);
          }
        }}
        tabIndex={0}
        role="button"
        aria-haspopup="dialog"
        aria-expanded={isOpen}
        className="cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
      >
        {trigger}
      </div>
      {isOpen && (
        <div
          className={`absolute z-50 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-elevated)] p-3 shadow-xl animate-in fade-in zoom-in-95 ${
            alignClasses
          } ${sideClasses} ${className}`}
        >
          {typeof children === 'function' ? children(() => setIsOpen(false)) : children}
        </div>
      )}
    </div>
  );
};
