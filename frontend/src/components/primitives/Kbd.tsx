import React from 'react';

export interface KbdProps {
  children: React.ReactNode;
  size?: 'xs' | 'sm';
  className?: string;
}

export const Kbd: React.FC<KbdProps> = ({ children, size = 'xs', className = '' }) => {
  const sizeStyles = {
    xs: 'min-w-[18px] h-4.5 px-1 text-[10px]',
    sm: 'min-w-[22px] h-5 px-1.5 text-xs',
  }[size];

  return (
    <kbd
      className={`inline-flex items-center justify-center font-mono font-medium rounded border border-[var(--border-strong)] bg-[var(--bg-inset)] text-[var(--text-secondary)] shadow-xs select-none ${sizeStyles} ${className}`}
    >
      {children}
    </kbd>
  );
};
