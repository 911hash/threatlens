import React from 'react';

export type BadgeVariant =
  | 'neutral'
  | 'info'
  | 'success'
  | 'warning'
  | 'danger'
  | 'outline'
  | 'demo'
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'clean';
export type BadgeSize = 'xs' | 'sm';

export interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  size?: BadgeSize;
  icon?: React.ReactNode;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  size = 'xs',
  icon,
  className = '',
}) => {
  const sizeStyles: Record<BadgeSize, string> = {
    xs: 'px-1.5 py-0.5 text-[10px] gap-1 leading-none font-semibold',
    sm: 'px-2 py-0.5 text-xs gap-1.5 leading-none font-semibold',
  };

  const variantStyles: Record<BadgeVariant, string> = {
    neutral:
      'bg-[var(--bg-inset)] text-[var(--text-secondary)] border border-[var(--border-subtle)]',
    info:
      'bg-sky-500/10 text-sky-500 border border-sky-500/30 dark:text-sky-400',
    success:
      'bg-emerald-500/10 text-emerald-600 border border-emerald-500/30 dark:text-emerald-400',
    warning:
      'bg-amber-500/10 text-amber-600 border border-amber-500/30 dark:text-amber-400',
    danger:
      'bg-red-500/10 text-red-600 border border-red-500/30 dark:text-red-400',
    outline:
      'bg-transparent text-[var(--text-primary)] border border-[var(--border-strong)]',
    demo:
      'bg-purple-500/10 text-purple-600 border border-purple-500/30 dark:text-purple-400 font-mono tracking-wider',
    critical:
      'bg-red-500/10 text-red-600 border border-red-500/30 dark:text-red-400',
    high:
      'bg-orange-500/10 text-orange-600 border border-orange-500/30 dark:text-orange-400',
    medium:
      'bg-amber-500/10 text-amber-600 border border-amber-500/30 dark:text-amber-400',
    low:
      'bg-sky-500/10 text-sky-600 border border-sky-500/30 dark:text-sky-400',
    clean:
      'bg-emerald-500/10 text-emerald-600 border border-emerald-500/30 dark:text-emerald-400',
  };

  return (
    <span
      className={`inline-flex items-center rounded select-none uppercase tracking-wider ${sizeStyles[size]
        } ${variantStyles[variant]} ${className}`}
    >
      {icon && <span className="shrink-0">{icon}</span>}
      <span>{children}</span>
    </span>
  );
};
