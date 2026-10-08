import React from 'react';

export interface ProgressBarProps {
  value?: number; // 0 to 100, undefined for indeterminate
  max?: number;
  label?: string;
  valueFormatter?: (val: number) => string;
  variant?: 'default' | 'success' | 'warning' | 'danger';
  size?: 'xs' | 'sm' | 'md';
  className?: string;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  max = 100,
  label,
  valueFormatter,
  variant = 'default',
  size = 'sm',
  className = '',
}) => {
  const isIndeterminate = value === undefined;
  const percentage = isIndeterminate ? 0 : Math.max(0, Math.min(100, (value / max) * 100));

  const sizeStyles = {
    xs: 'h-1',
    sm: 'h-1.5',
    md: 'h-2.5',
  }[size];

  const variantStyles = {
    default: 'bg-blue-600',
    success: 'bg-emerald-500',
    warning: 'bg-amber-500',
    danger: 'bg-red-500',
  }[variant];

  return (
    <div className={`w-full flex flex-col gap-1 ${className}`}>
      {(label || (value !== undefined && valueFormatter)) && (
        <div className="flex items-center justify-between text-xs select-none">
          {label && <span className="text-[var(--text-secondary)] font-medium">{label}</span>}
          {value !== undefined && (
            <span className="font-mono text-xs text-[var(--text-primary)] tabular-nums">
              {valueFormatter ? valueFormatter(value) : `${Math.round(percentage)}%`}
            </span>
          )}
        </div>
      )}
      <div className={`w-full ${sizeStyles} rounded-full bg-[var(--border-subtle)] overflow-hidden relative`}>
        {isIndeterminate ? (
          <div className="absolute inset-y-0 w-1/3 bg-blue-500 rounded-full animate-dash" />
        ) : (
          <div
            className={`h-full ${variantStyles} rounded-full transition-all duration-300`}
            style={{ width: `${percentage}%` }}
          />
        )}
      </div>
    </div>
  );
};
