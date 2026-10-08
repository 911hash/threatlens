import React, { forwardRef } from 'react';
import { ChevronDown } from 'lucide-react';

export type SelectSize = 'sm' | 'md';

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'size'> {
  options: SelectOption[];
  size?: SelectSize;
  label?: string;
  error?: string | boolean;
  helperText?: string;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  (
    {
      options,
      size = 'sm',
      label,
      error,
      helperText,
      disabled,
      className = '',
      id,
      ...props
    },
    ref
  ) => {
    const selectId = id || (label ? `select-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);
    const hasError = Boolean(error);
    const errorMessage = typeof error === 'string' ? error : undefined;

    const sizeStyles: Record<SelectSize, string> = {
      sm: 'h-8 text-xs pl-2.5 pr-8',
      md: 'h-9 text-sm pl-3 pr-9',
    };

    return (
      <div className="w-full flex flex-col gap-1">
        {label && (
          <label htmlFor={selectId} className="text-xs font-medium text-[var(--text-secondary)] select-none">
            {label}
          </label>
        )}
        <div className="relative flex items-center w-full">
          <select
            ref={ref}
            id={selectId}
            disabled={disabled}
            className={`w-full appearance-none rounded border bg-[var(--bg-inset)] text-[var(--text-primary)] transition-colors focus:bg-[var(--bg-panel)] focus:outline-none focus:ring-1 ${
              hasError
                ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
                : 'border-[var(--border-subtle)] focus:border-blue-500 focus:ring-blue-500'
            } ${sizeStyles[size]} disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer ${className}`}
            {...props}
          >
            {options.map(opt => (
              <option key={opt.value} value={opt.value} disabled={opt.disabled} className="bg-[var(--bg-panel)] text-[var(--text-primary)]">
                {opt.label}
              </option>
            ))}
          </select>
          <div className="absolute right-2.5 pointer-events-none text-[var(--text-tertiary)] flex items-center">
            <ChevronDown className="w-3.5 h-3.5" />
          </div>
        </div>
        {(errorMessage || helperText) && (
          <span className={`text-[11px] leading-tight ${hasError ? 'text-red-500' : 'text-[var(--text-tertiary)]'}`}>
            {errorMessage || helperText}
          </span>
        )}
      </div>
    );
  }
);

Select.displayName = 'Select';
