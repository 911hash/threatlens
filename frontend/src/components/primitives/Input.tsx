import React, { forwardRef } from 'react';

export type InputSize = 'sm' | 'md';

export interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'> {
  size?: InputSize;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  error?: string | boolean;
  isMono?: boolean;
  label?: string;
  helperText?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      size = 'sm',
      leftIcon,
      rightIcon,
      error,
      isMono = false,
      label,
      helperText,
      disabled,
      className = '',
      id,
      ...props
    },
    ref
  ) => {
    const inputId = id || (label ? `input-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);
    const hasError = Boolean(error);
    const errorMessage = typeof error === 'string' ? error : undefined;

    const sizeStyles: Record<InputSize, string> = {
      sm: 'h-8 text-xs px-2.5',
      md: 'h-9 text-sm px-3',
    };

    const paddingLeft = leftIcon ? (size === 'sm' ? 'pl-8' : 'pl-9') : '';
    const paddingRight = rightIcon ? (size === 'sm' ? 'pr-8' : 'pr-9') : '';

    return (
      <div className="w-full flex flex-col gap-1">
        {label && (
          <label htmlFor={inputId} className="text-xs font-medium text-[var(--text-secondary)] select-none">
            {label}
          </label>
        )}
        <div className="relative flex items-center w-full">
          {leftIcon && (
            <div className="absolute left-2.5 flex items-center pointer-events-none text-[var(--text-tertiary)]">
              {leftIcon}
            </div>
          )}
          <input
            ref={ref}
            id={inputId}
            disabled={disabled}
            className={`w-full rounded border bg-[var(--bg-inset)] text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] transition-colors focus:bg-[var(--bg-panel)] focus:outline-none focus:ring-1 ${
              hasError
                ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
                : 'border-[var(--border-subtle)] focus:border-blue-500 focus:ring-blue-500'
            } ${isMono ? 'font-mono' : 'font-sans'} ${sizeStyles[size]} ${paddingLeft} ${paddingRight} disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
            {...props}
          />
          {rightIcon && (
            <div className="absolute right-2.5 flex items-center text-[var(--text-tertiary)]">
              {rightIcon}
            </div>
          )}
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

Input.displayName = 'Input';
