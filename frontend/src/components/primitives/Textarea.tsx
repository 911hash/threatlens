import React, { forwardRef } from 'react';

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  error?: string | boolean;
  isMono?: boolean;
  label?: string;
  helperText?: string;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  (
    {
      error,
      isMono = false,
      label,
      helperText,
      disabled,
      className = '',
      id,
      rows = 4,
      ...props
    },
    ref
  ) => {
    const textareaId = id || (label ? `textarea-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);
    const hasError = Boolean(error);
    const errorMessage = typeof error === 'string' ? error : undefined;

    return (
      <div className="w-full flex flex-col gap-1">
        {label && (
          <label htmlFor={textareaId} className="text-xs font-medium text-[var(--text-secondary)] select-none">
            {label}
          </label>
        )}
        <textarea
          ref={ref}
          id={textareaId}
          rows={rows}
          disabled={disabled}
          className={`w-full p-2.5 rounded border text-xs bg-[var(--bg-inset)] text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] transition-colors focus:bg-[var(--bg-panel)] focus:outline-none focus:ring-1 ${
            hasError
              ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
              : 'border-[var(--border-subtle)] focus:border-blue-500 focus:ring-blue-500'
          } ${isMono ? 'font-mono' : 'font-sans'} disabled:opacity-50 disabled:cursor-not-allowed resize-y ${className}`}
          {...props}
        />
        {(errorMessage || helperText) && (
          <span className={`text-[11px] leading-tight ${hasError ? 'text-red-500' : 'text-[var(--text-tertiary)]'}`}>
            {errorMessage || helperText}
          </span>
        )}
      </div>
    );
  }
);

Textarea.displayName = 'Textarea';
