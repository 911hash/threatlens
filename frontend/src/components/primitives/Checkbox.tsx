import React, { forwardRef, useEffect, useRef } from 'react';
import { Check, Minus } from 'lucide-react';

export interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: React.ReactNode;
  description?: React.ReactNode;
  indeterminate?: boolean;
}

export const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>(
  ({ label, description, indeterminate = false, checked = false, disabled, className = '', id, ...props }, ref) => {
    const internalRef = useRef<HTMLInputElement>(null);
    const combinedRef = (ref || internalRef) as React.MutableRefObject<HTMLInputElement>;
    const checkboxId = id || (typeof label === 'string' ? `checkbox-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);

    useEffect(() => {
      if (combinedRef.current) {
        combinedRef.current.indeterminate = indeterminate;
      }
    }, [indeterminate, combinedRef]);

    return (
      <label
        htmlFor={checkboxId}
        className={`inline-flex items-start gap-2.5 cursor-pointer select-none group ${
          disabled ? 'opacity-50 cursor-not-allowed' : ''
        } ${className}`}
      >
        <div className="relative flex items-center justify-center shrink-0 mt-0.5">
          <input
            ref={combinedRef}
            id={checkboxId}
            type="checkbox"
            checked={checked}
            disabled={disabled}
            className="sr-only peer"
            {...props}
          />
          <div
            className={`w-4 h-4 rounded border transition-colors flex items-center justify-center peer-focus-visible:ring-2 peer-focus-visible:ring-blue-500 peer-focus-visible:ring-offset-1 ${
              checked || indeterminate
                ? 'bg-blue-600 border-blue-600 text-white'
                : 'bg-[var(--bg-inset)] border-[var(--border-strong)] group-hover:border-[var(--text-secondary)]'
            }`}
          >
            {indeterminate ? (
              <Minus className="w-3 h-3 text-white stroke-[3]" />
            ) : checked ? (
              <Check className="w-3 h-3 text-white stroke-[3]" />
            ) : null}
          </div>
        </div>
        {(label || description) && (
          <div className="flex flex-col text-xs">
            {label && <span className="font-medium text-[var(--text-primary)] leading-tight">{label}</span>}
            {description && <span className="text-[11px] text-[var(--text-tertiary)] mt-0.5">{description}</span>}
          </div>
        )}
      </label>
    );
  }
);

Checkbox.displayName = 'Checkbox';
