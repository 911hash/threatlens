import React from 'react';

export interface SegmentedControlOption<T extends string = string> {
  value: T;
  label: React.ReactNode;
  icon?: React.ReactNode;
  disabled?: boolean;
}

export interface SegmentedControlProps<T extends string = string> {
  options: SegmentedControlOption<T>[];
  value: T;
  onChange: (value: T) => void;
  size?: 'xs' | 'sm' | 'md';
  disabled?: boolean;
  className?: string;
  fullWidth?: boolean;
}

export function SegmentedControl<T extends string = string>({
  options,
  value,
  onChange,
  size = 'sm',
  disabled = false,
  className = '',
  fullWidth = false,
}: SegmentedControlProps<T>) {
  const sizeStyles = {
    xs: 'h-6 text-[11px] p-0.5',
    sm: 'h-7 text-xs p-0.5',
    md: 'h-8 text-xs p-1',
  };

  const itemPadding = {
    xs: 'px-2 py-0.5',
    sm: 'px-2.5 py-1',
    md: 'px-3 py-1',
  };

  return (
    <div
      role="group"
      className={`inline-flex items-center rounded-md bg-[var(--bg-inset)] border border-[var(--border-subtle)] ${
        sizeStyles[size]
      } ${fullWidth ? 'w-full' : ''} ${className}`}
    >
      {options.map((option, idx) => {
        const isSelected = option.value === value;
        const isDisabled = disabled || option.disabled;

        const handleKeyDown = (e: React.KeyboardEvent) => {
          let nextIndex = idx;
          if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
            nextIndex = (idx + 1) % options.length;
          } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
            nextIndex = (idx - 1 + options.length) % options.length;
          } else {
            return;
          }
          e.preventDefault();
          const nextOption = options[nextIndex];
          if (nextOption && !nextOption.disabled) {
            onChange(nextOption.value);
            const parent = e.currentTarget.parentElement;
            const buttons = parent?.querySelectorAll<HTMLButtonElement>('button');
            buttons?.[nextIndex]?.focus();
          }
        };

        return (
          <button
            key={option.value}
            type="button"
            role="tab"
            aria-selected={isSelected}
            data-active={isSelected ? 'true' : 'false'}
            disabled={isDisabled}
            onClick={() => onChange(option.value)}
            onKeyDown={handleKeyDown}
            className={`inline-flex items-center justify-center gap-1.5 font-medium rounded transition-all select-none focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed ${
              itemPadding[size]
            } ${fullWidth ? 'flex-1' : ''} ${
              isSelected
                ? 'bg-[var(--bg-panel)] text-[var(--text-primary)] shadow-sm font-semibold border border-[var(--border-strong)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] border border-transparent'
            }`}
          >
            {option.icon && <span className="shrink-0">{option.icon}</span>}
            <span>{option.label}</span>
          </button>
        );
      })}
    </div>
  );
}
