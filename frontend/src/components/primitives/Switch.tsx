import React from 'react';

export interface SwitchProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: React.ReactNode;
  description?: React.ReactNode;
  disabled?: boolean;
  size?: 'sm' | 'md';
  className?: string;
  id?: string;
}

export const Switch: React.FC<SwitchProps> = ({
  checked,
  onChange,
  label,
  description,
  disabled = false,
  size = 'sm',
  className = '',
  id,
}) => {
  const switchId = id || (typeof label === 'string' ? `switch-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);

  const isSm = size === 'sm';
  const trackClasses = isSm ? 'w-7 h-4' : 'w-9 h-5';
  const thumbClasses = isSm ? 'w-3 h-3' : 'w-4 h-4';
  const translateClasses = isSm
    ? checked
      ? 'translate-x-3.5'
      : 'translate-x-0.5'
    : checked
    ? 'translate-x-4.5'
    : 'translate-x-0.5';

  return (
    <label
      htmlFor={switchId}
      className={`inline-flex items-center gap-2.5 cursor-pointer select-none group ${
        disabled ? 'opacity-50 cursor-not-allowed' : ''
      } ${className}`}
    >
      <div className="relative inline-flex items-center shrink-0">
        <input
          id={switchId}
          type="checkbox"
          role="switch"
          aria-checked={checked}
          checked={checked}
          disabled={disabled}
          onChange={e => onChange(e.target.checked)}
          className="sr-only peer"
        />
        <div
          className={`${trackClasses} rounded-full transition-colors flex items-center peer-focus-visible:ring-2 peer-focus-visible:ring-blue-500 peer-focus-visible:ring-offset-1 ${
            checked ? 'bg-blue-600' : 'bg-[var(--border-strong)]'
          }`}
        >
          <div
            className={`${thumbClasses} rounded-full bg-white transition-transform ${translateClasses} shadow-sm`}
          />
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
};
