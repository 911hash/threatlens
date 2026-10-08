import React, { forwardRef } from 'react';

export interface RadioProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: React.ReactNode;
  description?: React.ReactNode;
}

export const Radio = forwardRef<HTMLInputElement, RadioProps>(
  ({ label, description, checked, disabled, className = '', id, ...props }, ref) => {
    const radioId = id || (typeof label === 'string' ? `radio-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);

    return (
      <label
        htmlFor={radioId}
        className={`inline-flex items-start gap-2.5 cursor-pointer select-none group ${
          disabled ? 'opacity-50 cursor-not-allowed' : ''
        } ${className}`}
      >
        <div className="relative flex items-center justify-center shrink-0 mt-0.5">
          <input
            ref={ref}
            id={radioId}
            type="radio"
            checked={checked}
            disabled={disabled}
            className="sr-only peer"
            {...props}
          />
          <div
            className={`w-4 h-4 rounded-full border transition-colors flex items-center justify-center peer-focus-visible:ring-2 peer-focus-visible:ring-blue-500 peer-focus-visible:ring-offset-1 ${
              checked
                ? 'border-blue-600 bg-blue-600'
                : 'border-[var(--border-strong)] bg-[var(--bg-inset)] group-hover:border-[var(--text-secondary)]'
            }`}
          >
            {checked && <div className="w-1.5 h-1.5 rounded-full bg-white" />}
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

Radio.displayName = 'Radio';

export interface RadioGroupProps {
  name: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{
    value: string;
    label: React.ReactNode;
    description?: React.ReactNode;
    disabled?: boolean;
  }>;
  direction?: 'horizontal' | 'vertical';
  className?: string;
}

export const RadioGroup: React.FC<RadioGroupProps> = ({
  name,
  value,
  onChange,
  options,
  direction = 'vertical',
  className = '',
}) => {
  return (
    <div
      role="radiogroup"
      className={`flex ${direction === 'horizontal' ? 'flex-row gap-4' : 'flex-col gap-2.5'} ${className}`}
    >
      {options.map(opt => (
        <Radio
          key={opt.value}
          name={name}
          value={opt.value}
          checked={value === opt.value}
          disabled={opt.disabled}
          onChange={() => onChange(opt.value)}
          label={opt.label}
          description={opt.description}
        />
      ))}
    </div>
  );
};
