import React, { useId } from 'react';

export interface SliderProps {
  value: number;
  onChange: (value: number) => void;
  min?: number;
  max?: number;
  step?: number;
  label?: string;
  valueFormatter?: (value: number) => string;
  disabled?: boolean;
  className?: string;
}

export const Slider: React.FC<SliderProps> = ({
  value,
  onChange,
  min = 0,
  max = 100,
  step = 1,
  label,
  valueFormatter,
  disabled = false,
  className = '',
}) => {
  const id = useId();
  const percentage = Math.max(0, Math.min(100, ((value - min) / (max - min)) * 100));

  return (
    <div className={`w-full flex flex-col gap-1.5 ${className}`}>
      {(label || valueFormatter) && (
        <div className="flex items-center justify-between text-xs select-none">
          {label && (
            <label htmlFor={id} className="font-medium text-[var(--text-secondary)]">
              {label}
            </label>
          )}
          <span className="font-mono text-xs text-[var(--text-primary)] tabular-nums">
            {valueFormatter ? valueFormatter(value) : value}
          </span>
        </div>
      )}
      <div className="relative flex items-center w-full h-5">
        <div className="w-full h-1.5 rounded-full bg-[var(--border-strong)] overflow-hidden">
          <div
            className="h-full bg-blue-600 transition-all"
            style={{ width: `${percentage}%` }}
          />
        </div>
        <input
          id={id}
          type="range"
          min={min}
          max={max}
          step={step}
          value={value}
          disabled={disabled}
          onChange={e => onChange(Number(e.target.value))}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer disabled:cursor-not-allowed"
        />
        {/* Visual Thumb */}
        <div
          className="absolute top-1/2 -translate-y-1/2 w-3.5 h-3.5 rounded-full bg-white border border-blue-600 shadow-sm pointer-events-none transition-all"
          style={{ left: `calc(${percentage}% - 7px)` }}
        />
      </div>
    </div>
  );
};
