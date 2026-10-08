import React from 'react';

export type StatusDotState = 'live' | 'healthy' | 'degraded' | 'stale' | 'scanning' | 'offline';

export interface StatusDotProps {
  status: StatusDotState;
  label?: string;
  pulse?: boolean;
  size?: 'xs' | 'sm' | 'md';
  className?: string;
}

export const StatusDot: React.FC<StatusDotProps> = ({
  status,
  label,
  pulse = true,
  size = 'sm',
  className = '',
}) => {
  const dotSize = {
    xs: 'w-1.5 h-1.5',
    sm: 'w-2 h-2',
    md: 'w-2.5 h-2.5',
  }[size];

  const colorConfig: Record<StatusDotState, { dot: string; pulseBg: string; text: string }> = {
    live: {
      dot: 'bg-emerald-500',
      pulseBg: 'bg-emerald-400',
      text: 'text-emerald-500',
    },
    healthy: {
      dot: 'bg-emerald-500',
      pulseBg: 'bg-emerald-400',
      text: 'text-emerald-500',
    },
    degraded: {
      dot: 'bg-amber-500',
      pulseBg: 'bg-amber-400',
      text: 'text-amber-500',
    },
    stale: {
      dot: 'bg-yellow-500',
      pulseBg: 'bg-yellow-400',
      text: 'text-yellow-500',
    },
    scanning: {
      dot: 'bg-blue-500',
      pulseBg: 'bg-blue-400',
      text: 'text-blue-500',
    },
    offline: {
      dot: 'bg-red-500',
      pulseBg: 'bg-red-400',
      text: 'text-red-500',
    },
  };

  const current = colorConfig[status] || colorConfig.offline;
  const isPulsing = pulse && (status === 'live' || status === 'scanning' || status === 'healthy');

  return (
    <div className={`inline-flex items-center gap-1.5 select-none ${className}`}>
      <div className="relative flex items-center justify-center shrink-0">
        {isPulsing && (
          <span
            className={`absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping ${current.pulseBg}`}
          />
        )}
        <span className={`relative inline-flex rounded-full ${dotSize} ${current.dot}`} />
      </div>
      {label && <span className="text-xs text-[var(--text-secondary)] font-medium leading-none">{label}</span>}
    </div>
  );
};
