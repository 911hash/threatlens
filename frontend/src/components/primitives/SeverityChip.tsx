import React from 'react';
import type { SeverityLevel } from '../../design/tokens';
import { getSeverityToken } from '../../design/tokens';
import { useTheme } from '../../design/ThemeContext';

export interface SeverityChipProps {
  severity: SeverityLevel | string | undefined | null;
  score?: number;
  size?: 'xs' | 'sm' | 'md';
  variant?: 'subtle' | 'solid' | 'outline';
  showDot?: boolean;
  className?: string;
}

export const SeverityChip: React.FC<SeverityChipProps> = ({
  severity,
  score,
  size = 'sm',
  variant = 'subtle',
  showDot = true,
  className = '',
}) => {
  const { theme } = useTheme();
  // Strictly resolved via getSeverityToken - NEVER branch directly on theme inside the component
  const token = getSeverityToken(severity, theme);

  const sizeStyles = {
    xs: 'px-1.5 py-0.5 text-[10px] gap-1 font-semibold',
    sm: 'px-2 py-0.5 text-xs gap-1.5 font-semibold',
    md: 'px-2.5 py-1 text-xs gap-2 font-semibold',
  }[size];

  const dotSize = {
    xs: 'w-1.5 h-1.5',
    sm: 'w-2 h-2',
    md: 'w-2.5 h-2.5',
  }[size];

  // Dynamic inline styling for the exact contrast token
  let style: React.CSSProperties = {};
  if (variant === 'subtle') {
    style = {
      backgroundColor: token.bg,
      color: token.text,
      borderColor: token.border,
    };
  } else if (variant === 'solid') {
    style = {
      backgroundColor: token.solid,
      color: '#FFFFFF',
      borderColor: token.solid,
    };
  } else if (variant === 'outline') {
    style = {
      backgroundColor: 'transparent',
      color: token.text,
      borderColor: token.text,
    };
  }

  return (
    <span
      style={style}
      className={`inline-flex items-center rounded border select-none uppercase tracking-wider tabular-nums ${sizeStyles} ${className}`}
    >
      {showDot && (
        <span
          className={`rounded-full shrink-0 ${dotSize}`}
          style={{ backgroundColor: variant === 'solid' ? '#FFFFFF' : token.solid }}
        />
      )}
      <span>{token.label}</span>
      {score !== undefined && (
        <span className="font-mono ml-0.5 opacity-90">{score != null ? score : '—'}</span>
      )}
    </span>
  );
};
