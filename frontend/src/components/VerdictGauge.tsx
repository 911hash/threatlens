import React, { useEffect, useState, useRef } from 'react';
import type { RiskLevel } from '../types/threat';
import { usePrefersReducedMotion } from '../hooks/usePrefersReducedMotion';
import { useTheme } from '../design/ThemeContext';
import { getSeverityToken } from '../design/tokens';

export interface VerdictGaugeProps {
  score?: number | null;
  level: RiskLevel;
  size?: number;
  className?: string;
}

export const VerdictGauge: React.FC<VerdictGaugeProps> = ({
  score,
  level,
  size = 140,
  className = '',
}) => {
  const prefersReducedMotion = usePrefersReducedMotion();
  const { theme } = useTheme();
  const token = getSeverityToken(level, theme);
  const isNull = score == null;
  const numScore = isNull ? 0 : Math.max(0, Math.min(100, score!));
  const [displayScore, setDisplayScore] = useState(prefersReducedMotion ? numScore : 0);
  const hasAnimatedRef = useRef(false);

  useEffect(() => {
    if (isNull) {
      setDisplayScore(0);
      return;
    }
    if (prefersReducedMotion || hasAnimatedRef.current) {
      setDisplayScore(numScore);
      return;
    }

    hasAnimatedRef.current = true;
    let start = 0;
    const duration = 850;
    const steps = 30;
    const stepTime = duration / steps;
    const increment = numScore / steps;

    const timer = setInterval(() => {
      start += increment;
      if (start >= numScore) {
        setDisplayScore(numScore);
        clearInterval(timer);
      } else {
        setDisplayScore(Math.floor(start));
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, [numScore, prefersReducedMotion, isNull]);

  // Radial geometry
  const strokeWidth = 10;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = isNull ? circumference : circumference - (displayScore / 100) * circumference;

  return (
    <div
      role="img"
      aria-label={isNull ? `Risk score unavailable, severity ${level}` : `Risk score: ${numScore} out of 100, severity ${level}`}
      className={`relative inline-flex items-center justify-center p-3 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-visual)] shadow-xs ${className}`}
      style={{ width: size + 24, height: size + 24 }}
    >
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="transform -rotate-90"
      >
        {/* Background track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--bg-inset)"
          strokeWidth={strokeWidth}
        />
        {/* Progress Arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={token.solid}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-300 ease-out"
        />
      </svg>

      {/* Center Score Readout */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span
          className="font-mono font-black tracking-tight leading-none text-[var(--text-primary)]"
          style={{ fontSize: size * 0.28 }}
        >
          {isNull ? '—' : displayScore}
        </span>
        <span className="font-mono text-[10px] text-[var(--text-tertiary)] uppercase tracking-wider mt-0.5">
          / 100
        </span>
      </div>
    </div>
  );
};
