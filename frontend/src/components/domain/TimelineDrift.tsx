import React from 'react';
import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react';

export interface TimelineDriftProps {
  scores?: number[];
  currentScore: number;
  previousScore?: number;
  width?: number;
  height?: number;
  className?: string;
}

export const TimelineDrift: React.FC<TimelineDriftProps> = ({
  scores = [],
  currentScore,
  previousScore,
  width = 64,
  height = 20,
  className = '',
}) => {
  const safeCurrent = typeof currentScore === 'number' && !isNaN(currentScore) ? currentScore : 0;
  const safePrev = typeof previousScore === 'number' && !isNaN(previousScore) ? previousScore : undefined;
  const delta = safePrev !== undefined ? safeCurrent - safePrev : undefined;

  // Build points for sparkline if scores provided
  const points = scores.length > 1 ? scores : safePrev !== undefined ? [safePrev, safeCurrent] : [safeCurrent];

  const min = Math.min(...points, 0);
  const max = Math.max(...points, 100);
  const range = max - min || 1;

  const svgPoints = points
    .map((val, idx) => {
      const x = (idx / (points.length - 1 || 1)) * (width - 4) + 2;
      const y = height - ((val - min) / range) * (height - 6) - 3;
      return `${x},${isNaN(y) ? height / 2 : y}`;
    })
    .join(' ');

  const isWorse = delta !== undefined && delta > 0;
  const isBetter = delta !== undefined && delta < 0;

  const deltaColor = isWorse
    ? 'text-red-500 bg-red-500/10 border-red-500/30'
    : isBetter
    ? 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30'
    : 'text-[var(--text-tertiary)] bg-[var(--bg-inset)] border-[var(--border-subtle)]';

  const strokeColor = isWorse ? '#ef4444' : isBetter ? '#10b981' : '#3b82f6';

  const cyPoint = height - ((safeCurrent - min) / range) * (height - 6) - 3;

  return (
    <div className={`inline-flex items-center gap-2 ${className}`}>
      {/* Mini Sparkline */}
      <svg width={width} height={height} className="overflow-visible shrink-0">
        {points.length > 1 && (
          <polyline
            fill="none"
            stroke={strokeColor}
            strokeWidth="1.75"
            strokeLinecap="round"
            strokeLinejoin="round"
            points={svgPoints}
          />
        )}
        {/* Current point dot */}
        {points.length > 0 && (
          <circle
            cx={width - 2}
            cy={isNaN(cyPoint) ? height / 2 : cyPoint}
            r="2.5"
            fill={strokeColor}
          />
        )}
      </svg>

      {/* Delta badge */}
      {delta !== undefined && (
        <span
          className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold border ${deltaColor}`}
        >
          {isWorse ? (
            <ArrowUpRight className="w-3 h-3" />
          ) : isBetter ? (
            <ArrowDownRight className="w-3 h-3" />
          ) : (
            <Minus className="w-2.5 h-2.5" />
          )}
          <span>{delta > 0 ? `+${delta}` : delta}</span>
        </span>
      )}
    </div>
  );
};
