import React from 'react';
import { useNavigate } from 'react-router-dom';
import { History, TrendingUp, Calendar, ChevronRight } from 'lucide-react';
import type { Scan } from '../types/threat';
import { usePrefersReducedMotion } from '../hooks/usePrefersReducedMotion';
import { useTheme } from '../design/ThemeContext';
import { getSeverityToken } from '../design/tokens';
import { Tooltip } from './primitives/Tooltip';

export interface TemporalSparklineProps {
  scans: Scan[];
  currentScanId: string;
}

export const TemporalSparkline: React.FC<TemporalSparklineProps> = ({ scans, currentScanId }) => {
  const navigate = useNavigate();
  const prefersReducedMotion = usePrefersReducedMotion();
  const { theme } = useTheme();

  // Sort chronological (oldest to newest)
  const sortedScans = React.useMemo(() => {
    return [...scans].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }, [scans]);

  if (sortedScans.length <= 1) {
    return (
      <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] text-center space-y-2">
        <History className="w-6 h-6 text-[var(--text-tertiary)] mx-auto" />
        <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)]">
          Temporal Context & Evolution
        </h4>
        <p className="text-xs text-[var(--text-secondary)] max-w-sm mx-auto">
          No prior scans to compare. Re-scan this target or seed demo data to track score drift across time.
        </p>
      </div>
    );
  }

  const firstSeen = new Date(sortedScans[0].timestamp).toLocaleString();
  const lastSeen = new Date(sortedScans[sortedScans.length - 1].timestamp).toLocaleString();

  // SVG Chart Geometry
  const width = 640;
  const height = 150;
  const paddingX = 40;
  const paddingY = 20;

  const innerWidth = width - paddingX * 2;
  const innerHeight = height - paddingY * 2;

  // Calculate points coordinates
  const points = sortedScans.map((s, idx) => {
    const x = paddingX + (idx / (sortedScans.length - 1)) * innerWidth;
    const y = height - paddingY - (Math.min(100, Math.max(0, s.risk_score)) / 100) * innerHeight;
    return { x, y, scan: s, isCurrent: s.id === currentScanId };
  });

  const pathD = points.reduce((acc, pt, idx) => {
    return idx === 0 ? `M ${pt.x} ${pt.y}` : `${acc} L ${pt.x} ${pt.y}`;
  }, '');

  return (
    <div className="space-y-3">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
        <div>
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            Temporal Score Drift Sparkline
          </h3>
          <p className="text-[11px] text-[var(--text-secondary)]">
            Tracking target evolution over {sortedScans.length} historical scans. Click any node to load that report.
          </p>
        </div>

        <div className="flex items-center gap-3 text-[10px] font-mono text-[var(--text-tertiary)]">
          <span>First: {firstSeen.split(',')[0]}</span>
          <span>·</span>
          <span>Latest: {lastSeen.split(',')[0]}</span>
        </div>
      </div>

      {/* Surface strictly uses --bg-visual */}
      <div className="p-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-visual)] shadow-xs">
        <div className="w-full overflow-x-auto">
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="w-full h-36 min-w-[480px]"
          >
            {/* Severity bands background (0-29 Low, 30-54 Med, 55-79 High, 80-100 Crit) */}
            {/* Critical: 80-100 */}
            <rect
              x={paddingX}
              y={paddingY}
              width={innerWidth}
              height={innerHeight * 0.2}
              fill="rgba(239, 68, 68, 0.08)"
            />
            {/* High: 55-79 */}
            <rect
              x={paddingX}
              y={paddingY + innerHeight * 0.2}
              width={innerWidth}
              height={innerHeight * 0.25}
              fill="rgba(249, 115, 22, 0.06)"
            />
            {/* Medium: 30-54 */}
            <rect
              x={paddingX}
              y={paddingY + innerHeight * 0.45}
              width={innerWidth}
              height={innerHeight * 0.25}
              fill="rgba(245, 158, 11, 0.05)"
            />
            {/* Low: 0-29 */}
            <rect
              x={paddingX}
              y={paddingY + innerHeight * 0.7}
              width={innerWidth}
              height={innerHeight * 0.3}
              fill="rgba(6, 182, 212, 0.04)"
            />

            {/* Threshold reference lines */}
            <line
              x1={paddingX}
              y1={paddingY + innerHeight * 0.2}
              x2={width - paddingX}
              y2={paddingY + innerHeight * 0.2}
              stroke="var(--border-subtle)"
              strokeDasharray="3 3"
            />
            <line
              x1={paddingX}
              y1={paddingY + innerHeight * 0.45}
              x2={width - paddingX}
              y2={paddingY + innerHeight * 0.45}
              stroke="var(--border-subtle)"
              strokeDasharray="3 3"
            />
            <line
              x1={paddingX}
              y1={paddingY + innerHeight * 0.7}
              x2={width - paddingX}
              y2={paddingY + innerHeight * 0.7}
              stroke="var(--border-subtle)"
              strokeDasharray="3 3"
            />

            {/* Sparkline Path */}
            <path
              d={pathD}
              fill="none"
              stroke="#3B82F6"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              className={prefersReducedMotion ? '' : 'transition-all duration-300'}
            />

            {/* Clickable Data Nodes */}
            {points.map((pt) => {
              const token = getSeverityToken(pt.scan.risk_level, theme);
              return (
                <g
                  key={pt.scan.id}
                  className="cursor-pointer group"
                  onClick={() => navigate(`/scans/${pt.scan.id}`)}
                >
                  {/* Outer ring for current scan */}
                  {pt.isCurrent && (
                    <circle
                      cx={pt.x}
                      cy={pt.y}
                      r="9"
                      fill="none"
                      stroke={token.solid}
                      strokeWidth="2"
                      opacity="0.8"
                      className="animate-pulse"
                    />
                  )}
                  {/* Point circle */}
                  <circle
                    cx={pt.x}
                    cy={pt.y}
                    r={pt.isCurrent ? '5.5' : '4'}
                    fill={token.solid}
                    stroke="var(--bg-visual)"
                    strokeWidth="2"
                    className="group-hover:scale-125 transition-transform"
                  />
                  {/* Score Label above point */}
                  <text
                    x={pt.x}
                    y={pt.y - 10}
                    textAnchor="middle"
                    fill="var(--text-primary)"
                    fontSize="10"
                    fontFamily="monospace"
                    fontWeight={pt.isCurrent ? 'bold' : 'normal'}
                  >
                    {pt.scan.risk_score}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Legend */}
        <div className="flex items-center justify-between text-[10px] font-mono text-[var(--text-tertiary)] pt-2 border-t border-[var(--border-subtle)] mt-2">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-cyan-400" /> Low (0-29)
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-amber-400" /> Med (30-54)
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-orange-400" /> High (55-79)
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-red-400" /> Crit (80-100)
            </span>
          </div>

          <span>Current scan highlighted</span>
        </div>
      </div>
    </div>
  );
};
