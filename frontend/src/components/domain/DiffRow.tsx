import React from 'react';
import { Plus, Minus, ArrowRight } from 'lucide-react';
import { SeverityChip } from '../primitives/SeverityChip';

export type DiffChangeType = 'added' | 'removed' | 'changed';

export interface DiffRowProps {
  changeType: DiffChangeType;
  title: string;
  source?: string;
  points?: number;
  oldPoints?: number;
  newPoints?: number;
  severity?: string;
  oldSeverity?: string;
  newSeverity?: string;
  className?: string;
}

export const DiffRow: React.FC<DiffRowProps> = ({
  changeType,
  title,
  source,
  points,
  oldPoints,
  newPoints,
  severity,
  oldSeverity,
  newSeverity,
  className = '',
}) => {
  const typeConfig: Record<
    DiffChangeType,
    { badge: React.ReactNode; border: string; bg: string }
  > = {
    added: {
      badge: (
        <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold text-red-500 bg-red-500/10 border border-red-500/20">
          <Plus className="w-2.5 h-2.5" /> Added {points !== undefined ? `+${points}` : ''}
        </span>
      ),
      border: 'border-red-500/20',
      bg: 'bg-red-500/5',
    },
    removed: {
      badge: (
        <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold text-emerald-500 bg-emerald-500/10 border border-emerald-500/20">
          <Minus className="w-2.5 h-2.5" /> Resolved {points !== undefined ? `-${points}` : ''}
        </span>
      ),
      border: 'border-emerald-500/20',
      bg: 'bg-emerald-500/5',
    },
    changed: {
      badge: (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold text-amber-500 bg-amber-500/10 border border-amber-500/20">
          <span>{oldPoints}</span>
          <ArrowRight className="w-2.5 h-2.5" />
          <span>{newPoints}</span>
        </span>
      ),
      border: 'border-amber-500/20',
      bg: 'bg-amber-500/5',
    },
  };

  const config = typeConfig[changeType];

  return (
    <div
      data-diff-type={changeType}
      className={`flex items-center justify-between p-2.5 rounded-lg border text-xs gap-3 ${
        config.border
      } ${config.bg} ${className}`}
    >
      <div className="flex items-center gap-2.5 min-w-0">
        <div className="shrink-0">{config.badge}</div>
        <div className="flex flex-col min-w-0">
          <span className="font-medium text-[var(--text-primary)] truncate">{title}</span>
          {source && (
            <span className="text-[10px] text-[var(--text-tertiary)] truncate">Source: {source}</span>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0">
        {changeType === 'changed' ? (
          <div className="flex items-center gap-1.5">
            {oldSeverity && <SeverityChip severity={oldSeverity} size="xs" />}
            <ArrowRight className="w-3 h-3 text-[var(--text-tertiary)]" />
            {newSeverity && <SeverityChip severity={newSeverity} size="xs" />}
          </div>
        ) : (
          severity && <SeverityChip severity={severity} size="xs" />
        )}
      </div>
    </div>
  );
};
