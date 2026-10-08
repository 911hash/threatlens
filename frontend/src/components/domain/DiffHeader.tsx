import React from 'react';
import { ArrowRight, ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react';
import { SeverityChip } from '../primitives/SeverityChip';
import { Badge } from '../primitives/Badge';

export interface DiffHeaderProps {
  scanA: {
    id: string;
    timestamp: string;
    score: number;
    level: string;
  };
  scanB: {
    id: string;
    timestamp: string;
    score: number;
    level: string;
  };
  scoreDelta: number;
  summarySentence?: string;
  className?: string;
}

export const DiffHeader: React.FC<DiffHeaderProps> = ({
  scanA,
  scanB,
  scoreDelta,
  summarySentence,
  className = '',
}) => {
  const isWorse = scoreDelta > 0;
  const isBetter = scoreDelta < 0;

  const deltaBadgeColor = isWorse
    ? 'text-red-500 bg-red-500/10 border-red-500/30'
    : isBetter
    ? 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30'
    : 'text-[var(--text-tertiary)] bg-[var(--bg-inset)] border-[var(--border-subtle)]';

  return (
    <div
      className={`rounded-xl border border-[var(--border-strong)] bg-[var(--bg-panel)] p-4 shadow-sm flex flex-col gap-3 ${className}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border-subtle)] pb-3">
        {/* Left: Scan A -> Scan B */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-[var(--text-tertiary)]">Baseline</span>
            <SeverityChip severity={scanA.level} score={scanA.score} size="xs" />
            <span className="text-[11px] font-mono text-[var(--text-tertiary)]">({scanA.id})</span>
          </div>

          <ArrowRight className="w-3.5 h-3.5 text-[var(--text-tertiary)]" />

          <div className="flex items-center gap-2">
            <span className="text-xs text-[var(--text-tertiary)]">Current</span>
            <SeverityChip severity={scanB.level} score={scanB.score} size="xs" />
            <span className="text-[11px] font-mono text-[var(--text-tertiary)]">({scanB.id})</span>
          </div>
        </div>

        {/* Right: Delta Badge */}
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono font-bold border ${deltaBadgeColor}`}
          >
            {isWorse ? (
              <ArrowUpRight className="w-4 h-4" />
            ) : isBetter ? (
              <ArrowDownRight className="w-4 h-4" />
            ) : (
              <Minus className="w-3.5 h-3.5" />
            )}
            <span>Delta: {scoreDelta > 0 ? `+${scoreDelta}` : scoreDelta} pts</span>
          </span>
          {scanA.level !== scanB.level && (
            <Badge variant="warning" size="sm">
              Verdict Changed
            </Badge>
          )}
        </div>
      </div>

      {summarySentence && (
        <p data-summary-sentence="true" className="text-xs text-[var(--text-secondary)] font-medium leading-relaxed">
          {summarySentence}
        </p>
      )}
    </div>
  );
};
