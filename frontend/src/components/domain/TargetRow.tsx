import React from 'react';
import { RefreshCw, Trash2, ChevronRight } from 'lucide-react';
import { DefangText } from './DefangText';
import { SeverityChip } from '../primitives/SeverityChip';
import { Badge } from '../primitives/Badge';
import { IconButton } from '../primitives/IconButton';

export interface TargetRowProps {
  id: string;
  target: string;
  targetType: string;
  level?: string;
  score?: number;
  lastScannedAt?: string;
  active?: boolean;
  onRescan?: () => void;
  onRemove?: () => void;
  onClick?: () => void;
  isRescanning?: boolean;
  className?: string;
}

export const TargetRow: React.FC<TargetRowProps> = ({
  target,
  targetType,
  level,
  score,
  lastScannedAt,
  active = true,
  onRescan,
  onRemove,
  onClick,
  isRescanning = false,
  className = '',
}) => {
  return (
    <div
      onClick={onClick}
      className={`group flex items-center justify-between p-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-panel)] hover:bg-[var(--bg-elevated)] transition-colors gap-3 cursor-pointer ${
        !active ? 'opacity-60' : ''
      } ${className}`}
    >
      <div className="flex items-center gap-3 min-w-0">
        <Badge variant="neutral" size="xs">
          {targetType}
        </Badge>

        <div className="flex flex-col min-w-0">
          <DefangText value={target} showCopy={true} className="text-xs font-medium" />
          {lastScannedAt && (
            <span className="text-[11px] text-[var(--text-tertiary)] mt-0.5">
              Last scanned: {new Date(lastScannedAt).toLocaleString()}
            </span>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2.5 shrink-0" onClick={e => e.stopPropagation()}>
        {level && <SeverityChip severity={level} score={score} size="xs" />}

        {onRescan && (
          <IconButton
            icon={<RefreshCw className={`w-3.5 h-3.5 ${isRescanning ? 'animate-spin' : ''}`} />}
            aria-label="Re-scan target"
            size="xs"
            variant="tertiary"
            disabled={isRescanning}
            onClick={onRescan}
          />
        )}

        {onRemove && (
          <IconButton
            icon={<Trash2 className="w-3.5 h-3.5" />}
            aria-label="Remove from watchlist"
            size="xs"
            variant="tertiary"
            onClick={onRemove}
          />
        )}

        {onClick && (
          <ChevronRight className="w-4 h-4 text-[var(--text-tertiary)] group-hover:text-[var(--text-primary)] transition-colors" />
        )}
      </div>
    </div>
  );
};
