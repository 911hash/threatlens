import React from 'react';
import { AlertTriangle, Bell, Clock, ArrowRight } from 'lucide-react';
import { DefangText } from './DefangText';
import { Button } from '../primitives/Button';

export interface AlertRowProps {
  id: string;
  target: string;
  kind: string;
  message: string;
  createdAt: string;
  seen: boolean;
  onInspect?: () => void;
  onDismiss?: () => void;
  className?: string;
}

export const AlertRow: React.FC<AlertRowProps> = ({
  target,
  kind,
  message,
  createdAt,
  seen,
  onInspect,
  onDismiss,
  className = '',
}) => {
  return (
    <div
      className={`flex flex-col sm:flex-row sm:items-center justify-between p-3 rounded-lg border transition-colors gap-3 ${
        seen
          ? 'bg-[var(--bg-panel)] border-[var(--border-subtle)] text-[var(--text-secondary)] opacity-80'
          : 'bg-[var(--bg-elevated)] border-amber-500/40 text-[var(--text-primary)] shadow-xs'
      } ${className}`}
    >
      <div className="flex items-start gap-3 min-w-0">
        <div className="mt-0.5 shrink-0">
          {seen ? (
            <Bell className="w-4 h-4 text-[var(--text-tertiary)]" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-amber-500" />
          )}
        </div>

        <div className="flex flex-col gap-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <DefangText value={target} showCopy={true} className="text-xs font-semibold" />
            <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-tertiary)]">
              {kind}
            </span>
          </div>

          <p className="text-xs text-[var(--text-secondary)] leading-relaxed">{message}</p>

          <div className="flex items-center gap-1.5 text-[11px] text-[var(--text-tertiary)] mt-0.5">
            <Clock className="w-3 h-3" />
            <span>{new Date(createdAt).toLocaleString()}</span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
        {!seen && onDismiss && (
          <Button variant="tertiary" size="xs" onClick={onDismiss}>
            Dismiss
          </Button>
        )}
        {onInspect && (
          <Button
            variant="secondary"
            size="xs"
            rightIcon={<ArrowRight className="w-3 h-3" />}
            onClick={onInspect}
          >
            Inspect
          </Button>
        )}
      </div>
    </div>
  );
};
