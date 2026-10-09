import React from 'react';
import type { InboxItem } from '../../types/threat';
import { SeverityChip } from '../primitives/SeverityChip';
import { DefangText } from './DefangText';
import { Globe, Sparkles } from 'lucide-react';

export interface InboxRowProps {
  item: InboxItem;
  isSelected: boolean;
  onSelect: () => void;
  lastVisitTimestamp?: number;
}

function formatRelativeTime(dateStr?: string): string {
  if (!dateStr) return '';
  const parsed = new Date(dateStr);
  if (isNaN(parsed.getTime())) return dateStr;

  const diffMs = Date.now() - parsed.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDays = Math.floor(diffHour / 24);

  if (diffSec < 60) return 'Just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHour < 24) return `${diffHour}h ago`;
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays}d ago`;
  return parsed.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export const InboxRow: React.FC<InboxRowProps> = ({
  item,
  isSelected,
  onSelect,
  lastVisitTimestamp = 0,
}) => {
  const itemTime = item.date ? new Date(item.date).getTime() : 0;
  const isUnread = lastVisitTimestamp > 0 && itemTime > lastVisitTimestamp;

  return (
    <div
      onClick={onSelect}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect();
        }
      }}
      className={`group relative flex flex-col gap-2 p-3.5 rounded-xl border transition-all cursor-pointer select-none text-left ${
        isSelected
          ? 'bg-[var(--bg-elevated)] border-[var(--primary)] shadow-md shadow-blue-500/5'
          : 'bg-[var(--bg-panel)]/80 hover:bg-[var(--bg-panel)] border-[var(--border-subtle)] hover:border-[var(--border-muted)]'
      }`}
    >
      {/* Top Header: Unread indicator, Sender domain, Relative time */}
      <div className="flex items-center justify-between gap-2 min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          {/* Unread blue dot */}
          {isUnread && (
            <span
              className="w-2 h-2 rounded-full bg-blue-500 shrink-0 ring-2 ring-blue-500/30"
              title="New since your last visit"
            />
          )}

          <div className="font-semibold text-xs text-[var(--text-primary)] truncate">
            {item.from_domain ? (
              <DefangText value={item.from_domain} showCopy={false} />
            ) : (
              item.from_address || 'Unknown Sender'
            )}
          </div>
        </div>

        <span className="text-[11px] font-medium text-[var(--text-tertiary)] shrink-0 whitespace-nowrap">
          {formatRelativeTime(item.date)}
        </span>
      </div>

      {/* Subject Line */}
      <div className="text-sm font-medium text-[var(--text-primary)] truncate line-clamp-1">
        {item.subject || '(No Subject)'}
      </div>

      {/* Bottom Row: Severity badge, indicators (Geo, AI) */}
      <div className="flex items-center justify-between gap-2 mt-1 pt-1.5 border-t border-[var(--border-subtle)]/50">
        <SeverityChip severity={item.risk_level} score={item.risk_score} size="xs" />

        <div className="flex items-center gap-2 text-[11px] text-[var(--text-muted)]">
          {item.has_geo && (
            <span className="flex items-center gap-1" title="Geolocation telemetry available">
              <Globe className="w-3 h-3 text-sky-400" />
            </span>
          )}
          {item.has_ai && (
            <span className="flex items-center gap-1" title="AI threat reasoning active">
              <Sparkles className="w-3 h-3 text-amber-400" />
            </span>
          )}
        </div>
      </div>
    </div>
  );
};
