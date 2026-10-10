import React, { useState, useEffect, useRef } from 'react';
import {
  Globe,
  ShieldCheck,
  Send,
  CheckCircle2,
  ExternalLink,
  Paperclip,
  Clock,
  ChevronRight,
  Info,
  Calendar,
} from 'lucide-react';
import type { ForensicEvent } from '../../types/threat';
import { useDrawer } from '../../context/DrawerContext';
import { Badge } from '../primitives/Badge';
import { Skeleton } from '../primitives/Skeleton';
import { EmptyState } from '../primitives/EmptyState';

export interface ForensicTimelineProps {
  events: ForensicEvent[];
  isLoading?: boolean;
  onEventClick?: (event: ForensicEvent) => void;
  className?: string;
}

const CATEGORY_CONFIG: Record<
  string,
  { label: string; icon: React.ReactNode; color: string; badgeVariant: 'info' | 'success' | 'warning' | 'neutral' }
> = {
  domain_registered: {
    label: 'Domain Registration',
    icon: <Globe className="w-3.5 h-3.5 text-emerald-400" />,
    color: 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10',
    badgeVariant: 'success',
  },
  certificate_issued: {
    label: 'TLS Certificate',
    icon: <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />,
    color: 'border-blue-500/30 text-blue-400 bg-blue-500/10',
    badgeVariant: 'info',
  },
  email_sent: {
    label: 'Email Dispatched',
    icon: <Send className="w-3.5 h-3.5 text-cyan-400" />,
    color: 'border-cyan-500/30 text-cyan-400 bg-cyan-500/10',
    badgeVariant: 'info',
  },
  email_delivered: {
    label: 'Delivery MTA',
    icon: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />,
    color: 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10',
    badgeVariant: 'success',
  },
  url_first_seen: {
    label: 'URL Telemetry',
    icon: <ExternalLink className="w-3.5 h-3.5 text-purple-400" />,
    color: 'border-purple-500/30 text-purple-400 bg-purple-500/10',
    badgeVariant: 'warning',
  },
  attachment_first_seen: {
    label: 'Attachment First Seen',
    icon: <Paperclip className="w-3.5 h-3.5 text-amber-400" />,
    color: 'border-amber-500/30 text-amber-400 bg-amber-500/10',
    badgeVariant: 'warning',
  },
};

export const ForensicTimeline: React.FC<ForensicTimelineProps> = ({
  events,
  isLoading = false,
  onEventClick,
  className = '',
}) => {
  const drawer = useDrawer();
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const itemRefs = useRef<(HTMLDivElement | null)[]>([]);

  useEffect(() => {
    if (selectedIndex >= events.length && events.length > 0) {
      setSelectedIndex(0);
    }
  }, [events.length, selectedIndex]);

  const handleOpenDetail = (ev: ForensicEvent) => {
    if (onEventClick) {
      onEventClick(ev);
    }

    const conf = CATEGORY_CONFIG[ev.category] || {
      label: ev.category,
      icon: <Clock className="w-3.5 h-3.5 text-blue-400" />,
      color: 'border-blue-500/30 text-blue-400 bg-blue-500/10',
      badgeVariant: 'info' as const,
    };

    drawer.open(
      <div className="space-y-5 p-1 text-[var(--text-primary)]">
        <div className="flex items-center gap-2">
          <span className={`p-2 rounded-lg border ${conf.color}`}>{conf.icon}</span>
          <div>
            <h4 className="text-sm font-semibold text-[var(--text-primary)]">{conf.label}</h4>
            <div className="text-xs text-[var(--text-tertiary)] font-mono">
              Category: {ev.category}
            </div>
          </div>
        </div>

        <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2 text-xs">
          <div className="flex justify-between items-center text-[var(--text-secondary)]">
            <span className="font-medium text-[var(--text-tertiary)]">Event Timestamp:</span>
            <span className="font-mono text-[var(--text-primary)]">
              {ev.event_timestamp ? new Date(ev.event_timestamp).toUTCString() : 'Unknown'}
            </span>
          </div>
          <div className="flex justify-between items-center text-[var(--text-secondary)]">
            <span className="font-medium text-[var(--text-tertiary)]">Intel Source:</span>
            <Badge variant="outline" size="xs">
              {ev.source}
            </Badge>
          </div>
          <div className="flex justify-between items-center text-[var(--text-secondary)]">
            <span className="font-medium text-[var(--text-tertiary)]">Evidence Ref:</span>
            <span className="font-mono text-[var(--text-primary)]">{ev.evidence_ref}</span>
          </div>
        </div>

        <div className="space-y-1.5">
          <h5 className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider">
            Event Description
          </h5>
          <p className="text-xs leading-relaxed p-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-panel)] font-sans">
            {ev.description}
          </p>
        </div>

        <div className="p-3 rounded-lg border border-blue-500/20 bg-blue-500/5 text-xs text-[var(--text-secondary)] flex items-start gap-2">
          <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
          <span>
            Forensic timeline markers are cryptographically reconstructed from immutable mail transmission headers and authoritative external telemetry (RDAP, crt.sh, VirusTotal).
          </span>
        </div>
      </div>,
      { title: 'Forensic Event Evidence' }
    );
  };

  const handleKeyDown = (e: React.KeyboardEvent, index: number) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      const next = (index + 1) % events.length;
      setSelectedIndex(next);
      itemRefs.current[next]?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const prev = (index - 1 + events.length) % events.length;
      setSelectedIndex(prev);
      itemRefs.current[prev]?.focus();
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleOpenDetail(events[index]);
    }
  };

  if (isLoading) {
    return (
      <div className={`space-y-4 ${className}`}>
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="flex gap-3 items-start">
            <Skeleton className="w-6 h-6 rounded-full shrink-0" />
            <div className="space-y-1.5 flex-1">
              <Skeleton className="h-3.5 w-32" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-3 w-20" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (!events || events.length === 0) {
    return (
      <EmptyState
        title="No Timeline Events"
        description="No chronological forensic events found in telemetry for this scan."
        icon={<Clock className="w-8 h-8 text-[var(--text-tertiary)]" />}
        className="py-8"
      />
    );
  }

  return (
    <div
      role="feed"
      aria-label="Forensic Timeline"
      className={`relative pl-4 space-y-4 before:absolute before:top-2 before:bottom-2 before:left-[21px] before:w-0.5 before:bg-[var(--border-subtle)] ${className}`}
    >
      {events.map((ev, idx) => {
        const conf = CATEGORY_CONFIG[ev.category] || {
          label: ev.category,
          icon: <Clock className="w-3.5 h-3.5 text-blue-400" />,
          color: 'border-blue-500/30 text-blue-400 bg-blue-500/10',
          badgeVariant: 'info' as const,
        };

        const isSelected = selectedIndex === idx;

        return (
          <div
            key={ev.id || `${ev.category}-${idx}`}
            ref={(el) => {
              itemRefs.current[idx] = el;
            }}
            tabIndex={0}
            role="article"
            aria-label={`${conf.label} at ${new Date(ev.event_timestamp).toLocaleString()}`}
            onClick={() => {
              setSelectedIndex(idx);
              handleOpenDetail(ev);
            }}
            onKeyDown={(e) => handleKeyDown(e, idx)}
            className={`group relative flex items-start gap-3 p-2.5 rounded-xl border transition-all duration-150 cursor-pointer outline-none ${
              isSelected
                ? 'border-blue-500/60 bg-blue-500/10 shadow-sm ring-1 ring-blue-500/30'
                : 'border-[var(--border-subtle)] bg-[var(--bg-panel)] hover:border-[var(--border-default)] hover:bg-[var(--bg-inset)]'
            }`}
          >
            {/* Timeline node icon */}
            <div
              className={`relative z-10 shrink-0 w-7 h-7 rounded-full flex items-center justify-center border shadow-xs transition-transform group-hover:scale-105 ${conf.color}`}
            >
              {conf.icon}
            </div>

            {/* Event Content */}
            <div className="flex-1 min-w-0 space-y-1">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="text-xs font-semibold text-[var(--text-primary)]">
                  {conf.label}
                </span>
                <span className="text-[10px] font-mono text-[var(--text-tertiary)] flex items-center gap-1">
                  <Calendar className="w-2.5 h-2.5" />
                  {ev.event_timestamp
                    ? new Date(ev.event_timestamp).toLocaleDateString(undefined, {
                        month: 'short',
                        day: 'numeric',
                        year: 'numeric',
                      }) +
                      ' ' +
                      new Date(ev.event_timestamp).toLocaleTimeString(undefined, {
                        hour: '2-digit',
                        minute: '2-digit',
                      })
                    : 'Unknown'}
                </span>
              </div>

              <p className="text-xs text-[var(--text-secondary)] line-clamp-2 leading-relaxed">
                {ev.description}
              </p>

              <div className="flex items-center gap-2 pt-0.5">
                <Badge variant="outline" size="xs" className="text-[9px] uppercase">
                  {ev.source}
                </Badge>
                <span className="text-[10px] text-[var(--text-tertiary)] flex items-center gap-0.5 group-hover:text-blue-400 transition-colors ml-auto font-mono">
                  <span>inspect</span>
                  <ChevronRight className="w-3 h-3" />
                </span>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
