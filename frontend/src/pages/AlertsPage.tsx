import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Bell,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  GitCompare,
  ExternalLink,
  Clock,
  Check,
  TrendingUp,
  TrendingDown,
  ShieldAlert,
  Search,
  Filter,
  Layers,
  ArrowRight,
  Eye,
} from 'lucide-react';
import { api } from '../api/client';
import type { AlertItem } from '../types/threat';
import { Button } from '../components/primitives/Button';
import { Badge } from '../components/primitives/Badge';
import { EmptyState } from '../components/primitives/EmptyState';
import { ErrorState } from '../components/primitives/ErrorState';
import { Skeleton } from '../components/primitives/Skeleton';
import { DefangText } from '../components/domain/DefangText';
import { useToast } from '../components/primitives/Toast';

export const AlertsPage: React.FC = () => {
  const navigate = useNavigate();
  const toast = useToast();
  const [searchParams] = useSearchParams();
  const stateOverride = searchParams.get('state');

  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [watchlistCount, setWatchlistCount] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [readFilter, setReadFilter] = useState<'all' | 'unread' | 'read'>('all');
  const [kindFilter, setKindFilter] = useState<string>('all');
  const [markingIds, setMarkingIds] = useState<string[]>([]);

  useEffect(() => {
    loadAlertsData();
  }, []);

  const loadAlertsData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [alertsData, watchlistData] = await Promise.all([
        api.getAlerts(),
        api.getWatchlist().catch(() => []),
      ]);
      setAlerts(alertsData);
      setWatchlistCount(watchlistData.length);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve threat escalation alerts.');
    } finally {
      setLoading(false);
    }
  };

  const handleMarkRead = async (alertId: string) => {
    try {
      setMarkingIds((prev) => [...prev, alertId]);
      await api.markAlertRead(alertId);

      // Optimistically update local alert state
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, seen: true } : a))
      );

      // Dispatch global event so Sidebar badge updates in real time
      window.dispatchEvent(new CustomEvent('threatlens:alerts-updated'));
      toast.success('Alert marked as read');
    } catch (err: any) {
      toast.error(err.message || 'Failed to update alert state');
    } finally {
      setMarkingIds((prev) => prev.filter((id) => id !== alertId));
    }
  };

  const handleMarkAllRead = async () => {
    const unread = alerts.filter((a) => !a.seen);
    if (unread.length === 0) return;

    try {
      await api.markAllAlertsRead();
      setAlerts((prev) => prev.map((a) => ({ ...a, seen: true })));
      window.dispatchEvent(new CustomEvent('threatlens:alerts-updated'));
      toast.success(`Marked ${unread.length} alerts as read`);
    } catch (err: any) {
      toast.error(err.message || 'Failed to mark all alerts as read');
    }
  };

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (readFilter === 'unread' && a.seen) return false;
      if (readFilter === 'read' && !a.seen) return false;
      if (kindFilter !== 'all' && a.kind !== kindFilter) return false;
      return true;
    });
  }, [alerts, readFilter, kindFilter]);

  // Group alerts by day (reverse chronological)
  const groupedAlerts = useMemo(() => {
    const groups: { [dateLabel: string]: AlertItem[] } = {};

    filteredAlerts.forEach((a) => {
      const d = new Date(a.created_at);
      const today = new Date();
      const yesterday = new Date();
      yesterday.setDate(today.getDate() - 1);

      let label = d.toLocaleDateString('en-US', {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      });

      if (d.toDateString() === today.toDateString()) {
        label = 'Today';
      } else if (d.toDateString() === yesterday.toDateString()) {
        label = 'Yesterday';
      }

      if (!groups[label]) groups[label] = [];
      groups[label].push(a);
    });

    return groups;
  }, [filteredAlerts]);

  const unreadCount = alerts.filter((a) => !a.seen).length;

  // State Matrix Overrides
  if (stateOverride === 'loading' || (loading && alerts.length === 0)) {
    return (
      <div className="max-w-5xl mx-auto py-8 px-4 space-y-6">
        <Skeleton className="w-1/3 h-8 rounded-lg" />
        <Skeleton className="w-full h-16 rounded-xl" />
        <div className="space-y-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-28 rounded-2xl" />
          ))}
        </div>
      </div>
    );
  }

  if (stateOverride === 'error' || (error && alerts.length === 0)) {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4">
        <ErrorState
          title="Failed to Load Drift Alerts"
          message={error || 'Unable to communicate with alerting engine.'}
          onRetry={loadAlertsData}
        />
      </div>
    );
  }

  if (stateOverride === 'empty' || alerts.length === 0) {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4 space-y-6 animate-in fade-in duration-200">
        <EmptyState
          title="No Escalations"
          description={`ThreatLens is watching ${watchlistCount || 4} targets. Automated alerts will trigger the moment a score escalates or indicators drift.`}
          action={
            <Button
              variant="primary"
              size="md"
              onClick={() => navigate('/watchlist')}
              className="flex items-center gap-2"
            >
              <span>View Watchlist</span>
              <ArrowRight className="w-4 h-4" />
            </Button>
          }
        />
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto py-8 px-4 space-y-6 pb-16 animate-in fade-in duration-150">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <h1 className="text-2xl font-bold text-[var(--text-primary)]">
              Threat Escalation & Drift Alerts
            </h1>
            {unreadCount > 0 && (
              <Badge variant="warning" size="xs">
                {unreadCount} unread
              </Badge>
            )}
          </div>
          <p className="text-xs text-[var(--text-secondary)]">
            Continuous threat surveillance monitoring verdict drift across active watchlist infrastructure.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {unreadCount > 0 && (
            <Button
              variant="secondary"
              size="sm"
              onClick={handleMarkAllRead}
              className="flex items-center gap-1.5"
            >
              <Check className="w-3.5 h-3.5" />
              <span>Mark all as read</span>
            </Button>
          )}

          <Button
            variant="secondary"
            size="sm"
            onClick={loadAlertsData}
            className="flex items-center gap-1.5"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </Button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-3.5 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-[var(--text-tertiary)]">Filter:</span>
          {/* Read filter */}
          <div className="flex items-center rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-0.5 text-xs">
            {(['all', 'unread', 'read'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setReadFilter(mode)}
                className={`px-2.5 py-1 rounded-md capitalize font-medium transition-colors cursor-pointer ${
                  readFilter === mode
                    ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)] shadow-xs'
                    : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
                }`}
              >
                {mode}
              </button>
            ))}
          </div>

          {/* Kind filter */}
          <select
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value)}
            aria-label="Filter alerts by alert type"
            className="px-2.5 py-1 text-xs rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-primary)] cursor-pointer"
          >
            <option value="all">All Alert Types</option>
            <option value="threat_escalation">Threat Escalation</option>
            <option value="threat_downgrade">Threat Downgrade</option>
            <option value="score_change">Score Drift</option>
          </select>
        </div>

        <div className="text-xs text-[var(--text-tertiary)] font-mono">
          Showing {filteredAlerts.length} of {alerts.length} alerts
        </div>
      </div>

      {/* Grouped Feed */}
      <div className="space-y-6">
        {Object.keys(groupedAlerts).length > 0 ? (
          Object.entries(groupedAlerts).map(([dateLabel, items]) => (
            <div key={dateLabel} className="space-y-3">
              <div className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-tertiary)] flex items-center gap-2">
                <Clock className="w-3.5 h-3.5 text-blue-400" />
                <span>{dateLabel}</span>
                <span className="text-[10px] text-[var(--text-tertiary)] font-normal">
                  ({items.length} {items.length === 1 ? 'event' : 'events'})
                </span>
              </div>

              <div className="space-y-3">
                {items.map((alert) => {
                  const isEscalation = alert.kind === 'threat_escalation';
                  const isDowngrade = alert.kind === 'threat_downgrade';
                  const isMarking = markingIds.includes(alert.id);

                  return (
                    <div
                      key={alert.id}
                      className={`p-4 rounded-2xl border transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
                        !alert.seen
                          ? 'bg-[var(--bg-elevated)] border-amber-500/40 shadow-xs'
                          : 'bg-[var(--bg-panel)] border-[var(--border-subtle)] text-[var(--text-secondary)]'
                      }`}
                    >
                      <div className="flex items-start gap-3.5 min-w-0">
                        <div className="mt-0.5 shrink-0">
                          {isEscalation ? (
                            <div className="p-2 rounded-xl bg-red-500/10 text-red-400 border border-red-500/20">
                              <TrendingUp className="w-4 h-4" />
                            </div>
                          ) : isDowngrade ? (
                            <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              <TrendingDown className="w-4 h-4" />
                            </div>
                          ) : (
                            <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                              <RotateCcw className="w-4 h-4" />
                            </div>
                          )}
                        </div>

                        <div className="space-y-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-xs font-semibold text-[var(--text-primary)]">
                              <DefangText value={alert.target} showCopy={true} />
                            </span>
                            <Badge
                              variant={isEscalation ? 'danger' : isDowngrade ? 'success' : 'warning'}
                              size="xs"
                              className="uppercase font-mono font-bold"
                            >
                              {isEscalation ? 'ESCALATION' : isDowngrade ? 'DOWNGRADE' : 'DRIFT'}
                            </Badge>
                            {!alert.seen && (
                              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                            )}
                          </div>

                          <p className="text-xs text-[var(--text-primary)] leading-relaxed">
                            {alert.message}
                          </p>

                          <div className="flex items-center gap-2 text-[11px] text-[var(--text-tertiary)] font-mono pt-0.5">
                            <Clock className="w-3 h-3" />
                            <span>
                              {new Date(alert.created_at).toLocaleTimeString('en-US', {
                                hour: '2-digit',
                                minute: '2-digit',
                              })}
                            </span>
                            {alert.previous_scan_id && (
                              <>
                                <span>·</span>
                                <span>Prior: {alert.previous_scan_id}</span>
                              </>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                        {!alert.seen && (
                          <Button
                            variant="secondary"
                            size="xs"
                            onClick={() => handleMarkRead(alert.id)}
                            disabled={isMarking}
                            className="flex items-center gap-1"
                          >
                            <Check className="w-3 h-3" />
                            <span>{isMarking ? 'Updating...' : 'Mark Read'}</span>
                          </Button>
                        )}

                        <Button
                          variant="primary"
                          size="xs"
                          onClick={() => {
                            if (alert.previous_scan_id && alert.scan_id) {
                              navigate(`/compare/${alert.previous_scan_id}/${alert.scan_id}`);
                            } else {
                              navigate(`/scans/${alert.scan_id}`);
                            }
                          }}
                          className="flex items-center gap-1"
                        >
                          <GitCompare className="w-3 h-3" />
                          <span>View Diff</span>
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))
        ) : (
          <div className="p-8 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] text-center text-xs text-[var(--text-tertiary)] space-y-2">
            <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto" />
            <p>No alerts match the selected filter criteria.</p>
          </div>
        )}
      </div>
    </div>
  );
};
