import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Bookmark,
  Bell,
  Plus,
  RotateCcw,
  Trash2,
  ExternalLink,
  GitCompare,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ShieldAlert,
  TrendingUp,
  TrendingDown,
  Minus,
  LayoutGrid,
  Table as TableIcon,
  Search,
  Sparkles,
  ArrowRight,
  ChevronRight,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../api/client';
import type { WatchlistItem, RiskLevel } from '../types/threat';
import { useDrawer } from '../context/DrawerContext';
import { useLocalStorage } from '../hooks/useLocalStorage';
import { useToast } from '../components/primitives/Toast';
import { Button } from '../components/primitives/Button';
import { Badge } from '../components/primitives/Badge';
import { Modal } from '../components/primitives/Modal';
import { Input } from '../components/primitives/Input';
import { EmptyState } from '../components/primitives/EmptyState';
import { ErrorState } from '../components/primitives/ErrorState';
import { Skeleton } from '../components/primitives/Skeleton';
import { SeverityChip } from '../components/primitives/SeverityChip';
import { DefangText } from '../components/domain/DefangText';
import { TimelineDrift } from '../components/domain/TimelineDrift';

export function WatchlistPage() {
  const navigate = useNavigate();
  const drawer = useDrawer();
  const toast = useToast();
  const [searchParams] = useSearchParams();
  const stateOverride = searchParams.get('state');

  const [watchlist, setWatchlist] = useState<WatchlistItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // View toggle: 'grid' | 'table'
  const [viewMode, setViewMode] = useLocalStorage<'grid' | 'table'>('threatlens_watchlist_view', 'grid');
  const [searchQuery, setSearchQuery] = useState('');

  // Add target modal state
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [newTarget, setNewTarget] = useState('');
  const [newTargetType, setNewTargetType] = useState<'url' | 'hash'>('url');
  const [isAdding, setIsAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  // Rescan tracking
  const [rescanningId, setRescanningId] = useState<string | null>(null);

  useEffect(() => {
    loadWatchlist();
  }, []);

  const loadWatchlist = async () => {
    setLoading(true);
    setError(null);
    try {
      const items = await api.getWatchlist();
      const normalized = (items || []).map((w: any) => ({
        ...w,
        current_score: typeof w.current_score === 'number' ? w.current_score : (w.last_score ?? 0),
        current_level: w.current_level || w.last_level || 'LOW',
        last_scanned: w.last_scanned || w.last_scanned_at || w.added_at || new Date().toISOString(),
      }));
      setWatchlist(normalized);
    } catch (err: any) {
      setError(err.message || 'Failed to load watchlist targets.');
    } finally {
      setLoading(false);
    }
  };

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = newTarget.trim();
    if (!clean) return;

    try {
      setIsAdding(true);
      setAddError(null);
      await api.addToWatchlist(clean, newTargetType);
      toast.success(`Target added to active watchlist`, 'Watchlist Updated');
      setNewTarget('');
      setIsAddModalOpen(false);
      await loadWatchlist();
    } catch (err: any) {
      setAddError(err.message || 'Failed to add target to watchlist.');
    } finally {
      setIsAdding(false);
    }
  };

  const handleDelete = async (id: string, targetName: string) => {
    try {
      await api.deleteFromWatchlist(id);
      setWatchlist((prev) => prev.filter((item) => item.id !== id));
      toast.info(`Removed ${targetName} from watchlist`);
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete target');
    }
  };

  const handleRescan = async (item: WatchlistItem) => {
    try {
      setRescanningId(item.id);
      const res = await api.rescanWatchlistItem(item.id);

      // Optimistically update the item in local state
      setWatchlist((prev) =>
        prev.map((w) =>
          w.id === item.id
            ? {
                ...w,
                previous_score: w.current_score,
                current_score: res.score,
                current_level: res.level as RiskLevel,
                last_scan_id: res.scan_id,
                last_scanned: new Date().toISOString(),
              }
            : w
        )
      );

      toast.success(
        `Rescanned ${item.target}: Score is now ${res.score} (${res.level})`,
        'Watchlist Drift Evaluated'
      );
    } catch (err: any) {
      toast.error(err.message || 'Failed to rescan target');
    } finally {
      setRescanningId(null);
    }
  };

  const openItemDrawer = (item: WatchlistItem) => {
    const delta = item.previous_score !== undefined ? item.current_score - item.previous_score : 0;

    drawer.open(
      <div className="space-y-5 text-xs text-[var(--text-secondary)]">
        <div>
          <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)] tracking-wider">
            Watchlist Target Telemetry
          </span>
          <h3 className="text-base font-bold text-[var(--text-primary)] mt-1 flex items-center gap-2">
            <span className="font-mono text-sm">{item.id}</span>
            <SeverityChip severity={item.current_level} score={item.current_score} size="xs" />
          </h3>
        </div>

        <div className="p-3 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1">
          <span className="text-[10px] font-mono uppercase text-[var(--text-tertiary)]">
            Monitored Target ({item.target_type.toUpperCase()})
          </span>
          <div className="font-mono text-xs text-[var(--text-primary)] break-all">
            <DefangText value={item.target} showCopy={true} />
          </div>
        </div>

        {/* Drift Timeline Sparkline */}
        <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-[var(--text-primary)]">Score Evolution Drift</span>
            <TimelineDrift
              currentScore={item.current_score}
              previousScore={item.previous_score}
              width={90}
              height={24}
            />
          </div>
          <p className="text-[11px] text-[var(--text-secondary)]">
            {delta > 0
              ? `Score escalated by +${delta} points on most recent automated check.`
              : delta < 0
              ? `Score improved by ${delta} points on most recent check.`
              : `Verdict is stable without recent score movement.`}
          </p>
        </div>

        <div className="grid grid-cols-2 gap-2.5">
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Monitoring Cadence</span>
            <div className="font-mono font-bold text-xs text-[var(--text-primary)] mt-0.5">
              Every {item.interval_hours || 6} hours
            </div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Last Verification</span>
            <div className="font-mono text-xs text-[var(--text-primary)] mt-0.5 truncate">
              {new Date(item.last_scanned).toLocaleDateString()}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 pt-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleRescan(item)}
            disabled={rescanningId === item.id}
            className="flex-1 flex items-center justify-center gap-1.5"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${rescanningId === item.id ? 'animate-spin' : ''}`} />
            <span>{rescanningId === item.id ? 'Rescanning...' : 'Rescan Now'}</span>
          </Button>

          {item.last_scan_id && (
            <Button
              variant="primary"
              size="sm"
              onClick={() => {
                drawer.close();
                navigate(`/scans/${item.last_scan_id}`);
              }}
              className="flex-1 flex items-center justify-center gap-1.5"
            >
              <span>View Report</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </Button>
          )}
        </div>
      </div>,
      {
        title: `Watchlist Target`,
      }
    );
  };

  // Filtered watchlist
  const filteredItems = watchlist.filter((item) =>
    item.target.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Compute countdown helper
  const getNextScanCountdown = (lastScanned: string, intervalHours = 6) => {
    const nextMs = new Date(lastScanned).getTime() + intervalHours * 3600 * 1000;
    const diffHours = Math.max(0, Math.round((nextMs - Date.now()) / (3600 * 1000)));
    return diffHours > 0 ? `In ${diffHours}h` : 'Due soon';
  };

  // State Matrix Overrides
  if (stateOverride === 'loading' || (loading && watchlist.length === 0)) {
    return (
      <div className="max-w-7xl mx-auto py-8 px-4 space-y-6">
        <div className="flex justify-between items-center">
          <Skeleton className="w-48 h-8 rounded-lg" />
          <Skeleton className="w-32 h-8 rounded-lg" />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <Skeleton key={i} className="h-44 rounded-2xl" />
          ))}
        </div>
      </div>
    );
  }

  if (stateOverride === 'error' || (error && watchlist.length === 0)) {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4">
        <ErrorState
          title="Failed to Load Watchlist"
          message={error || 'Unable to retrieve monitored targets from backend.'}
          onRetry={loadWatchlist}
        />
      </div>
    );
  }

  if (stateOverride === 'empty' || watchlist.length === 0) {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4 space-y-6 animate-in fade-in duration-200">
        <EmptyState
          title="No Targets Under Active Watch"
          description="ThreatLens will re-check these on a schedule and tell you the moment the verdict changes."
          action={
            <Button
              variant="primary"
              size="md"
              onClick={() => setIsAddModalOpen(true)}
              className="flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              <span>Add First Target</span>
            </Button>
          }
        />

        {/* Modal for adding target */}
        <Modal
          isOpen={isAddModalOpen}
          onClose={() => setIsAddModalOpen(false)}
          title="Add Target to Continuous Watchlist"
          description="ThreatLens will monitor this indicator and trigger drift alerts on verdict changes."
        >
          <form onSubmit={handleAddTarget} className="space-y-4 py-2">
            <div>
              <label className="text-xs font-semibold text-[var(--text-primary)] block mb-1">
                Indicator Target
              </label>
              <Input
                value={newTarget}
                onChange={(e) => setNewTarget(e.target.value)}
                placeholder="https://example.com/login or file hash..."
                className="font-mono text-xs"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-[var(--text-primary)] block mb-1">
                Indicator Type
              </label>
              <select
                value={newTargetType}
                onChange={(e) => setNewTargetType(e.target.value as any)}
                aria-label="Indicator Type"
                className="w-full p-2 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-xs text-[var(--text-primary)]"
              >
                <option value="url">URL / Domain</option>
                <option value="hash">File Hash</option>
              </select>
            </div>
            {addError && <p className="text-xs text-red-500">{addError}</p>}
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" size="sm" type="button" onClick={() => setIsAddModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="primary" size="sm" type="submit" disabled={isAdding || !newTarget.trim()}>
                {isAdding ? 'Adding...' : 'Add to Watchlist'}
              </Button>
            </div>
          </form>
        </Modal>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto py-8 px-4 space-y-6 pb-16 animate-in fade-in duration-150">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Bookmark className="w-6 h-6 text-blue-400" />
            <span>Continuous Threat Watchlist</span>
            <span className="text-xs font-mono font-normal text-[var(--text-tertiary)]">
              ({watchlist.length} targets)
            </span>
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Automated background re-analysis tracking infrastructure drift, new blacklist listings, and hop evolution.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* View Mode Toggle: Grid vs Table */}
          <div className="flex items-center rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-panel)] p-0.5">
            <button
              type="button"
              onClick={() => setViewMode('grid')}
              aria-label="Grid view"
              className={`p-1.5 rounded-md text-xs transition-colors ${
                viewMode === 'grid'
                  ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)] shadow-xs'
                  : 'text-[var(--text-tertiary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <LayoutGrid className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={() => setViewMode('table')}
              aria-label="Table view"
              className={`p-1.5 rounded-md text-xs transition-colors ${
                viewMode === 'table'
                  ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)] shadow-xs'
                  : 'text-[var(--text-tertiary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <TableIcon className="w-4 h-4" />
            </button>
          </div>

          <Button
            variant="primary"
            size="sm"
            onClick={() => setIsAddModalOpen(true)}
            className="flex items-center gap-1.5"
          >
            <Plus className="w-4 h-4" />
            <span>Add Target</span>
          </Button>
        </div>
      </div>

      {/* Filter / Search Bar */}
      <div className="p-3.5 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] flex items-center justify-between gap-4">
        <div className="relative flex-1 max-w-sm">
          <input
            type="text"
            aria-label="Filter watchlist targets by indicator or note"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter watchlist targets..."
            className="w-full pl-9 pr-3 py-2 text-xs font-mono rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
          <Search className="w-3.5 h-3.5 text-[var(--text-tertiary)] absolute left-3 top-2.5 pointer-events-none" />
        </div>

        <div className="text-xs text-[var(--text-secondary)] font-mono">
          <span>Cadence: Every 6h</span>
        </div>
      </div>

      {/* VIEW: CARD GRID */}
      {viewMode === 'grid' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredItems.map((item) => {
            const delta = item.previous_score !== undefined ? item.current_score - item.previous_score : 0;
            const hasDrift = delta !== 0 || item.unread_drift;

            return (
              <div
                key={item.id}
                role="button"
                tabIndex={0}
                onClick={() => openItemDrawer(item)}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && openItemDrawer(item)}
                className="p-5 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] hover:border-blue-500/50 hover:bg-[var(--bg-elevated)] transition-all cursor-pointer flex flex-col justify-between group space-y-4"
              >
                {/* Card Top */}
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <SeverityChip severity={item.current_level} score={item.current_score} size="xs" />
                      <Badge variant="neutral" size="xs" className="uppercase font-mono">
                        {item.target_type}
                      </Badge>
                    </div>

                    {hasDrift && (
                      <Badge variant="warning" size="xs">
                        Drift Detected
                      </Badge>
                    )}
                  </div>

                  <div className="font-mono text-xs font-semibold text-[var(--text-primary)] truncate">
                    <DefangText value={item.target} showCopy={true} />
                  </div>
                </div>

                {/* Score & Drift sparkline preview */}
                <div className="p-3 rounded-xl bg-[var(--bg-inset)] border border-[var(--border-subtle)] flex items-center justify-between">
                  <div>
                    <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Risk Score</span>
                    <div className="font-mono text-sm font-bold text-[var(--text-primary)] flex items-center gap-1 mt-0.5">
                      <span>{item.current_score}</span>
                      {delta > 0 ? (
                        <span className="text-red-400 text-xs flex items-center">
                          <TrendingUp className="w-3 h-3" /> +{delta}
                        </span>
                      ) : delta < 0 ? (
                        <span className="text-emerald-400 text-xs flex items-center">
                          <TrendingDown className="w-3 h-3" /> {delta}
                        </span>
                      ) : (
                        <span className="text-[var(--text-tertiary)] text-xs flex items-center">
                          <Minus className="w-3 h-3" /> 0
                        </span>
                      )}
                    </div>
                  </div>

                  <TimelineDrift
                    currentScore={item.current_score}
                    previousScore={item.previous_score}
                    width={70}
                    height={20}
                  />
                </div>

                {/* Card Footer: Metadata & Actions */}
                <div className="pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px] text-[var(--text-tertiary)]">
                  <div className="flex items-center gap-1 font-mono">
                    <Clock className="w-3 h-3" />
                    <span>Next: {getNextScanCountdown(item.last_scanned, item.interval_hours)}</span>
                  </div>

                  <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                    <button
                      type="button"
                      onClick={() => handleRescan(item)}
                      disabled={rescanningId === item.id}
                      aria-label="Rescan target"
                      className="p-1.5 rounded-lg text-blue-400 hover:text-blue-300 hover:bg-[var(--bg-inset)] transition-colors cursor-pointer"
                    >
                      <RotateCcw className={`w-3.5 h-3.5 ${rescanningId === item.id ? 'animate-spin' : ''}`} />
                    </button>

                    <button
                      type="button"
                      onClick={() => handleDelete(item.id, item.target)}
                      aria-label="Delete target"
                      className="p-1.5 rounded-lg text-red-400 hover:text-red-300 hover:bg-[var(--bg-inset)] transition-colors cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* VIEW: TABLE */
        <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] overflow-hidden shadow-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[var(--border-strong)] bg-[var(--bg-inset)]/60 text-[var(--text-secondary)] font-mono text-[11px] uppercase">
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Indicator Target</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Drift Trend</th>
                  <th className="py-2.5 px-3">Cadence</th>
                  <th className="py-2.5 px-3">Last Checked</th>
                  <th className="py-2.5 px-3">Next Check</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)] font-mono">
                {filteredItems.map((item) => {
                  const delta = item.previous_score !== undefined ? item.current_score - item.previous_score : 0;
                  return (
                    <tr
                      key={item.id}
                      onClick={() => openItemDrawer(item)}
                      className="hover:bg-[var(--bg-elevated)] transition-colors cursor-pointer group"
                    >
                      <td className="py-3 px-3">
                        <SeverityChip severity={item.current_level} score={item.current_score} size="xs" />
                      </td>
                      <td className="py-3 px-3 font-semibold text-[var(--text-primary)] max-w-xs truncate">
                        <DefangText value={item.target} showCopy={true} />
                      </td>
                      <td className="py-3 px-3 uppercase text-[var(--text-tertiary)]">
                        {item.target_type}
                      </td>
                      <td className="py-3 px-3">
                        <TimelineDrift
                          currentScore={item.current_score}
                          previousScore={item.previous_score}
                          width={60}
                          height={18}
                        />
                      </td>
                      <td className="py-3 px-3 text-[var(--text-secondary)]">
                        Every {item.interval_hours || 6}h
                      </td>
                      <td className="py-3 px-3 text-[var(--text-tertiary)] text-[11px]">
                        {new Date(item.last_scanned).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-3 text-blue-400 text-[11px]">
                        {getNextScanCountdown(item.last_scanned, item.interval_hours)}
                      </td>
                      <td className="py-3 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          <button
                            type="button"
                            onClick={() => handleRescan(item)}
                            disabled={rescanningId === item.id}
                            className="p-1 rounded text-blue-400 hover:text-blue-300"
                            title="Rescan"
                          >
                            <RotateCcw className={`w-3.5 h-3.5 ${rescanningId === item.id ? 'animate-spin' : ''}`} />
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDelete(item.id, item.target)}
                            className="p-1 rounded text-red-400 hover:text-red-300"
                            title="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal for adding target */}
      <Modal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        title="Add Target to Continuous Watchlist"
        description="ThreatLens will monitor this indicator and trigger drift alerts on verdict changes."
      >
        <form onSubmit={handleAddTarget} className="space-y-4 py-2">
          <div>
            <label className="text-xs font-semibold text-[var(--text-primary)] block mb-1">
              Indicator Target
            </label>
            <Input
              value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)}
              placeholder="https://example.com/login or file hash..."
              className="font-mono text-xs"
            />
          </div>
          <div>
            <label className="text-xs font-semibold text-[var(--text-primary)] block mb-1">
              Indicator Type
            </label>
            <select
              value={newTargetType}
              onChange={(e) => setNewTargetType(e.target.value as any)}
              aria-label="Indicator Type"
              className="w-full p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-xs text-[var(--text-primary)]"
            >
              <option value="url">URL / Domain</option>
              <option value="hash">File Hash</option>
            </select>
          </div>
          {addError && <p className="text-xs text-red-500">{addError}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" size="sm" type="button" onClick={() => setIsAddModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" size="sm" type="submit" disabled={isAdding || !newTarget.trim()}>
              {isAdding ? 'Adding...' : 'Add to Watchlist'}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
