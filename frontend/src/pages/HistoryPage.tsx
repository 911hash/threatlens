import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Search,
  Filter,
  ExternalLink,
  GitCompare,
  Clock,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Eye,
  FileCode,
  Globe,
  Binary,
  Layers,
  Bookmark,
  Download,
  Trash2,
  Sparkles,
  Sliders,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { api } from '../api/client';
import type { Scan, RiskLevel } from '../types/threat';
import { useDrawer } from '../context/DrawerContext';
import { useToast } from '../components/primitives/Toast';
import { DataTable } from '../components/primitives/DataTable';
import type { ColumnDef, SortState } from '../components/primitives/DataTable';
import { Button } from '../components/primitives/Button';
import { Badge } from '../components/primitives/Badge';
import { Input } from '../components/primitives/Input';
import { Slider } from '../components/primitives/Slider';
import { EmptyState } from '../components/primitives/EmptyState';
import { ErrorState } from '../components/primitives/ErrorState';
import { SeverityChip } from '../components/primitives/SeverityChip';
import { DefangText } from '../components/domain/DefangText';

export function InvestigationsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const drawer = useDrawer();
  const toast = useToast();

  const stateOverride = searchParams.get('state');

  // URL search params sync
  const activeType = searchParams.get('type') || 'all';
  const activeSeverity = searchParams.get('severity') || 'all';
  const activeSearch = searchParams.get('search') || '';
  const activeTime = searchParams.get('time') || 'all';
  const minScoreParam = Number(searchParams.get('minScore') || '0');
  const demoOnlyParam = searchParams.get('demo') === 'true';

  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters state
  const [searchQuery, setSearchQuery] = useState(activeSearch);
  const [severityFilter, setSeverityFilter] = useState<string>(activeSeverity);
  const [typeFilter, setTypeFilter] = useState<string>(activeType);
  const [timeFilter, setTimeFilter] = useState<string>(activeTime);
  const [minScore, setMinScore] = useState<number>(minScoreParam);
  const [demoOnly, setDemoOnly] = useState<boolean>(demoOnlyParam);

  // Sorting & Selection
  const [sortState, setSortState] = useState<SortState>({ columnId: 'timestamp', direction: 'desc' });
  const [selectedScanIds, setSelectedScanIds] = useState<string[]>([]);

  // Pagination
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Synchronize state with URL
  const updateUrlParams = (newParams: Record<string, string | null>) => {
    const params = new URLSearchParams(searchParams);
    Object.entries(newParams).forEach(([k, v]) => {
      if (v === null || v === 'all' || v === '' || v === '0') {
        params.delete(k);
      } else {
        params.set(k, v);
      }
    });
    setSearchParams(params, { replace: true });
  };

  useEffect(() => {
    loadScans();
  }, [typeFilter]);

  const loadScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getScans(typeFilter === 'all' ? undefined : typeFilter, 100);
      setScans(data);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve investigation records.');
    } finally {
      setLoading(false);
    }
  };

  // Filtered & Sorted Scans
  const filteredScans = useMemo(() => {
    let result = [...scans];

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (s) =>
          s.target.toLowerCase().includes(q) ||
          s.id.toLowerCase().includes(q) ||
          (s.explanation && s.explanation.toLowerCase().includes(q))
      );
    }

    if (severityFilter !== 'all') {
      const sevs = severityFilter.toLowerCase().split(',');
      result = result.filter((s) => sevs.includes(s.risk_level.toLowerCase()));
    }

    if (typeFilter !== 'all') {
      result = result.filter((s) => s.target_type === typeFilter);
    }

    if (minScore > 0) {
      result = result.filter((s) => s.risk_score >= minScore);
    }

    if (demoOnly) {
      result = result.filter((s) => s.is_demo);
    }

    if (timeFilter !== 'all') {
      const now = Date.now();
      const hours = timeFilter === '24h' ? 24 : timeFilter === '7d' ? 168 : 720;
      result = result.filter((s) => (now - new Date(s.timestamp).getTime()) / (1000 * 60 * 60) <= hours);
    }

    // Sort
    if (sortState.direction && sortState.columnId) {
      result.sort((a, b) => {
        let valA: any = (a as any)[sortState.columnId];
        let valB: any = (b as any)[sortState.columnId];
        if (sortState.columnId === 'timestamp') {
          valA = new Date(a.timestamp).getTime();
          valB = new Date(b.timestamp).getTime();
        }
        if (valA < valB) return sortState.direction === 'asc' ? -1 : 1;
        if (valA > valB) return sortState.direction === 'asc' ? 1 : -1;
        return 0;
      });
    }

    return result;
  }, [scans, searchQuery, severityFilter, typeFilter, minScore, demoOnly, timeFilter, sortState]);

  // Paginated data
  const totalPages = Math.ceil(filteredScans.length / pageSize) || 1;
  const paginatedScans = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredScans.slice(start, start + pageSize);
  }, [filteredScans, page, pageSize]);

  // Bulk actions
  const handleBulkAddToWatchlist = async () => {
    try {
      const selected = scans.filter((s) => selectedScanIds.includes(s.id));
      for (const item of selected) {
        await api.addToWatchlist(item.target, item.target_type);
      }
      toast.success(`Added ${selected.length} targets to active watchlist`);
      setSelectedScanIds([]);
    } catch (err: any) {
      toast.error(err.message || 'Failed to add targets to watchlist');
    }
  };

  const handleBulkCompare = () => {
    if (selectedScanIds.length >= 2) {
      navigate(`/compare/${selectedScanIds[0]}/${selectedScanIds[1]}`);
    } else {
      toast.info('Select at least 2 scans to compare evolution');
    }
  };

  const handleBulkExport = () => {
    const selected = scans.filter((s) => selectedScanIds.includes(s.id));
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(selected, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `threatlens_investigations_export.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    toast.success(`Exported ${selected.length} scan records`);
  };

  const openScanDrawer = (scan: Scan) => {
    drawer.open(
      <div className="space-y-5 text-xs text-[var(--text-secondary)]">
        <div>
          <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)] tracking-wider">
            Investigation Snapshot
          </span>
          <h3 className="text-base font-bold text-[var(--text-primary)] mt-1 flex items-center gap-2">
            <span className="font-mono text-sm">{scan.id}</span>
            <SeverityChip severity={scan.risk_level} score={scan.risk_score} size="xs" />
          </h3>
        </div>

        <div className="p-3 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1">
          <span className="text-[10px] font-mono uppercase text-[var(--text-tertiary)]">
            Indicator Target ({scan.target_type.toUpperCase()})
          </span>
          <div className="font-mono text-xs text-[var(--text-primary)] break-all">
            <DefangText value={scan.target} showCopy={true} />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2.5">
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Risk Score</span>
            <div className="font-mono font-bold text-sm text-[var(--text-primary)] mt-0.5">
              {scan.risk_score} / 100
            </div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Confidence</span>
            <div className="font-mono font-bold text-sm text-[var(--text-primary)] mt-0.5">
              {scan.confidence}%
            </div>
          </div>
        </div>

        <div className="p-3 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-subtle)] space-y-1">
          <div className="font-semibold text-[var(--text-primary)]">Assessment</div>
          <p className="leading-relaxed">{scan.explanation}</p>
        </div>

        <div>
          <div className="font-semibold text-[var(--text-primary)] mb-2">Contributing Factors</div>
          <div className="space-y-1.5">
            {scan.factors.slice(0, 4).map((f) => (
              <div
                key={f.id}
                className="p-2 rounded border border-[var(--border-subtle)] bg-[var(--bg-panel)] flex items-center justify-between text-[11px]"
              >
                <span className="truncate pr-2">{f.title}</span>
                <span className="font-mono font-bold text-[var(--text-primary)] shrink-0">
                  {f.points > 0 ? `+${f.points}` : f.points} pts
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>,
      {
        title: `Investigation ${scan.id}`,
        fullPageAction: (
          <Button
            variant="primary"
            size="xs"
            onClick={() => {
              drawer.close();
              navigate(`/scans/${scan.id}`);
            }}
          >
            Open Full Report
          </Button>
        ),
      }
    );
  };

  // Columns definition for DataTable
  const columns: ColumnDef<Scan>[] = useMemo(
    () => [
      {
        id: 'severity',
        header: 'Verdict',
        width: 140,
        sortable: true,
        cell: (row) => (
          <SeverityChip severity={row.risk_level} score={row.risk_score} size="xs" />
        ),
      },
      {
        id: 'target',
        header: 'Target Indicator',
        width: 320,
        minWidth: 180,
        sortable: true,
        cell: (row) => (
          <div className="font-mono text-xs truncate" title={row.target}>
            <DefangText value={row.target} showCopy={true} />
          </div>
        ),
      },
      {
        id: 'target_type',
        header: 'Type',
        width: 90,
        sortable: true,
        cell: (row) => (
          <Badge variant="neutral" size="xs" className="uppercase font-mono">
            {row.target_type}
          </Badge>
        ),
      },
      {
        id: 'confidence',
        header: 'Confidence',
        width: 110,
        sortable: true,
        cell: (row) => (
          <span className="font-mono text-xs tabular-nums text-[var(--text-secondary)]">
            {row.confidence}%
          </span>
        ),
      },
      {
        id: 'detection_count',
        header: 'Sources',
        width: 100,
        sortable: true,
        cell: (row) => (
          <span className="font-mono text-xs text-[var(--text-secondary)]">
            {row.detection_count} / {row.total_engines || 7}
          </span>
        ),
      },
      {
        id: 'timestamp',
        header: 'Scanned At',
        width: 150,
        sortable: true,
        cell: (row) => (
          <span className="text-[11px] text-[var(--text-tertiary)] font-mono">
            {new Date(row.timestamp).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            })}
          </span>
        ),
      },
      {
        id: 'actions',
        header: 'Report',
        width: 90,
        enableResizing: false,
        enableHiding: false,
        cell: (row) => (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              navigate(`/scans/${row.id}`);
            }}
            className="p-1 rounded text-blue-400 hover:text-blue-300 hover:bg-[var(--bg-inset)] transition-colors flex items-center gap-1 text-[11px] font-medium"
          >
            <span>Open</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        ),
      },
    ],
    [navigate]
  );

  // State Matrix Overrides
  if (stateOverride === 'loading') {
    return (
      <div className="max-w-7xl mx-auto py-8 px-4 space-y-6">
        <div className="flex justify-between items-center">
          <div className="w-48 h-8 rounded bg-[var(--bg-panel)] animate-pulse" />
          <div className="w-32 h-8 rounded bg-[var(--bg-panel)] animate-pulse" />
        </div>
        <div className="h-96 rounded-2xl bg-[var(--bg-panel)] border border-[var(--border-subtle)] animate-pulse" />
      </div>
    );
  }

  if (stateOverride === 'error') {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4">
        <ErrorState
          title="Investigations Engine Failed"
          message="Simulated error: unable to load investigation records."
          onRetry={loadScans}
        />
      </div>
    );
  }

  if (stateOverride === 'empty') {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4">
        <EmptyState
          title="No Investigation Records"
          description="Simulated empty state. Start by analyzing a target or load the seeded demo intelligence dataset."
          action={
            <Button variant="primary" size="sm" onClick={() => navigate('/analyze/url')}>
              Analyze Indicator
            </Button>
          }
        />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto py-8 px-4 space-y-6 pb-16 animate-in fade-in duration-150">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2">
            <span>Security Investigations History</span>
            <span className="text-xs font-mono font-normal text-[var(--text-tertiary)]">
              ({filteredScans.length} records)
            </span>
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Query, filter, and compare historical threat telemetry snapshots across all correlated assets.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadScans}
            className="flex items-center gap-1.5"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate('/analyze/url')}
          >
            New Scan
          </Button>
        </div>
      </div>

      {/* FILTER BAR */}
      <div className="p-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
          {/* Search Input */}
          <div className="relative">
            <input
              type="text"
              aria-label="Search investigations by indicator or domain"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                updateUrlParams({ search: e.target.value });
              }}
              placeholder="Search indicators, IDs, domains..."
              className="w-full pl-9 pr-3 py-2 text-xs font-mono rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            <Search className="w-3.5 h-3.5 text-[var(--text-tertiary)] absolute left-3 top-2.5 pointer-events-none" />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            aria-label="Filter investigations by severity"
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              updateUrlParams({ severity: e.target.value });
            }}
            className="px-3 py-2 text-xs rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="high,critical">High & Critical</option>
            <option value="medium">Medium Only</option>
            <option value="low">Low Only</option>
            <option value="safe">Safe Only</option>
          </select>

          {/* Target Type Filter */}
          <select
            value={typeFilter}
            aria-label="Filter investigations by target type"
            onChange={(e) => {
              setTypeFilter(e.target.value);
              updateUrlParams({ type: e.target.value });
            }}
            className="px-3 py-2 text-xs rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer"
          >
            <option value="all">All Indicator Types</option>
            <option value="url">URLs Only</option>
            <option value="hash">File Hashes Only</option>
            <option value="file">Files Only</option>
          </select>

          {/* Time Window Filter */}
          <select
            value={timeFilter}
            aria-label="Filter investigations by time window"
            onChange={(e) => {
              setTimeFilter(e.target.value);
              updateUrlParams({ time: e.target.value });
            }}
            className="px-3 py-2 text-xs rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer"
          >
            <option value="all">All Time</option>
            <option value="24h">Past 24 Hours</option>
            <option value="7d">Past 7 Days</option>
            <option value="30d">Past 30 Days</option>
          </select>
        </div>

        {/* Secondary filters row (Min score slider & demo toggle) */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-2 border-t border-[var(--border-subtle)]">
          <div className="flex items-center gap-4 flex-1 max-w-sm">
            <span className="text-[11px] text-[var(--text-tertiary)] font-mono shrink-0">
              Min Risk Score: {minScore}
            </span>
            <Slider
              value={minScore}
              min={0}
              max={100}
              step={5}
              onChange={(val) => {
                setMinScore(val);
                updateUrlParams({ minScore: val > 0 ? String(val) : null });
              }}
            />
          </div>

          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={demoOnly}
                onChange={(e) => {
                  setDemoOnly(e.target.checked);
                  updateUrlParams({ demo: e.target.checked ? 'true' : null });
                }}
                className="rounded border-[var(--border-subtle)] text-blue-600 focus:ring-0"
              />
              <span>Demo data only</span>
            </label>

            {(searchQuery || severityFilter !== 'all' || typeFilter !== 'all' || timeFilter !== 'all' || minScore > 0 || demoOnly) && (
              <button
                type="button"
                onClick={() => {
                  setSearchQuery('');
                  setSeverityFilter('all');
                  setTypeFilter('all');
                  setTimeFilter('all');
                  setMinScore(0);
                  setDemoOnly(false);
                  setSearchParams(new URLSearchParams());
                }}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium cursor-pointer"
              >
                Reset filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* BULK ACTION BAR (Visible when items selected) */}
      {selectedScanIds.length > 0 && (
        <div className="p-3 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-between gap-3 animate-in fade-in duration-100">
          <div className="flex items-center gap-2 text-xs text-blue-400 font-medium">
            <CheckCircle2 className="w-4 h-4" />
            <span>{selectedScanIds.length} investigations selected</span>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="xs"
              onClick={handleBulkAddToWatchlist}
              className="flex items-center gap-1.5"
            >
              <Bookmark className="w-3.5 h-3.5" />
              <span>Add to Watchlist</span>
            </Button>

            <Button
              variant="secondary"
              size="xs"
              onClick={handleBulkCompare}
              disabled={selectedScanIds.length < 2}
              className="flex items-center gap-1.5"
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>Compare Scans</span>
            </Button>

            <Button
              variant="secondary"
              size="xs"
              onClick={handleBulkExport}
              className="flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </Button>
          </div>
        </div>
      )}

      {/* DATA TABLE */}
      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] overflow-hidden shadow-xs">
        <DataTable<Scan>
          data={paginatedScans}
          columns={columns}
          rowKey={(s) => s.id}
          selectable={true}
          selectedRowKeys={selectedScanIds}
          onSelectedRowKeysChange={setSelectedScanIds}
          onRowClick={(row) => openScanDrawer(row)}
          sortState={sortState}
          onSortChange={setSortState}
          isLoading={loading}
          maxHeight="650px"
          emptyState={
            <div className="py-12 px-4 text-center space-y-3">
              <Layers className="w-8 h-8 text-[var(--text-tertiary)] mx-auto" />
              <div className="text-sm font-bold text-[var(--text-primary)]">
                No matching investigations found
              </div>
              <p className="text-xs text-[var(--text-secondary)] max-w-sm mx-auto">
                No scan records match the current filter criteria. Try broadening your filters or run a new scan.
              </p>
            </div>
          }
        />

        {/* Pagination Footer */}
        <div className="p-3 border-t border-[var(--border-subtle)] bg-[var(--bg-inset)] flex items-center justify-between text-xs text-[var(--text-secondary)]">
          <div className="flex items-center gap-2">
            <span>Page size:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="px-2 py-0.5 rounded bg-[var(--bg-panel)] border border-[var(--border-subtle)] text-[var(--text-primary)] cursor-pointer"
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
            <span className="font-mono text-[11px] text-[var(--text-tertiary)]">
              Showing {(page - 1) * pageSize + 1} - {Math.min(page * pageSize, filteredScans.length)} of {filteredScans.length}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="xs"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </Button>
            <span className="font-mono text-[11px]">
              Page {page} of {totalPages}
            </span>
            <Button
              variant="secondary"
              size="xs"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export const HistoryPage = InvestigationsPage;
