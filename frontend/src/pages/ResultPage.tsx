import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Sparkles,
  Terminal,
  Clock,
  RotateCcw,
  AlertTriangle,
  ArrowLeft,
} from 'lucide-react';
import { api } from '../api/client';
import type { Scan, HealthStatus, WatchlistItem } from '../types/threat';
import { useLocalStorage } from '../hooks/useLocalStorage';
import { useToast } from '../components/primitives/Toast';
import { SegmentedControl, type SegmentedControlOption } from '../components/primitives/SegmentedControl';
import { EmptyState } from '../components/primitives/EmptyState';
import { ErrorState } from '../components/primitives/ErrorState';
import { Skeleton } from '../components/primitives/Skeleton';
import { Button } from '../components/primitives/Button';

// Flagship report components
import { VerdictHeader } from '../components/VerdictHeader';
import { ExplainSimplyCard } from '../components/ExplainSimplyCard';
import { ScoreBreakdownBar } from '../components/ScoreBreakdownBar';
import { FactorsList } from '../components/FactorsList';
import { SourceCardGrid } from '../components/SourceCardGrid';
import { AttackChainGraph } from '../components/AttackChainGraph';
import { TemporalSparkline } from '../components/TemporalSparkline';
import { RawJsonViewer } from '../components/RawJsonViewer';

export const ResultPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const toast = useToast();

  // Primary data states
  const [scan, setScan] = useState<Scan | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Health and source key configuration
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [isLoadingSources, setIsLoadingSources] = useState(true);

  // Watchlist & history states
  const [watchlist, setWatchlist] = useState<WatchlistItem[]>([]);
  const [historyScans, setHistoryScans] = useState<Scan[]>([]);
  const [prevScanId, setPrevScanId] = useState<string | null>(null);
  const [isFirstScan, setIsFirstScan] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [isRescanning, setIsRescanning] = useState(false);

  // View mode toggle: 'plain' (default) | 'technical', persisted via useLocalStorage
  const [viewMode, setViewMode] = useLocalStorage<'plain' | 'technical'>(
    'threatlens_report_view',
    'plain'
  );

  // Score breakdown hover state to highlight matching factor rows
  const [hoveredGroup, setHoveredGroup] = useState<string | null>(null);

  // Load report data with parallel network requests
  const loadReportData = useCallback(async () => {
    if (!id) return;
    setIsLoading(true);
    setError(null);
    setHistoryError(null);

    try {
      // Fire parallel requests per acceptance criteria (3+ in flight simultaneously)
      const [scanRes, healthRes, watchlistRes] = await Promise.all([
        api.getScan(id),
        api.getHealth().catch(() => null),
        api.getWatchlist().catch(() => []),
      ]);

      setScan(scanRes);
      if (healthRes) setHealth(healthRes);
      if (watchlistRes) setWatchlist(watchlistRes);

      // Stagger source card skeleton resolution subtly to showcase independent streams
      setTimeout(() => {
        setIsLoadingSources(false);
      }, 350);

      // Immediately fetch historical scans and drift context for target
      if (scanRes.previous_scan_id) {
        setPrevScanId(scanRes.previous_scan_id);
        setIsFirstScan(false);
      }

      try {
        const hist = await api.getTargetHistory(scanRes.target);
        if (hist && Array.isArray(hist.scans)) {
          setHistoryScans(hist.scans);
          const earlier = hist.scans.filter(
            (s) => s.target === scanRes.target && new Date(s.timestamp).getTime() < new Date(scanRes.timestamp).getTime()
          );

          if (earlier.length > 0) {
            earlier.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
            setPrevScanId(earlier[0].id);
            setIsFirstScan(false);
          } else {
            setIsFirstScan(true);
            if (!scanRes.previous_scan_id) setPrevScanId(null);
          }
        }
      } catch (hErr: any) {
        setHistoryError(hErr.message || 'Could not load target scan history.');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load investigation scan.');
    } finally {
      setIsLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadReportData();
  }, [loadReportData]);

  // Handle Watchlist toggle
  const isWatchlisted = Boolean(scan && watchlist.some((w) => w.target === scan.target));

  const handleToggleWatchlist = async () => {
    if (!scan) return;
    try {
      if (isWatchlisted) {
        const item = watchlist.find((w) => w.target === scan.target);
        if (item) {
          await api.deleteFromWatchlist(item.id);
          setWatchlist((prev) => prev.filter((w) => w.id !== item.id));
          toast.info('Removed target from watchlist', 'Watchlist Updated');
        }
      } else {
        const added = await api.addToWatchlist(scan.target, scan.target_type);
        setWatchlist((prev) => [...prev, added]);
        toast.success('Target added to surveillance watchlist', 'Watchlist Updated');
      }
    } catch (err: any) {
      toast.error(err.message || 'Failed to update watchlist');
    }
  };

  // Handle Re-scan action
  const handleRescan = async () => {
    if (!scan) return;
    try {
      setIsRescanning(true);
      toast.info(`Initiating re-analysis for ${scan.target}...`);
      let freshScan: Scan;
      if (scan.target_type === 'url') {
        freshScan = await api.analyzeUrl(scan.target, true);
      } else {
        freshScan = await api.analyzeHash(scan.target);
      }
      toast.success('Re-scan completed with updated intelligence');
      navigate(`/scans/${freshScan.id}`);
    } catch (err: any) {
      toast.error(err.message || 'Re-scan failed');
    } finally {
      setIsRescanning(false);
    }
  };

  // Stale status check: older than 12 hours
  const isStale = React.useMemo(() => {
    if (!scan) return false;
    const diffHours = (Date.now() - new Date(scan.timestamp).getTime()) / (1000 * 60 * 60);
    return diffHours > 12;
  }, [scan]);

  // Loading Skeleton State
  if (isLoading && !scan) {
    return (
      <div className="space-y-6 max-w-7xl mx-auto pb-12 animate-in fade-in duration-150">
        <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] flex flex-col md:flex-row items-center gap-6">
          <Skeleton className="w-32 h-32 rounded-2xl shrink-0" />
          <div className="space-y-3 flex-1 w-full">
            <div className="flex gap-2">
              <Skeleton className="w-24 h-6 rounded-full" />
              <Skeleton className="w-16 h-6 rounded-full" />
            </div>
            <Skeleton className="w-3/4 h-8 rounded-lg" />
            <Skeleton className="w-1/2 h-4 rounded" />
          </div>
          <div className="flex gap-2 shrink-0">
            <Skeleton className="w-20 h-8 rounded-md" />
            <Skeleton className="w-28 h-8 rounded-md" />
          </div>
        </div>
        <div className="flex justify-between items-center">
          <Skeleton className="w-48 h-8 rounded-md" />
          <Skeleton className="w-32 h-6 rounded" />
        </div>
        <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
          <Skeleton className="w-1/3 h-5 rounded" />
          <Skeleton className="w-full h-16 rounded-xl" />
          <Skeleton className="w-full h-24 rounded-xl" />
        </div>
      </div>
    );
  }

  // Error State
  if (error && !scan) {
    return (
      <div className="max-w-2xl mx-auto py-12">
        <ErrorState
          title="Failed to Load Investigation Report"
          message={error}
          onRetry={loadReportData}
        />
        <div className="mt-4 text-center">
          <Button variant="secondary" size="sm" onClick={() => navigate('/scans')}>
            <ArrowLeft className="w-4 h-4 mr-1.5" />
            Back to Investigations
          </Button>
        </div>
      </div>
    );
  }

  // Empty State
  if (!scan) {
    return (
      <div className="max-w-2xl mx-auto py-12">
        <EmptyState
          title="Investigation Report Not Found"
          description="The requested scan record does not exist or may have been pruned."
          action={
            <Button variant="primary" size="sm" onClick={() => navigate('/analyze')}>
              Run New Analysis
            </Button>
          }
        />
      </div>
    );
  }

  const viewOptions: SegmentedControlOption<'plain' | 'technical'>[] = [
    {
      value: 'plain',
      label: 'Plain English',
      icon: <Sparkles className="w-3.5 h-3.5 text-blue-400" />,
    },
    {
      value: 'technical',
      label: 'Technical Evidence',
      icon: <Terminal className="w-3.5 h-3.5 text-purple-400" />,
    },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      {/* Stale Warning Banner */}
      {isStale && (
        <div className="flex items-center justify-between p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-300">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              This intelligence snapshot was generated over 12 hours ago. Live domain reputation and DNS records may have drifted.
            </span>
          </div>
          <button
            type="button"
            onClick={handleRescan}
            className="flex items-center gap-1 font-semibold underline hover:text-amber-200 cursor-pointer shrink-0 ml-3"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Refresh Scan</span>
          </button>
        </div>
      )}

      {/* A. VERDICT HEADER */}
      <VerdictHeader
        scan={scan}
        historyScans={historyScans}
        prevScanId={prevScanId}
        isFirstScan={isFirstScan}
        historyError={historyError}
        isWatchlisted={isWatchlisted}
        isRescanning={isRescanning}
        onRescan={handleRescan}
        onToggleWatchlist={handleToggleWatchlist}
      />

      {/* B. VIEW TOGGLE - SegmentedControl */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
        <div className="flex items-center gap-2">
          <SegmentedControl<'plain' | 'technical'>
            options={viewOptions}
            value={viewMode}
            onChange={(val) => setViewMode(val)}
            size="md"
          />
        </div>

        <div className="text-[11px] font-mono text-[var(--text-tertiary)] flex items-center gap-2">
          <span>{scan.factors.length} evidence factors indexed</span>
          <span>·</span>
          <span>{scan.total_engines || 0} engines correlated</span>
        </div>
      </div>

      {/* C & D: CONDITIONAL VIEW CONTENT */}
      {viewMode === 'plain' ? (
        /* C. PLAIN ENGLISH VIEW */
        <div className="space-y-6 animate-in fade-in duration-150">
          <ExplainSimplyCard
            score={scan.risk_score}
            level={scan.risk_level}
            factors={scan.factors}
            explanation={scan.explanation}
            recommendedAction={scan.recommended_action}
            isDemo={scan.is_demo}
          />

          {/* High-level Factors overview in Plain English */}
          <FactorsList
            factors={scan.factors}
            viewMode="plain"
          />
        </div>
      ) : (
        /* D. TECHNICAL VIEW */
        <div className="space-y-6 animate-in fade-in duration-150">
          {/* Score breakdown with group ceilings and hover highlighting */}
          <ScoreBreakdownBar
            groupBreakdown={scan.group_breakdown}
            totalScore={scan.risk_score}
            hoveredGroup={hoveredGroup}
            onHoverGroup={setHoveredGroup}
          />

          {/* Grouped Factor List with hover highlight & drawer integration */}
          <FactorsList
            factors={scan.factors}
            viewMode="technical"
            hoveredGroup={hoveredGroup}
          />
        </div>
      )}

      {/* E. EVIDENCE SOURCES - SourceCardGrid (7 cards, in-place expansion) */}
      <SourceCardGrid
        sources={scan.sources}
        configuredSources={health?.configured_sources}
        isLoading={isLoadingSources}
        onRetrySource={(src) => {
          toast.info(`Retrying intelligence ingestion for ${src}...`);
          loadReportData();
        }}
      />

      {/* F. ATTACK CHAIN - AttackChainGraph (keyboard nav, drawer, --bg-visual) */}
      <AttackChainGraph
        graph={scan.attack_chain}
        redirects={scan.raw_summary?.redirects}
      />

      {/* G. TEMPORAL CONTEXT - TemporalSparkline (--bg-visual, clickable nodes) */}
      <TemporalSparkline
        scans={historyScans.length > 0 ? historyScans : [scan]}
        currentScanId={scan.id}
      />

      {/* H. RAW DATA - RawJsonViewer (collapsed by default, search, copy) */}
      <RawJsonViewer
        data={scan}
        title={`Raw Telemetry Payload (${scan.id})`}
        defaultOpen={false}
      />
    </div>
  );
};
