import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Bell,
  GitCompare,
  TrendingUp,
  Search,
  RotateCcw,
  Sparkles,
  ExternalLink,
  Clock,
  ArrowRight,
  Layers,
  FileCode,
  Globe,
  Binary,
  UploadCloud,
  CheckCircle2,
  Sliders,
  Radio,
  Lock,
  Database,
} from 'lucide-react';
const ThreatEvolutionChart = React.lazy(() => import('../components/domain/ThreatEvolutionChart'));
import { api } from '../api/client';
import type { Scan, AlertItem } from '../types/threat';
import { useDrawer } from '../context/DrawerContext';
import { useHealth } from '../hooks/useHealth';
import { useGlobalPaste, detectIndicatorType } from '../hooks/useGlobalPaste';
import { useToast } from '../components/primitives/Toast';
import { Button } from '../components/primitives/Button';
import { Badge } from '../components/primitives/Badge';
import { Skeleton } from '../components/primitives/Skeleton';
import { EmptyState } from '../components/primitives/EmptyState';
import { ErrorState } from '../components/primitives/ErrorState';
import { SeverityChip } from '../components/primitives/SeverityChip';
import { TargetRow } from '../components/domain/TargetRow';
import { AlertRow } from '../components/domain/AlertRow';
import { DefangText } from '../components/domain/DefangText';

const FEATURED_DEMO_URL = 'http://service-cdn.example-phishing-login.com/auth';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const drawer = useDrawer();
  const toast = useToast();
  const [searchParams] = useSearchParams();
  const stateOverride = searchParams.get('state'); // For 6-state matrix verification

  const { data: health, status: healthStatus } = useHealth();
  const [scans, setScans] = useState<Scan[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [featuredHistory, setFeaturedHistory] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Hero Bar State
  const [scanInput, setScanInput] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const heroInputRef = useRef<HTMLInputElement>(null);

  // Demo seeding state
  const [isSeeding, setIsSeeding] = useState(false);

  // Auto-detect input type
  const detectedType = detectIndicatorType(scanInput);

  // Global paste hook to focus hero bar and set target
  useGlobalPaste((pasted) => {
    setScanInput(pasted.target);
    heroInputRef.current?.focus();
    toast.info(`Indicator pasted: ${pasted.type.toUpperCase()}`, 'Global Paste');
  });

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [scansData, alertsData] = await Promise.all([
        api.getScans(undefined, 50),
        api.getAlerts().catch(() => [] as AlertItem[]),
      ]);
      setScans(scansData);
      setAlerts(alertsData);

      // Fetch featured target history for evolution chart
      try {
        const histData = await api.getTargetHistory(FEATURED_DEMO_URL);
        if (histData && histData.scans) {
          const sorted = [...histData.scans].sort(
            (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
          );
          setFeaturedHistory(sorted);
        }
      } catch {
        const matching = scansData
          .filter((s) => s.target === FEATURED_DEMO_URL)
          .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        setFeaturedHistory(matching);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  };

  const handleHeroSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = scanInput.trim();
    if (!clean) return;

    try {
      setIsSubmitting(true);
      if (detectedType === 'url') {
        const result = await api.analyzeUrl(clean);
        navigate(`/scans/${result.id}`);
      } else if (detectedType === 'hash') {
        const result = await api.analyzeHash(clean);
        navigate(`/scans/${result.id}`);
      } else {
        // Fallback to URL analyze tab
        navigate(`/analyze/url?target=${encodeURIComponent(clean)}`);
      }
    } catch (err: any) {
      toast.error(err.message || 'Analysis initiation failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSeedDemoData = async () => {
    try {
      setIsSeeding(true);
      await api.seedDemo(true);
      toast.success('Clean demo dataset loaded successfully', 'Demo Seed');
      await loadDashboardData();
    } catch (err: any) {
      toast.error(err.message || 'Failed to load demo data');
    } finally {
      setIsSeeding(false);
    }
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
          <div className="font-semibold text-[var(--text-primary)]">Verdict Summary</div>
          <p className="leading-relaxed">{scan.explanation}</p>
        </div>

        <div>
          <div className="font-semibold text-[var(--text-primary)] mb-2">Key Contributing Factors</div>
          <div className="space-y-1.5">
            {scan.factors.slice(0, 3).map((f) => (
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
        title: `Scan ${scan.id}`,
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

  // State Matrix Overrides / Computations
  const isStateLoading = stateOverride === 'loading' || (loading && scans.length === 0);
  const isStateError = stateOverride === 'error' || (error && scans.length === 0);
  const isStateEmpty = stateOverride === 'empty' || (!loading && scans.length === 0);
  const isStateStale = stateOverride === 'stale';
  const isStateDemo = stateOverride === 'demo' || scans.some((s) => s.is_demo);
  const isStatePartial = stateOverride === 'partial';

  // Metrics computation
  const totalScans24h = scans.filter((s) => {
    const diff = (Date.now() - new Date(s.timestamp).getTime()) / (1000 * 60 * 60);
    return diff <= 24;
  }).length || scans.length;

  const highCriticalCount = scans.filter(
    (s) => s.risk_level === 'HIGH' || s.risk_level === 'CRITICAL'
  ).length;

  const targetCounts: Record<string, number> = {};
  scans.forEach((s) => {
    targetCounts[s.target] = (targetCounts[s.target] || 0) + 1;
  });
  const changedThreatsCount = Object.values(targetCounts).filter((c) => c > 1).length;

  const feedsOnlineCount = health?.configured_sources
    ? Object.values(health.configured_sources).filter(Boolean).length
    : 7;

  // Chart Data
  const chartData = featuredHistory.map((s, index) => {
    const d = new Date(s.timestamp);
    const label = isNaN(d.getTime()) ? `S${index + 1}` : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    return {
      index: index + 1,
      id: s.id,
      label,
      score: s.risk_score,
      level: s.risk_level,
    };
  });

  // 1. Loading State
  if (isStateLoading) {
    return (
      <div className="max-w-7xl mx-auto py-8 px-4 space-y-8 animate-in fade-in duration-150">
        <div className="space-y-4">
          <Skeleton className="w-1/3 h-8 rounded-lg" />
          <Skeleton className="w-full h-14 rounded-2xl" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Skeleton className="lg:col-span-2 h-72 rounded-2xl" />
          <Skeleton className="h-72 rounded-2xl" />
        </div>
      </div>
    );
  }

  // 2. Error State
  if (isStateError) {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4">
        <ErrorState
          title="Failed to Load Overview Dashboard"
          message={error || 'Unable to communicate with the ThreatLens API engine.'}
          onRetry={loadDashboardData}
        />
      </div>
    );
  }

  // 3. Empty State (Fresh Install)
  if (isStateEmpty) {
    return (
      <div className="max-w-4xl mx-auto py-12 px-4 space-y-8 animate-in fade-in duration-200">
        <div className="text-center space-y-2">
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">Welcome to ThreatLens</h1>
          <p className="text-xs text-[var(--text-secondary)] max-w-lg mx-auto">
            Your explainability and threat-evolution layer is ready. Start by scanning any live indicator or load the seeded demo investigation dataset.
          </p>
        </div>

        {/* 3-Step Guided Card */}
        <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
              <div className="w-7 h-7 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center font-bold text-xs font-mono">
                1
              </div>
              <h3 className="text-sm font-bold text-[var(--text-primary)]">Scan Something</h3>
              <p className="text-[11px] text-[var(--text-secondary)]">
                Input any URL, domain, or file hash to aggregate multi-source signals in parallel.
              </p>
            </div>

            <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
              <div className="w-7 h-7 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center font-bold text-xs font-mono">
                2
              </div>
              <h3 className="text-sm font-bold text-[var(--text-primary)]">Add to Watchlist</h3>
              <p className="text-[11px] text-[var(--text-secondary)]">
                Pin suspicious infrastructure to automated re-checks and detect quiet DNS/hop changes.
              </p>
            </div>

            <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
              <div className="w-7 h-7 rounded-lg bg-purple-500/10 text-purple-400 flex items-center justify-center font-bold text-xs font-mono">
                3
              </div>
              <h3 className="text-sm font-bold text-[var(--text-primary)]">Watch What Changes</h3>
              <p className="text-[11px] text-[var(--text-secondary)]">
                Review verdict drift, escalation alerts, and hop evolution across multiple scans.
              </p>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
            <Button
              variant="primary"
              size="md"
              onClick={handleSeedDemoData}
              disabled={isSeeding}
              className="flex items-center gap-2"
            >
              <Sparkles className="w-4 h-4" />
              <span>{isSeeding ? 'Loading Dataset...' : 'Load Demo Dataset'}</span>
            </Button>
            <Button
              variant="secondary"
              size="md"
              onClick={() => navigate('/analyze/url')}
            >
              Scan a Live Indicator
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto py-8 px-4 space-y-8 pb-16 animate-in fade-in duration-150">
      {/* Stale State Banner */}
      {isStateStale && (
        <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-amber-400 shrink-0" />
            <span>Dashboard telemetry is cached from a previous session. Click refresh to query live engine feeds.</span>
          </div>
          <Button variant="secondary" size="xs" onClick={loadDashboardData}>
            Refresh
          </Button>
        </div>
      )}

      {/* Partial State Banner */}
      {isStatePartial && (
        <div className="p-3 rounded-xl border border-blue-500/30 bg-blue-500/10 text-xs text-blue-300 flex items-center gap-2">
          <Activity className="w-4 h-4 text-blue-400 shrink-0 animate-spin" />
          <span>Partial feed synchronization in progress. 2 external providers responding with degraded latency.</span>
        </div>
      )}

      {/* 1. HERO SCAN BAR */}
      <div className="p-6 md:p-8 rounded-3xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h1 className="text-xl md:text-2xl font-black text-[var(--text-primary)] tracking-tight flex items-center gap-2">
              <span>Security Intelligence & Evolution</span>
              {isStateDemo && <Badge variant="demo" size="xs">Demo Mode</Badge>}
            </h1>
            <p className="text-xs text-[var(--text-secondary)] mt-0.5">
              Explainable threat synthesis across live network infrastructure, file hashes, and community feeds.
            </p>
          </div>
          <div className="text-[11px] font-mono text-[var(--text-tertiary)] flex items-center gap-2">
            <span>Paste anywhere to scan</span>
            <span className="hidden sm:inline">·</span>
            <span className="hidden sm:inline">⌘+V / Ctrl+V</span>
          </div>
        </div>

        {/* Hero Input Form */}
        <form onSubmit={handleHeroSubmit} className="relative">
          <div className="relative flex items-center">
            <div className="absolute left-4 text-[var(--text-tertiary)] pointer-events-none">
              {detectedType === 'hash' ? (
                <Binary className="w-5 h-5 text-purple-400" />
              ) : (
                <Globe className="w-5 h-5 text-blue-400" />
              )}
            </div>

            <input
              id="hero-scan-input"
              aria-label="Target indicator URL, domain, or hash"
              ref={heroInputRef}
              type="text"
              value={scanInput}
              onChange={(e) => setScanInput(e.target.value)}
              placeholder="Paste indicator target: URL, domain, or MD5 / SHA-256 hash..."
              className="w-full pl-12 pr-32 py-3.5 text-sm font-mono rounded-2xl bg-[var(--bg-inset)] border border-[var(--border-strong)] text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all shadow-inner"
            />

            <div className="absolute right-2 flex items-center gap-2">
              {scanInput && (
                <Badge variant="neutral" size="xs" className="hidden sm:inline-block font-mono uppercase">
                  {detectedType}
                </Badge>
              )}
              <Button
                variant="primary"
                size="sm"
                type="submit"
                disabled={!scanInput.trim() || isSubmitting}
                className="font-bold shrink-0"
              >
                {isSubmitting ? 'Analyzing...' : 'Analyze'}
              </Button>
            </div>
          </div>
        </form>

        {/* Quick sample chips */}
        <div className="flex items-center gap-2 flex-wrap pt-1 text-[11px]">
          <span className="text-[var(--text-tertiary)] font-mono">Sample indicators:</span>
          <button
            type="button"
            onClick={() => setScanInput('http://service-cdn.example-phishing-login.com/auth')}
            className="px-2 py-0.5 rounded-md bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-blue-400 font-mono transition-colors"
          >
            Phishing CDN URL
          </button>
          <button
            type="button"
            onClick={() => setScanInput('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')}
            className="px-2 py-0.5 rounded-md bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-purple-400 font-mono transition-colors"
          >
            SHA-256 Hash
          </button>
          <Link
            to="/analyze/file"
            className="px-2 py-0.5 rounded-md bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-amber-400 font-mono transition-colors flex items-center gap-1"
          >
            <UploadCloud className="w-3 h-3" />
            <span>Drop File Sample</span>
          </Link>
        </div>
      </div>

      {/* 2. KPI STRIP (Deep links into Investigations) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* KPI 1: Scans 24h */}
        <div
          role="button"
          tabIndex={0}
          onClick={() => navigate('/scans?time=24h')}
          onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && navigate('/scans?time=24h')}
          className="p-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] hover:border-blue-500/50 transition-all cursor-pointer group space-y-1"
        >
          <div className="flex items-center justify-between text-[11px] font-mono text-[var(--text-tertiary)]">
            <span>TOTAL SCANS (24H)</span>
            <Activity className="w-3.5 h-3.5 text-blue-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-black font-mono text-[var(--text-primary)]">
            {totalScans24h}
          </div>
          <div className="text-[10px] text-[var(--text-secondary)] group-hover:text-blue-400 flex items-center gap-1">
            <span>Filter 24h history</span>
            <ArrowRight className="w-2.5 h-2.5" />
          </div>
        </div>

        {/* KPI 2: High/Critical Findings */}
        <div
          role="button"
          tabIndex={0}
          onClick={() => navigate('/scans?severity=high,critical')}
          onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && navigate('/scans?severity=high,critical')}
          className="p-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] hover:border-red-500/50 transition-all cursor-pointer group space-y-1"
        >
          <div className="flex items-center justify-between text-[11px] font-mono text-[var(--text-tertiary)]">
            <span>HIGH & CRITICAL</span>
            <ShieldAlert className="w-3.5 h-3.5 text-red-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-black font-mono text-red-400">
            {highCriticalCount}
          </div>
          <div className="text-[10px] text-[var(--text-secondary)] group-hover:text-red-400 flex items-center gap-1">
            <span>Filter high threats</span>
            <ArrowRight className="w-2.5 h-2.5" />
          </div>
        </div>

        {/* KPI 3: Watchlist Drift Events */}
        <div
          role="button"
          tabIndex={0}
          onClick={() => navigate('/alerts')}
          onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && navigate('/alerts')}
          className="p-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] hover:border-amber-500/50 transition-all cursor-pointer group space-y-1"
        >
          <div className="flex items-center justify-between text-[11px] font-mono text-[var(--text-tertiary)]">
            <span>WATCHLIST DRIFT</span>
            <TrendingUp className="w-3.5 h-3.5 text-amber-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-black font-mono text-amber-400">
            {changedThreatsCount}
          </div>
          <div className="text-[10px] text-[var(--text-secondary)] group-hover:text-amber-400 flex items-center gap-1">
            <span>View drift alerts</span>
            <ArrowRight className="w-2.5 h-2.5" />
          </div>
        </div>

        {/* KPI 4: Feeds Online */}
        <div
          role="button"
          tabIndex={0}
          onClick={() => navigate('/settings')}
          onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && navigate('/settings')}
          className="p-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] hover:border-emerald-500/50 transition-all cursor-pointer group space-y-1"
        >
          <div className="flex items-center justify-between text-[11px] font-mono text-[var(--text-tertiary)]">
            <span>FEEDS ACTIVE</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-black font-mono text-emerald-400">
            {feedsOnlineCount} / 7
          </div>
          <div className="text-[10px] text-[var(--text-secondary)] group-hover:text-emerald-400 flex items-center gap-1">
            <span>Inspect providers</span>
            <ArrowRight className="w-2.5 h-2.5" />
          </div>
        </div>
      </div>

      {/* 3. THREAT EVOLUTION CHART (Strictly on --bg-visual) */}
      <div className="p-5 md:p-6 rounded-3xl border border-[var(--border-subtle)] bg-[var(--bg-visual)] shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-blue-400" />
              Featured Threat Evolution Timeline
            </h3>
            <p className="text-[11px] text-[var(--text-secondary)]">
              Score escalation and factor accretion observed across re-scans for <code className="text-blue-400 font-mono">service-cdn.example-phishing-login.com</code>
            </p>
          </div>
          <Badge variant="demo" size="xs">
            Seeded Evolution
          </Badge>
        </div>

        <div className="h-56 w-full pt-2">
          {chartData.length > 0 ? (
            <React.Suspense
              fallback={
                <div className="h-full flex items-center justify-center text-xs text-[var(--text-tertiary)] font-mono">
                  Loading telemetry canvas...
                </div>
              }
            >
              <ThreatEvolutionChart data={chartData} />
            </React.Suspense>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-[var(--text-tertiary)] font-mono">
              Insufficient history data points recorded for evolution chart.
            </div>
          )}
        </div>
      </div>

      {/* 4. DUAL COLUMN: RECENT INVESTIGATIONS & ACTIVE ALERTS */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Investigations (2 cols) */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-400" />
              Recent Investigations
            </h3>
            <Link
              to="/scans"
              className="text-xs font-medium text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
            >
              <span>View all</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="space-y-2">
            {scans.slice(0, 5).map((scan) => (
              <TargetRow
                key={scan.id}
                id={scan.id}
                target={scan.target}
                targetType={scan.target_type}
                level={scan.risk_level}
                score={scan.risk_score}
                lastScannedAt={scan.timestamp}
                onClick={() => openScanDrawer(scan)}
              />
            ))}
          </div>
        </div>

        {/* Active Drift Alerts (1 col) */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
              <Bell className="w-4 h-4 text-amber-400" />
              Active Drift Alerts
            </h3>
            <Link
              to="/alerts"
              className="text-xs font-medium text-amber-400 hover:text-amber-300 flex items-center gap-1 transition-colors"
            >
              <span>View all</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="space-y-2">
            {alerts.length > 0 ? (
              alerts.slice(0, 3).map((alert) => (
                <AlertRow
                  key={alert.id}
                  id={alert.id}
                  target={alert.target}
                  kind={alert.kind}
                  message={alert.message}
                  createdAt={alert.created_at}
                  seen={alert.seen}
                  onInspect={() => navigate(`/alerts`)}
                />
              ))
            ) : (
              <div className="p-6 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] text-center text-xs text-[var(--text-tertiary)] space-y-1">
                <CheckCircle2 className="w-5 h-5 text-emerald-500 mx-auto mb-1" />
                <div className="font-semibold text-[var(--text-secondary)]">No unread drift alerts</div>
                <p className="text-[11px]">All watchlist targets are stable without score escalations.</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 5. FEED STATUS PANEL */}
      <div className="p-5 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
              <Database className="w-4 h-4 text-indigo-400" />
              Telemetry Provider Operational Status
            </h3>
            <p className="text-[11px] text-[var(--text-secondary)]">
              Multi-source correlation feeds. Keyless public engines and authenticated providers.
            </p>
          </div>
          <Link
            to="/settings"
            className="text-xs font-medium text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
          >
            <span>Provider settings</span>
            <Sliders className="w-3 h-3" />
          </Link>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-3">
          {[
            { name: 'DNS Resolution', key: 'dns', keyless: true, latency: '42ms' },
            { name: 'RDAP WHOIS', key: 'rdap', keyless: true, latency: '118ms' },
            { name: 'crt.sh CT Logs', key: 'crtsh', keyless: true, latency: '185ms' },
            { name: 'OpenPhish Feed', key: 'openphish', keyless: true, latency: '64ms' },
            { name: 'VirusTotal Multi-AV', key: 'virustotal', keyless: false, latency: '280ms' },
            { name: 'Google Safe Browsing', key: 'google_safe_browsing', keyless: false, latency: '95ms' },
            { name: 'URLhaus Blacklist', key: 'urlhaus', keyless: true, latency: '72ms' },
          ].map((src) => {
            const isConfigured = health?.configured_sources ? health.configured_sources[src.key] ?? src.keyless : src.keyless;
            return (
              <div
                key={src.name}
                className="p-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2 flex flex-col justify-between"
              >
                <div>
                  <div className="text-[10px] font-mono text-[var(--text-tertiary)] uppercase flex items-center justify-between">
                    <span>{src.latency}</span>
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  </div>
                  <div className="font-semibold text-xs text-[var(--text-primary)] mt-1 truncate">
                    {src.name}
                  </div>
                </div>

                <div className="pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between">
                  <span className="text-[10px] text-[var(--text-tertiary)] font-mono">
                    {src.keyless ? 'Keyless' : 'API Key'}
                  </span>
                  {isConfigured ? (
                    <Badge variant="low" size="xs">
                      Live
                    </Badge>
                  ) : (
                    <Badge variant="demo" size="xs">
                      Demo
                    </Badge>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
