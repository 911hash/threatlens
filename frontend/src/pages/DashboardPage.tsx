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
  Mail,
  UploadCloud,
  CheckCircle2,
  Sliders,
  Radio,
  Lock,
  Database,
  FileCheck2,
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
import { ErrorState } from '../components/primitives/ErrorState';
import { SeverityChip } from '../components/primitives/SeverityChip';
import { TargetRow } from '../components/domain/TargetRow';
import { AlertRow } from '../components/domain/AlertRow';
import { DefangText } from '../components/domain/DefangText';

const FEATURED_DEMO_URL = 'http://service-cdn.example-phishing-login.com/auth';

interface FeedSourceDef {
  name: string;
  key: string;
  keyless: boolean;
  latency: string;
}

const FEED_SOURCES: FeedSourceDef[] = [
  { name: 'DNS Resolution', key: 'dns', keyless: true, latency: '38ms' },
  { name: 'RDAP WHOIS', key: 'rdap', keyless: true, latency: '112ms' },
  { name: 'crt.sh CT Logs', key: 'crtsh', keyless: true, latency: '175ms' },
  { name: 'OpenPhish Feed', key: 'openphish', keyless: true, latency: '58ms' },
  { name: 'VirusTotal Multi-AV', key: 'virustotal', keyless: false, latency: '260ms' },
  { name: 'Google Safe Browsing', key: 'google_safe_browsing', keyless: false, latency: '92ms' },
  { name: 'URLhaus Blacklist', key: 'urlhaus', keyless: true, latency: '65ms' },
];

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
  const [isDragging, setIsDragging] = useState(false);
  const heroInputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
      } else if (detectedType === 'email') {
        navigate(`/analyze/email?target=${encodeURIComponent(clean)}`);
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

  const handleFileUpload = async (file: File) => {
    if (!file) return;
    setIsSubmitting(true);
    try {
      toast.info(`Analyzing ${file.name}...`, 'File Analysis');
      let result: Scan;
      if (file.name.endsWith('.eml') || file.type.includes('email') || file.type.includes('message')) {
        result = await api.analyzeEmail(file);
      } else {
        result = await api.analyzeFile(file);
      }
      toast.success(`Analysis completed for ${file.name}`, 'Success');
      navigate(`/scans/${result.id}`);
    } catch (err: any) {
      toast.error(err.message || 'File analysis failed');
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
            <div className="font-mono font-bold text-sm text-[var(--text-primary)] mt-0.5 tabular-nums">
              {scan.risk_score} / 100
            </div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Confidence</span>
            <div className="font-mono font-bold text-sm text-[var(--text-primary)] mt-0.5 tabular-nums">
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
                <span className="font-mono font-bold text-[var(--text-primary)] shrink-0 tabular-nums">
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

  // State Matrix Computations
  const isStateLoading = stateOverride === 'loading' || (loading && scans.length === 0);
  const isStateError = stateOverride === 'error' || (error && scans.length === 0);
  const isStateEmpty = stateOverride === 'empty' || (!loading && scans.length === 0);
  const isStateStale = stateOverride === 'stale';
  const isStateDemo = stateOverride === 'demo' || scans.some((s) => s.is_demo);
  const isStatePartial = stateOverride === 'partial' || healthStatus === 'degraded';

  // Metrics computation with tabular numerals
  const now = Date.now();
  const totalScans24h = scans.filter((s) => {
    const diff = (now - new Date(s.timestamp).getTime()) / (1000 * 60 * 60);
    return diff <= 24;
  }).length;

  const highCriticalCount = scans.filter(
    (s) => s.risk_level === 'HIGH' || s.risk_level === 'CRITICAL'
  ).length;

  const targetCounts: Record<string, number> = {};
  scans.forEach((s) => {
    targetCounts[s.target] = (targetCounts[s.target] || 0) + 1;
  });
  const watchlistDriftCount = alerts.length > 0
    ? alerts.length
    : Object.values(targetCounts).filter((c) => c > 1).length;

  const feedsOnlineCount = health?.configured_sources
    ? Object.values(health.configured_sources).filter(Boolean).length
    : (healthStatus === 'healthy' ? 7 : 6);

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

  // 1. Loading State (Exact skeleton matching final dimensions to eliminate layout shift)
  if (isStateLoading) {
    return (
      <div className="max-w-7xl mx-auto py-8 px-4 space-y-8 animate-in fade-in duration-150">
        {/* Hero scan bar skeleton */}
        <div className="p-6 md:p-8 rounded-3xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <Skeleton className="w-1/3 h-7 rounded-lg" />
            <Skeleton className="w-36 h-4 rounded-md" />
          </div>
          <Skeleton className="w-full h-14 rounded-2xl" />
          <div className="flex gap-2">
            <Skeleton className="w-24 h-5 rounded-md" />
            <Skeleton className="w-28 h-5 rounded-md" />
            <Skeleton className="w-32 h-5 rounded-md" />
          </div>
        </div>

        {/* 4 KPI cards skeleton */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="p-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-2 h-[104px]">
              <div className="flex justify-between items-center">
                <Skeleton className="w-24 h-3.5 rounded" />
                <Skeleton className="w-4 h-4 rounded-full" />
              </div>
              <Skeleton className="w-16 h-7 rounded" />
              <Skeleton className="w-28 h-3 rounded" />
            </div>
          ))}
        </div>

        {/* 2-column layout skeleton (2/3 left, 1/3 right) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-3">
            <div className="flex justify-between items-center">
              <Skeleton className="w-40 h-4 rounded" />
              <Skeleton className="w-16 h-3 rounded" />
            </div>
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} className="w-full h-14 rounded-lg" />
            ))}
          </div>
          <div className="space-y-6">
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <Skeleton className="w-36 h-4 rounded" />
                <Skeleton className="w-16 h-3 rounded" />
              </div>
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="w-full h-16 rounded-lg" />
              ))}
            </div>
            <Skeleton className="w-full h-48 rounded-2xl" />
          </div>
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
          <span>Feed telemetry synchronization in progress. Rate-limited or degraded providers will update asynchronously.</span>
        </div>
      )}

      {/* 1. HERO SCAN BAR */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setIsDragging(false);
          if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
          }
        }}
        className={`p-6 md:p-8 rounded-3xl border transition-all shadow-sm space-y-4 ${
          isDragging
            ? 'border-blue-500 bg-blue-500/5 ring-4 ring-blue-500/20'
            : 'border-[var(--border-subtle)] bg-[var(--bg-panel)]'
        }`}
      >
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
            <span>Paste anywhere on page</span>
            <span className="hidden sm:inline">·</span>
            <span className="hidden sm:inline">⌘+V / Ctrl+V</span>
          </div>
        </div>

        {/* Hidden file input for drag/drop or click upload */}
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          accept=".eml,.msg,.txt,.exe,.bin,.pdf,.doc,.docx"
          onChange={(e) => {
            if (e.target.files && e.target.files.length > 0) {
              handleFileUpload(e.target.files[0]);
            }
          }}
        />

        {/* Hero Input Form */}
        <form onSubmit={handleHeroSubmit} className="relative">
          <div className="relative flex items-center">
            <div className="absolute left-4 text-[var(--text-tertiary)] pointer-events-none">
              {detectedType === 'hash' ? (
                <Binary className="w-5 h-5 text-purple-400" />
              ) : detectedType === 'email' ? (
                <Mail className="w-5 h-5 text-indigo-400" />
              ) : (
                <Globe className="w-5 h-5 text-blue-400" />
              )}
            </div>

            <input
              id="hero-scan-input"
              aria-label="Target indicator URL, hash, or drop an .eml file"
              ref={heroInputRef}
              type="text"
              value={scanInput}
              onChange={(e) => setScanInput(e.target.value)}
              placeholder="Paste a URL, hash, or drop an .eml file..."
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

        {/* Sample chips & File Upload trigger */}
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
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="px-2 py-0.5 rounded-md bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-amber-400 font-mono transition-colors flex items-center gap-1"
          >
            <UploadCloud className="w-3 h-3 text-amber-400" />
            <span>Drop File / .eml</span>
          </button>
        </div>
      </div>

      {/* 2. KPI STRIP (Stacked at 320px, 4 in a row at 1280px) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
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
          <div className="text-2xl font-black font-mono tabular-nums text-[var(--text-primary)]">
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
          <div className="text-2xl font-black font-mono tabular-nums text-red-400">
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
          <div className="text-2xl font-black font-mono tabular-nums text-amber-400">
            {watchlistDriftCount}
          </div>
          <div className="text-[10px] text-[var(--text-secondary)] group-hover:text-amber-400 flex items-center gap-1">
            <span>View drift alerts</span>
            <ArrowRight className="w-2.5 h-2.5" />
          </div>
        </div>

        {/* KPI 4: Sources Online */}
        <div
          role="button"
          tabIndex={0}
          onClick={() => navigate('/settings')}
          onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && navigate('/settings')}
          className="p-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] hover:border-emerald-500/50 transition-all cursor-pointer group space-y-1"
        >
          <div className="flex items-center justify-between text-[11px] font-mono text-[var(--text-tertiary)]">
            <span>SOURCES ONLINE</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-black font-mono tabular-nums text-emerald-400">
            {feedsOnlineCount} / 7
          </div>
          <div className="text-[10px] text-[var(--text-secondary)] group-hover:text-emerald-400 flex items-center gap-1">
            <span>Inspect providers</span>
            <ArrowRight className="w-2.5 h-2.5" />
          </div>
        </div>
      </div>

      {/* 3. OPTIONAL FEATURED THREAT EVOLUTION TIMELINE (When data exists or demo mode) */}
      {chartData.length > 0 && (
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

          <div className="h-52 w-full pt-2">
            <React.Suspense
              fallback={
                <div className="h-full flex items-center justify-center text-xs text-[var(--text-tertiary)] font-mono">
                  Loading telemetry canvas...
                </div>
              }
            >
              <ThreatEvolutionChart data={chartData} />
            </React.Suspense>
          </div>
        </div>
      )}

      {/* 4. TWO-COLUMN LAYOUT (2/3 LEFT, 1/3 RIGHT) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column (2/3): Recent Investigations or 3-step Onboarding Empty State */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-400" />
              Recent Investigations
            </h3>
            {scans.length > 0 && (
              <Link
                to="/scans"
                className="text-xs font-medium text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
              >
                <span>View all</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            )}
          </div>

          {/* If scans exist, render 5 most recent scans */}
          {scans.length > 0 && !isStateEmpty ? (
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
          ) : (
            /* Fresh Install / Empty State: 3-step Onboarding Card */
            <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-6">
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-blue-400" />
                  <span>Welcome to ThreatLens</span>
                </h4>
                <p className="text-xs text-[var(--text-secondary)]">
                  Your explainable multi-source security intelligence layer is ready. Follow the 3-step lifecycle below to begin:
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {/* Step 1 */}
                <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
                  <div className="w-7 h-7 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center font-bold text-xs font-mono">
                    1
                  </div>
                  <div className="text-xs font-bold text-[var(--text-primary)]">Scan Something</div>
                  <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
                    Paste any URL, domain, file hash, or drop an .eml to aggregate 7 multi-source signals.
                  </p>
                </div>

                {/* Step 2 */}
                <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
                  <div className="w-7 h-7 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center font-bold text-xs font-mono">
                    2
                  </div>
                  <div className="text-xs font-bold text-[var(--text-primary)]">Add to Watchlist</div>
                  <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
                    Pin suspicious infrastructure to automated re-checks and detect quiet DNS/hop changes.
                  </p>
                </div>

                {/* Step 3 */}
                <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
                  <div className="w-7 h-7 rounded-lg bg-purple-500/10 text-purple-400 flex items-center justify-center font-bold text-xs font-mono">
                    3
                  </div>
                  <div className="text-xs font-bold text-[var(--text-primary)]">Watch What Changes</div>
                  <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
                    Review verdict drift, escalation alerts, and hop evolution across multiple scans.
                  </p>
                </div>
              </div>

              <div className="flex flex-col sm:flex-row items-center gap-3 pt-1 border-t border-[var(--border-subtle)]">
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleSeedDemoData}
                  disabled={isSeeding}
                  className="flex items-center gap-2 font-bold"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>{isSeeding ? 'Loading Dataset...' : 'Load Demo Dataset'}</span>
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setScanInput('http://service-cdn.example-phishing-login.com/auth');
                    heroInputRef.current?.focus();
                  }}
                  className="flex items-center gap-1.5"
                >
                  <Search className="w-3.5 h-3.5" />
                  <span>Try Sample Indicator</span>
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Right Column (1/3): Active Drift Alerts + Feed Status Panel */}
        <div className="lg:col-span-1 space-y-6">
          {/* Active Drift Alerts */}
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
                <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] text-center space-y-1">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 mx-auto mb-1" />
                  <div className="text-xs font-semibold text-[var(--text-primary)]">No Active Drift Alerts</div>
                  <p className="text-[11px] text-[var(--text-secondary)]">All monitored targets remain stable.</p>
                </div>
              )}
            </div>
          </div>

          {/* Threat Intelligence Feed Status Panel */}
          <div className="p-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
                  <Database className="w-4 h-4 text-indigo-400" />
                  Feed Status (7 Sources)
                </h3>
              </div>
              <Link
                to="/settings"
                className="text-[11px] font-medium text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
              >
                <span>Settings</span>
                <Sliders className="w-3 h-3" />
              </Link>
            </div>

            {/* Grid of 7 sources */}
            <div className="space-y-1.5">
              {FEED_SOURCES.map((src) => {
                const isConfigured = health?.configured_sources
                  ? health.configured_sources[src.key] ?? src.keyless
                  : src.keyless;
                const isError = healthStatus === 'offline';
                const isDegraded = healthStatus === 'degraded' && !isConfigured;

                let dotColorClass = 'bg-emerald-400 shadow-emerald-500/50';
                let statusLabel = 'Reachable';

                if (isError) {
                  dotColorClass = 'bg-red-400 shadow-red-500/50';
                  statusLabel = 'Error';
                } else if (isDegraded) {
                  dotColorClass = 'bg-amber-400 shadow-amber-500/50';
                  statusLabel = 'Degraded';
                } else if (!isConfigured) {
                  dotColorClass = 'bg-zinc-500 shadow-zinc-500/50';
                  statusLabel = 'Unconfigured';
                }

                return (
                  <div
                    key={src.name}
                    className="p-2.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] flex items-center justify-between text-xs"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`w-2 h-2 rounded-full shrink-0 shadow-xs ${dotColorClass}`} />
                      <span className="font-medium text-[var(--text-primary)] truncate">{src.name}</span>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-[10px] font-mono text-[var(--text-tertiary)] tabular-nums">{src.latency}</span>
                      <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-[var(--bg-panel)] text-[var(--text-tertiary)] border border-[var(--border-subtle)]">
                        {src.keyless ? 'Keyless' : 'API Key'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
