import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, useNavigate, useSearchParams, useLocation } from 'react-router-dom';
import {
  Sparkles,
  Terminal,
  Clock,
  RotateCcw,
  AlertTriangle,
  ArrowLeft,
  Lock,
  Mail,
  ShieldCheck,
  Globe,
} from 'lucide-react';
import { api } from '../api/client';
import type {
  Scan,
  HealthStatus,
  WatchlistItem,
  EmailAnalysisResponse,
  EmailAuthResult,
  EmailHeaderAnalysis,
  EmailAttachment,
  GeoLocation,
} from '../types/threat';
import { useLocalStorage } from '../hooks/useLocalStorage';
import { useToast } from '../components/primitives/Toast';
import { SegmentedControl, type SegmentedControlOption } from '../components/primitives/SegmentedControl';
import { EmptyState } from '../components/primitives/EmptyState';
import { ErrorState } from '../components/primitives/ErrorState';
import { Skeleton } from '../components/primitives/Skeleton';
import { Button } from '../components/primitives/Button';
import { Badge } from '../components/primitives/Badge';
import { useDrawer } from '../context/DrawerContext';

// Flagship report components
import { VerdictHeader } from '../components/VerdictHeader';
import { ExplainSimplyCard } from '../components/ExplainSimplyCard';
import { ScoreBreakdownBar } from '../components/ScoreBreakdownBar';
import { FactorsList } from '../components/FactorsList';
import { SourceCardGrid } from '../components/SourceCardGrid';
import { AttackChainGraph } from '../components/AttackChainGraph';
import { TemporalSparkline } from '../components/TemporalSparkline';
import { RawJsonViewer } from '../components/RawJsonViewer';

// Email Forensics components
import { AuthResultsPanel } from '../components/domain/AuthResultsPanel';
import { HeaderChainPanel } from '../components/domain/HeaderChainPanel';
import { AttachmentList } from '../components/domain/AttachmentList';
import { SanitizedBodyViewer } from '../components/domain/SanitizedBodyViewer';
import { GeoPanel, getCountryFlag } from '../components/domain/GeoPanel';
import { WorldMapMarker } from '../components/domain/WorldMapMarker';
import { DefangText } from '../components/domain/DefangText';

export const ResultPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const toast = useToast();
  const drawer = useDrawer();
  const stateOverride = searchParams.get('state');

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

  // URL query parameter view mode override
  useEffect(() => {
    const v = searchParams.get('view');
    if (v === 'technical' || v === 'plain') {
      setViewMode(v);
    }
  }, [searchParams]);

  // Score breakdown hover state to highlight matching factor rows
  const [hoveredGroup, setHoveredGroup] = useState<string | null>(null);

  // Email state passed through router navigation or session cache
  const locationEmailAnalysis = (location.state as any)?.emailAnalysis as EmailAnalysisResponse | undefined;

  useEffect(() => {
    if (locationEmailAnalysis && scan?.id) {
      try {
        sessionStorage.setItem(`threatlens_email_${scan.id}`, JSON.stringify(locationEmailAnalysis));
      } catch {
        // Ignore storage exceptions
      }
    }
  }, [locationEmailAnalysis, scan?.id]);

  const cachedEmailAnalysis = React.useMemo(() => {
    if (locationEmailAnalysis) return locationEmailAnalysis;
    if (scan?.id && scan.target_type === 'email') {
      try {
        const item = sessionStorage.getItem(`threatlens_email_${scan.id}`);
        if (item) return JSON.parse(item) as EmailAnalysisResponse;
      } catch {
        return null;
      }
    }
    return null;
  }, [locationEmailAnalysis, scan?.id, scan?.target_type]);

  // Fallback extraction from scan.raw_summary when target_type === 'email'
  const emailAuthResult: EmailAuthResult | undefined =
    cachedEmailAnalysis?.auth_result || (scan?.raw_summary?.auth_result as EmailAuthResult | undefined);

  const emailHeaderAnalysis: EmailHeaderAnalysis | undefined =
    cachedEmailAnalysis?.header_analysis || (scan?.raw_summary?.header_analysis as EmailHeaderAnalysis | undefined);

  const emailAttachments: EmailAttachment[] =
    cachedEmailAnalysis?.parse_result?.attachments ||
    (scan?.raw_summary?.attachments as EmailAttachment[] | undefined) ||
    [];

  const emailSanitizedHtml: string | undefined =
    cachedEmailAnalysis?.sanitized_html || (scan?.raw_summary?.sanitized_html as string | undefined);

  const emailPlainBody: string | undefined =
    cachedEmailAnalysis?.parse_result?.plain_body || (scan?.raw_summary?.plain_body as string | undefined);

  const emailSender: string | undefined =
    cachedEmailAnalysis?.parse_result?.sender ||
    (scan?.raw_summary?.from_address as string | undefined);

  const emailReplyTo: string | undefined =
    cachedEmailAnalysis?.parse_result?.reply_to || (scan?.raw_summary?.reply_to as string | undefined);

  const emailSubject: string | undefined =
    cachedEmailAnalysis?.parse_result?.subject ||
    (scan?.raw_summary?.subject as string | undefined);

  const emailDate: string | undefined =
    cachedEmailAnalysis?.parse_result?.date || (scan?.raw_summary?.date as string | undefined);

  // Email Geolocation & Sender Infrastructure
  const emailSenderIps: string[] =
    (cachedEmailAnalysis?.parse_result?.sender_ips && cachedEmailAnalysis.parse_result.sender_ips.length > 0
      ? cachedEmailAnalysis.parse_result.sender_ips
      : undefined) ||
    (scan?.raw_summary?.sender_ips && (scan.raw_summary.sender_ips as string[]).length > 0
      ? (scan.raw_summary.sender_ips as string[])
      : undefined) ||
    (emailHeaderAnalysis?.sender_ips && emailHeaderAnalysis.sender_ips.length > 0
      ? emailHeaderAnalysis.sender_ips
      : undefined) ||
    [];

  const emailGeoResults: GeoLocation[] =
    (cachedEmailAnalysis?.geo_results && cachedEmailAnalysis.geo_results.length > 0
      ? cachedEmailAnalysis.geo_results
      : undefined) ||
    (scan?.geo_results && (scan.geo_results as GeoLocation[]).length > 0
      ? (scan.geo_results as GeoLocation[])
      : undefined) ||
    (scan?.raw_summary?.geo_results && (scan.raw_summary.geo_results as GeoLocation[]).length > 0
      ? (scan.raw_summary.geo_results as GeoLocation[])
      : undefined) ||
    (emailHeaderAnalysis?.geo_results && emailHeaderAnalysis.geo_results.length > 0
      ? emailHeaderAnalysis.geo_results
      : undefined) ||
    [];

  const emailPrivacyMode: string =
    cachedEmailAnalysis?.privacy_mode ||
    (scan?.privacy_mode as string | undefined) ||
    (scan?.raw_summary?.privacy_mode as string | undefined) ||
    'full';

  const displayGeoItems = React.useMemo(() => {
    if (emailSenderIps.length > 0) {
      return emailSenderIps.map((ip, idx) => {
        const geo = emailGeoResults.find((g) => g.ip === ip) || emailGeoResults[idx];
        return { ip, geo, hopIndex: idx };
      });
    }
    return emailGeoResults.map((geo, idx) => ({
      ip: geo.ip,
      geo,
      hopIndex: idx,
    }));
  }, [emailSenderIps, emailGeoResults]);

  const primaryGeo = React.useMemo(() => {
    return displayGeoItems.find((item) => item.geo && typeof item.geo.lat === 'number') || displayGeoItems[0];
  }, [displayGeoItems]);

  const handlePivotGeo = (geo: GeoLocation, ip: string, hopIndex?: number) => {
    drawer.open(
      <div className="space-y-6">
        {/* Top Identity & Location */}
        <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-3xl">{getCountryFlag(geo.country_code)}</span>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm font-bold text-[var(--text-primary)]">
                    <DefangText value={ip} />
                  </span>
                  {hopIndex !== undefined && (
                    <Badge variant="neutral" size="xs">
                      Hop {hopIndex}
                    </Badge>
                  )}
                  {geo.cached && (
                    <Badge variant="neutral" size="xs">
                      Cached Snapshot
                    </Badge>
                  )}
                </div>
                <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                  {[geo.city, geo.region, geo.country].filter((c) => c && c !== 'unknown').join(', ') ||
                    'Unknown Location'}
                </p>
              </div>
            </div>
          </div>

          {/* Risk Badges */}
          <div className="flex flex-wrap gap-2 pt-2 border-t border-[var(--border-subtle)]">
            {geo.is_tor && (
              <Badge variant="danger" size="sm">
                Tor Exit Node (Critical Risk)
              </Badge>
            )}
            {geo.is_vpn && (
              <Badge variant="warning" size="sm">
                Commercial / Public VPN
              </Badge>
            )}
            {geo.is_proxy && !geo.is_vpn && (
              <Badge variant="warning" size="sm">
                Proxy Relay
              </Badge>
            )}
            {geo.is_datacenter && (
              <Badge variant="info" size="sm">
                Datacenter / Cloud Hosting
              </Badge>
            )}
            {!geo.is_tor && !geo.is_vpn && !geo.is_proxy && !geo.is_datacenter && !geo.is_unknown && (
              <Badge variant="success" size="sm">
                Residential / Standard Range
              </Badge>
            )}
            {geo.is_unknown && (
              <Badge variant="outline" size="sm">
                Telemetry Unknown
              </Badge>
            )}
          </div>
        </div>

        {/* World Map for this specific IP */}
        <WorldMapMarker
          lat={geo.lat}
          lon={geo.lon}
          country={geo.country}
          city={geo.city}
          ip={ip}
        />

        {/* Technical Telemetry Table */}
        <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--text-primary)] font-mono">
            Network & Routing Telemetry
          </h4>
          <dl className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <dt className="text-[var(--text-tertiary)]">ASN Number</dt>
              <dd className="font-mono font-semibold text-purple-400">{geo.asn || 'N/A'}</dd>
            </div>
            <div>
              <dt className="text-[var(--text-tertiary)]">Internet Service Provider</dt>
              <dd className="font-mono text-[var(--text-primary)]">{geo.isp || 'N/A'}</dd>
            </div>
            <div>
              <dt className="text-[var(--text-tertiary)]">Organization</dt>
              <dd className="font-mono text-[var(--text-primary)]">{geo.org || 'N/A'}</dd>
            </div>
            <div>
              <dt className="text-[var(--text-tertiary)]">Timezone</dt>
              <dd className="font-mono text-[var(--text-primary)]">{geo.timezone || 'N/A'}</dd>
            </div>
            <div>
              <dt className="text-[var(--text-tertiary)]">Coordinates</dt>
              <dd className="font-mono text-[var(--text-secondary)]">
                {geo.lat !== undefined && geo.lon !== undefined ? `${geo.lat}, ${geo.lon}` : 'N/A'}
              </dd>
            </div>
            <div>
              <dt className="text-[var(--text-tertiary)]">Cache Status</dt>
              <dd className="font-mono text-[var(--text-secondary)]">
                {geo.cached ? 'Hit (SQLite 24h TTL)' : 'Live Query'}
              </dd>
            </div>
          </dl>
        </div>

        {/* Raw JSON */}
        <div className="p-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)]">
          <div className="text-[11px] font-mono font-bold text-[var(--text-secondary)] mb-2">Raw Geo Telemetry:</div>
          <pre className="text-[11px] font-mono text-[var(--text-tertiary)] overflow-x-auto p-2 bg-[var(--bg-panel)] rounded border border-[var(--border-subtle)]">
            {JSON.stringify(geo, null, 2)}
          </pre>
        </div>
      </div>,
      {
        title: `Infrastructure Telemetry: ${ip}`,
      }
    );
  };

  // URL query parameter pivot / drawer override for automated testing & deep-linking
  useEffect(() => {
    if (searchParams.get('pivot') === 'true' && displayGeoItems.length > 0 && !drawer.isOpen) {
      const targetItem = displayGeoItems[0];
      if (targetItem && targetItem.geo) {
        handlePivotGeo(targetItem.geo, targetItem.ip, targetItem.hopIndex);
      }
    }
  }, [searchParams, displayGeoItems, drawer.isOpen]);

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
    if (scan.target_type === 'email') {
      toast.info('Email samples are processed strictly in memory and not retained. Please re-upload your .eml or .msg file to re-run.', 'Privacy Mode Active');
      navigate('/analyze/email');
      return;
    }
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

  // Stale status check: older than 12 hours or state override
  const isStale = React.useMemo(() => {
    if (stateOverride === 'stale') return true;
    if (!scan) return false;
    const diffHours = (Date.now() - new Date(scan.timestamp).getTime()) / (1000 * 60 * 60);
    return diffHours > 12;
  }, [scan, stateOverride]);

  // Loading Skeleton State
  if (stateOverride === 'loading' || (isLoading && !scan)) {
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
  if (stateOverride === 'error' || (error && !scan)) {
    return (
      <div className="max-w-2xl mx-auto py-12">
        <ErrorState
          title="Failed to Load Investigation Report"
          message={error || 'Unable to retrieve scan telemetry. Simulated error state.'}
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
  if (stateOverride === 'empty' || !scan) {
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

      {/* Partial Ingestion State Banner */}
      {stateOverride === 'partial' && (
        <div className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-amber-400 shrink-0" />
            <span>Partial Analysis in Progress: Correlating telemetry engines (3 of 4 checks completed)...</span>
          </div>
          <span className="font-mono text-[10px] uppercase px-2 py-0.5 rounded bg-amber-500/20 text-amber-300">
            Incomplete Ingestion
          </span>
        </div>
      )}

      {/* Strict Privacy Mode Banner for Email Targets */}
      {scan.target_type === 'email' && (
        <div className="p-3.5 rounded-xl border border-blue-500/25 bg-blue-500/5 text-xs text-[var(--text-secondary)] flex items-start gap-2.5">
          <Lock className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed">
            <span className="font-semibold text-[var(--text-primary)]">Privacy Mode: </span>
            Email content analyzed locally. Nothing transmitted. Email file and attachments were stream-hashed in memory and NEVER written to disk, NEVER uploaded to external services, and NEVER retained.
          </div>
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

          {/* Email Forensic Overview in Plain English */}
          {scan.target_type === 'email' && (
            <>
              {emailAuthResult && <AuthResultsPanel authResult={emailAuthResult} />}
              {displayGeoItems.length > 0 && primaryGeo && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs p-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)]">
                    <span className="font-bold uppercase tracking-wider font-mono text-[var(--text-primary)] flex items-center gap-1.5 text-xs">
                      <Globe className="w-3.5 h-3.5 text-cyan-400" />
                      Infrastructure & Sender Location
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-[var(--text-tertiary)] font-mono text-[11px]">Privacy Mode:</span>
                      {emailPrivacyMode === 'hash_only' ? (
                        <Badge variant="warning" size="xs">cached results only</Badge>
                      ) : (
                        <Badge variant="success" size="xs">live lookup enabled</Badge>
                      )}
                    </div>
                  </div>
                  <WorldMapMarker
                    lat={primaryGeo.geo?.lat}
                    lon={primaryGeo.geo?.lon}
                    country={primaryGeo.geo?.country}
                    city={primaryGeo.geo?.city}
                    ip={primaryGeo.ip}
                  />
                  <div className="space-y-2">
                    {displayGeoItems.map((item) => (
                      <GeoPanel
                        key={`plain-hop-${item.hopIndex}-${item.ip}`}
                        geolocation={item.geo}
                        ip={item.ip}
                        hopIndex={item.hopIndex}
                        onPivot={(geo) => handlePivotGeo(geo, item.ip, item.hopIndex)}
                      />
                    ))}
                  </div>
                </div>
              )}
              <SanitizedBodyViewer sanitizedHtml={emailSanitizedHtml} plainBody={emailPlainBody} />
              <AttachmentList attachments={emailAttachments} />
            </>
          )}

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

          {/* Email Detailed Forensic Panels in Technical View */}
          {scan.target_type === 'email' && (
            <>
              {emailAuthResult && <AuthResultsPanel authResult={emailAuthResult} />}

              {/* Geolocation & Sender Infrastructure Forensics */}
              {displayGeoItems.length > 0 && (
                <div className="space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)]">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-cyan-400" />
                      <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-primary)] font-mono">
                        Sender Infrastructure & Geolocation Forensics
                      </h3>
                      <Badge variant="neutral" size="xs">
                        {displayGeoItems.length} {displayGeoItems.length === 1 ? 'Relay IP' : 'Relay IPs'}
                      </Badge>
                    </div>

                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-[var(--text-tertiary)] font-mono text-[11px]">Privacy Mode:</span>
                      {emailPrivacyMode === 'hash_only' ? (
                        <Badge variant="warning" size="xs" icon={<Lock className="w-3 h-3 text-amber-400" />}>
                          cached results only
                        </Badge>
                      ) : (
                        <Badge variant="success" size="xs" icon={<ShieldCheck className="w-3 h-3 text-emerald-400" />}>
                          live lookup enabled
                        </Badge>
                      )}
                    </div>
                  </div>

                  {/* Primary Geographic Origin Map */}
                  {primaryGeo && (
                    <WorldMapMarker
                      lat={primaryGeo.geo?.lat}
                      lon={primaryGeo.geo?.lon}
                      country={primaryGeo.geo?.country}
                      city={primaryGeo.geo?.city}
                      ip={primaryGeo.ip}
                    />
                  )}

                  {/* Hop-Ordered Stack of GeoPanels (Hop 0 closest relay at top) */}
                  <div className="space-y-3">
                    {displayGeoItems.map((item) => (
                      <GeoPanel
                        key={`hop-${item.hopIndex}-${item.ip}`}
                        geolocation={item.geo}
                        ip={item.ip}
                        hopIndex={item.hopIndex}
                        onPivot={(geo) => handlePivotGeo(geo, item.ip, item.hopIndex)}
                      />
                    ))}
                  </div>
                </div>
              )}

              {emailHeaderAnalysis && (
                <HeaderChainPanel
                  headerAnalysis={emailHeaderAnalysis}
                  sender={emailSender}
                  replyTo={emailReplyTo}
                  subject={emailSubject}
                  date={emailDate}
                />
              )}
              <AttachmentList attachments={emailAttachments} />
              <SanitizedBodyViewer sanitizedHtml={emailSanitizedHtml} plainBody={emailPlainBody} />
            </>
          )}

          {/* Grouped Factor List with hover highlight & drawer integration */}
          <FactorsList
            factors={scan.factors}
            viewMode="technical"
            hoveredGroup={hoveredGroup}
          />
        </div>
      )}

      {/* E. EVIDENCE SOURCES - Only displayed for URL/hash/file queries */}
      {scan.target_type !== 'email' && (
        <SourceCardGrid
          sources={scan.sources}
          configuredSources={health?.configured_sources}
          isLoading={isLoadingSources}
          onRetrySource={(src) => {
            toast.info(`Retrying intelligence ingestion for ${src}...`);
            loadReportData();
          }}
        />
      )}

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
