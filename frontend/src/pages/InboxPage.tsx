import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Mail,
  RefreshCw,
  ArrowLeft,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Sparkles,
  Inbox as InboxIcon,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  Filter,
} from 'lucide-react';
import { api } from '../api/client';
import type { InboxItem, Scan, RiskLevel } from '../types/threat';
import { GmailConnectCard } from '../components/shell/GmailConnectCard';
import { InboxRow } from '../components/domain/InboxRow';
import { VerdictGauge } from '../components/VerdictGauge';
import { SeverityChip } from '../components/primitives/SeverityChip';
import { DefangText } from '../components/domain/DefangText';
import { AuthResultsPanel } from '../components/domain/AuthResultsPanel';
import { GeoPanel } from '../components/domain/GeoPanel';
import { WorldMapMarker } from '../components/domain/WorldMapMarker';
import { AIAnalysisSection } from '../components/domain/AIAnalysisSection';
import { AttachmentList } from '../components/domain/AttachmentList';
import { SanitizedBodyViewer } from '../components/domain/SanitizedBodyViewer';
import { Button } from '../components/primitives/Button';
import { Badge } from '../components/primitives/Badge';
import { CopyButton } from '../components/primitives/CopyButton';
import { useToast } from '../components/primitives/Toast';

interface DayGroup {
  label: string;
  items: InboxItem[];
}

export const InboxPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { toast } = useToast();

  // Gmail status state
  const [authStatus, setAuthStatus] = useState<{
    connected: boolean;
    email: string | null;
    connected_at?: string;
    last_sync_at?: string;
  } | null>(null);
  const [isLoadingStatus, setIsLoadingStatus] = useState(true);

  // Inbox items state
  const [inboxItems, setInboxItems] = useState<InboxItem[]>([]);
  const [isLoadingItems, setIsLoadingItems] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');

  // Selected item state
  const [selectedGmailId, setSelectedGmailId] = useState<string | null>(searchParams.get('id'));
  const [selectedDetail, setSelectedDetail] = useState<Scan | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  // Sync state & rate limit countdown
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncCountdown, setSyncCountdown] = useState<number>(0);

  // Unread & feedback tracking
  const [lastVisitTimestamp, setLastVisitTimestamp] = useState<number>(0);
  const [readIds, setReadIds] = useState<Set<string>>(new Set());
  const [benignMarkedIds, setBenignMarkedIds] = useState<Set<string>>(new Set());

  // 1. Initialize visit timestamp from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem('threatlens:inbox_last_visit');
      const prev = stored ? parseInt(stored, 10) : 0;
      setLastVisitTimestamp(prev);
      localStorage.setItem('threatlens:inbox_last_visit', Date.now().toString());
    } catch {
      // Storage unavailable
    }
  }, []);

  // 2. Fetch Gmail Connection Status
  const checkStatus = useCallback(async () => {
    try {
      setIsLoadingStatus(true);
      const res = await api.getGmailStatus();
      setAuthStatus(res);
      return res;
    } catch (err) {
      setAuthStatus({ connected: false, email: null });
      return { connected: false, email: null };
    } finally {
      setIsLoadingStatus(false);
    }
  }, []);

  // 3. Fetch Inbox Messages
  const fetchInbox = useCallback(async () => {
    try {
      setIsLoadingItems(true);
      const items = await api.getInbox(1, 100);
      setInboxItems(items);
      // Auto-select first message on desktop if none selected
      if (!selectedGmailId && items.length > 0 && window.innerWidth >= 1024) {
        setSelectedGmailId(items[0].gmail_id);
      }
    } catch (err: any) {
      toast({
        title: 'Failed to load inbox',
        description: err?.message || 'Could not retrieve synced emails',
        variant: 'destructive',
      });
    } finally {
      setIsLoadingItems(false);
    }
  }, [selectedGmailId, toast]);

  // Initial load
  useEffect(() => {
    checkStatus().then((status) => {
      if (status.connected) {
        fetchInbox();
      }
    });
  }, [checkStatus, fetchInbox]);

  // Rate-limit countdown timer
  useEffect(() => {
    if (syncCountdown <= 0) return;
    const timer = setInterval(() => {
      setSyncCountdown((prev) => (prev <= 1 ? 0 : prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [syncCountdown]);

  // 4. Manual Sync Trigger
  const handleSync = async () => {
    if (isSyncing || syncCountdown > 0) return;

    try {
      setIsSyncing(true);
      window.dispatchEvent(
        new CustomEvent('threatlens:inbox-syncing', { detail: { syncing: true } })
      );

      const res = await api.syncInbox();
      toast({
        title: 'Sync complete',
        description: `Synced ${res.synced_count} new email${res.synced_count === 1 ? '' : 's'}`,
        variant: 'default',
      });
      // Start 30s rate limit countdown
      setSyncCountdown(30);
      await fetchInbox();
    } catch (err: any) {
      if (err?.code === 'SYNC_RATE_LIMITED' || err?.retry_after_seconds) {
        const remaining = err.retry_after_seconds || 30;
        setSyncCountdown(remaining);
        toast({
          title: 'Sync rate limited',
          description: `Please wait ${remaining}s before syncing again.`,
          variant: 'default',
        });
      } else {
        toast({
          title: 'Sync failed',
          description: err?.message || 'Could not sync inbox with Gmail',
          variant: 'destructive',
        });
      }
    } finally {
      setIsSyncing(false);
      window.dispatchEvent(
        new CustomEvent('threatlens:inbox-syncing', { detail: { syncing: false } })
      );
    }
  };

  // 5. Fetch Detail for Selected Email
  useEffect(() => {
    if (!selectedGmailId) {
      setSelectedDetail(null);
      setDetailError(null);
      return;
    }

    setReadIds((prev) => new Set([...prev, selectedGmailId]));

    let isCurrent = true;
    const loadDetail = async () => {
      try {
        setIsLoadingDetail(true);
        setDetailError(null);
        const data = await api.getInboxMessageDetail(selectedGmailId);
        if (isCurrent) {
          setSelectedDetail(data);
        }
      } catch (err: any) {
        if (isCurrent) {
          setDetailError(err?.message || 'Failed to load forensic detail');
          setSelectedDetail(null);
        }
      } finally {
        if (isCurrent) {
          setIsLoadingDetail(false);
        }
      }
    };

    loadDetail();
    return () => {
      isCurrent = false;
    };
  }, [selectedGmailId]);

  // Handle item selection
  const handleSelectItem = (id: string) => {
    setSelectedGmailId(id);
    setSearchParams(id ? { id } : {});
  };

  const handleBackToList = () => {
    setSelectedGmailId(null);
    setSearchParams({});
  };

  const handleMarkBenign = () => {
    if (!selectedGmailId) return;
    setBenignMarkedIds((prev) => new Set([...prev, selectedGmailId]));
    toast({
      title: 'Feedback recorded',
      description: 'Email flagged as benign. Forensic score adjusted locally.',
      variant: 'default',
    });
  };

  // 6. Group inbox items by day
  const groupedItems = useMemo<DayGroup[]>(() => {
    const filtered = inboxItems.filter((item) => {
      if (filterSeverity === 'all') return true;
      return (item.risk_level || '').toUpperCase() === filterSeverity.toUpperCase();
    });

    const groups: Record<string, InboxItem[]> = {};

    const todayStr = new Date().toDateString();
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toDateString();

    filtered.forEach((item) => {
      let groupKey = 'Older';
      if (item.date) {
        const itemDate = new Date(item.date);
        if (!isNaN(itemDate.getTime())) {
          const itemDateStr = itemDate.toDateString();
          if (itemDateStr === todayStr) {
            groupKey = 'Today';
          } else if (itemDateStr === yesterdayStr) {
            groupKey = 'Yesterday';
          } else {
            groupKey = itemDate.toLocaleDateString(undefined, {
              month: 'short',
              day: 'numeric',
              year: itemDate.getFullYear() !== new Date().getFullYear() ? 'numeric' : undefined,
            });
          }
        }
      }

      if (!groups[groupKey]) {
        groups[groupKey] = [];
      }
      groups[groupKey].push(item);
    });

    // Order: Today -> Yesterday -> Dates chronologically descending
    const orderedLabels = Object.keys(groups).sort((a, b) => {
      if (a === 'Today') return -1;
      if (b === 'Today') return 1;
      if (a === 'Yesterday') return -1;
      if (b === 'Yesterday') return 1;
      return 0;
    });

    return orderedLabels.map((label) => ({
      label,
      items: groups[label],
    }));
  }, [inboxItems, filterSeverity]);

  // Render Loading Skeleton
  if (isLoadingStatus) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center gap-3 text-[var(--text-secondary)]">
          <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />
          <span className="text-sm font-medium">Checking Gmail connection...</span>
        </div>
      </div>
    );
  }

  // If Not Connected: Show GmailConnectCard
  if (!authStatus?.connected) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12">
        <GmailConnectCard />
      </div>
    );
  }

  // Active connected view
  const currentItemMeta = inboxItems.find((i) => i.gmail_id === selectedGmailId);
  const isMarkedBenign = selectedGmailId ? benignMarkedIds.has(selectedGmailId) : false;

  // Extract forensics fields from detail
  const rawSummary = (selectedDetail as any)?.raw_summary || {};
  const authResult = (selectedDetail as any)?.auth_result || rawSummary?.auth_result;
  const attachments = (selectedDetail as any)?.attachments || rawSummary?.attachments || [];
  const sanitizedHtml = (selectedDetail as any)?.sanitized_html || rawSummary?.sanitized_html;
  const plainBody = (selectedDetail as any)?.plain_body || rawSummary?.plain_body;
  const geoResults = (selectedDetail as any)?.geo_results || rawSummary?.geo_results || [];
  const llmResult =
    (selectedDetail as any)?.llm_result ||
    rawSummary?.llm_result ||
    (selectedDetail as any)?.ai_analysis ||
    rawSummary?.llm_reasoning;
  const anonymizedPrompt =
    (selectedDetail as any)?.anonymized_prompt || rawSummary?.anonymized_prompt;

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)] overflow-hidden bg-[var(--bg-base)]">
      {/* ───────────────────────────────────────────────────────────── */}
      {/* Inbox Control Bar */}
      {/* ───────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 bg-[var(--bg-panel)] border-b border-[var(--border-subtle)] shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-1.5 rounded-lg bg-red-500/10 text-red-500 shrink-0">
            <Mail className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold text-[var(--text-primary)] truncate">Gmail Inbox</h1>
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Connected: {authStatus.email}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {/* Severity Filter */}
          <div className="hidden sm:flex items-center gap-1 bg-[var(--bg-inset)] p-0.5 rounded-lg border border-[var(--border-subtle)] text-xs">
            {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                type="button"
                onClick={() => setFilterSeverity(lvl)}
                className={`px-2 py-1 rounded-md text-[11px] font-semibold uppercase transition-colors ${
                  filterSeverity === lvl
                    ? 'bg-[var(--bg-panel)] text-[var(--text-primary)] shadow-xs'
                    : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

          {/* Sync Button */}
          <Button
            variant="secondary"
            size="sm"
            onClick={handleSync}
            disabled={isSyncing || syncCountdown > 0}
            className="flex items-center gap-1.5 text-xs font-semibold"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin text-blue-500' : ''}`} />
            <span>
              {isSyncing
                ? 'Syncing...'
                : syncCountdown > 0
                ? `Sync (${syncCountdown}s)`
                : 'Sync Inbox'}
            </span>
          </Button>
        </div>
      </div>

      {/* ───────────────────────────────────────────────────────────── */}
      {/* Two-Pane Layout Container (1280px 2-pane / 320px collapsing) */}
      {/* ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-1 min-h-0 overflow-hidden relative">
        {/* ── LEFT PANE: Email List (380px on desktop) ── */}
        <aside
          aria-label="Email Inbox List"
          className={`w-full lg:w-[380px] lg:shrink-0 flex flex-col border-r border-[var(--border-subtle)] bg-[var(--bg-base)] h-full overflow-hidden ${
            selectedGmailId ? 'hidden lg:flex' : 'flex'
          }`}
        >
          {/* Header count indicator */}
          <div className="flex items-center justify-between px-3.5 py-2 border-b border-[var(--border-subtle)]/60 text-xs text-[var(--text-tertiary)] bg-[var(--bg-inset)]/50 shrink-0">
            <span>{inboxItems.length} messages synced</span>
            {lastVisitTimestamp > 0 && (
              <span className="text-[11px]">Blue dot = new since last visit</span>
            )}
          </div>

          {/* Scrollable list */}
          <div className="flex-1 overflow-y-auto p-3 space-y-4">
            {isLoadingItems ? (
              <div className="flex flex-col items-center justify-center py-12 text-[var(--text-tertiary)] gap-2">
                <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />
                <span className="text-xs">Fetching messages...</span>
              </div>
            ) : groupedItems.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 px-4 text-center text-[var(--text-tertiary)]">
                <InboxIcon className="w-10 h-10 mb-2 opacity-40 text-gray-400" />
                <p className="text-sm font-semibold text-[var(--text-secondary)]">No emails found</p>
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  Click 'Sync Inbox' above to fetch your recent Gmail messages.
                </p>
              </div>
            ) : (
              groupedItems.map((group) => (
                <div key={group.label} className="space-y-1.5">
                  <div className="sticky top-0 z-10 px-1 py-1 bg-[var(--bg-base)]/95 backdrop-blur-xs text-[11px] font-bold uppercase tracking-wider text-[var(--text-tertiary)]">
                    {group.label}
                  </div>
                  <div className="space-y-1.5">
                    {group.items.map((item) => (
                      <InboxRow
                        key={item.gmail_id}
                        item={item}
                        isSelected={selectedGmailId === item.gmail_id}
                        onSelect={() => handleSelectItem(item.gmail_id)}
                        lastVisitTimestamp={lastVisitTimestamp}
                      />
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </aside>

        {/* ── RIGHT PANE: Detail Panel ── */}
        <main
          aria-label="Email Forensic Detail"
          className={`flex-1 min-w-0 flex flex-col bg-[var(--bg-panel)] h-full overflow-hidden ${
            selectedGmailId ? 'flex' : 'hidden lg:flex'
          }`}
        >
          {/* If no email selected in desktop view */}
          {!selectedGmailId ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-[var(--text-tertiary)]">
              <div className="w-16 h-16 rounded-2xl bg-[var(--bg-inset)] border border-[var(--border-subtle)] flex items-center justify-center mb-4 text-[var(--text-muted)]">
                <Mail className="w-8 h-8 opacity-50" />
              </div>
              <h2 className="text-base font-bold text-[var(--text-secondary)]">Select an email</h2>
              <p className="text-xs text-[var(--text-muted)] mt-1 max-w-sm">
                Select an email from the left pane to view full forensic telemetry, authentication
                results, geo-routing, and AI threat reasoning.
              </p>
            </div>
          ) : isLoadingDetail ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-[var(--text-tertiary)] gap-3">
              <RefreshCw className="w-7 h-7 animate-spin text-blue-500" />
              <p className="text-sm font-semibold text-[var(--text-secondary)]">
                Extracting forensic telemetry & LLM reasoning...
              </p>
            </div>
          ) : detailError ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
              <AlertTriangle className="w-10 h-10 text-red-400 mb-2" />
              <h3 className="text-sm font-bold text-[var(--text-primary)]">
                Forensic Analysis Unavailable
              </h3>
              <p className="text-xs text-red-400 mt-1 max-w-md">{detailError}</p>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => handleSelectItem(selectedGmailId)}
                className="mt-4"
              >
                Retry
              </Button>
            </div>
          ) : selectedDetail ? (
            <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6">
              {/* Mobile Back Button */}
              <div className="lg:hidden flex items-center justify-between pb-3 border-b border-[var(--border-subtle)]">
                <button
                  type="button"
                  onClick={handleBackToList}
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors"
                >
                  <ArrowLeft className="w-4 h-4" />
                  <span>Back to Inbox</span>
                </button>
                <span className="text-[11px] text-[var(--text-tertiary)] font-mono">
                  {selectedDetail.gmail_id}
                </span>
              </div>

              {/* ───────────────────────────────────────────────────────────── */}
              {/* a. Header: Subject, From (defanged), Date, Gmail ID */}
              {/* ───────────────────────────────────────────────────────────── */}
              <div className="p-5 rounded-2xl bg-[var(--bg-surface)] border border-[var(--border-subtle)] shadow-xs space-y-3">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <h2 className="text-lg sm:text-xl font-bold tracking-tight text-[var(--text-primary)] break-words">
                    {selectedDetail.subject || currentItemMeta?.subject || '(No Subject)'}
                  </h2>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-tertiary)]">
                      ID: {selectedDetail.gmail_id || selectedGmailId}
                    </span>
                    <CopyButton
                      text={selectedDetail.gmail_id || selectedGmailId || ''}
                      size="sm"
                      label="Copy Gmail ID"
                    />
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-[var(--text-secondary)] pt-1 border-t border-[var(--border-subtle)]/70">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[var(--text-tertiary)]">From:</span>
                    <strong className="text-[var(--text-primary)]">
                      {selectedDetail.from_address || currentItemMeta?.from_address ? (
                        <DefangText
                          value={selectedDetail.from_address || currentItemMeta?.from_address || ''}
                        />
                      ) : (
                        'Unknown'
                      )}
                    </strong>
                  </div>

                  <div className="flex items-center gap-1.5">
                    <span className="text-[var(--text-tertiary)]">Date:</span>
                    <span>
                      {selectedDetail.date || currentItemMeta?.date || 'Unknown'}
                    </span>
                  </div>
                </div>
              </div>

              {/* ───────────────────────────────────────────────────────────── */}
              {/* b. RiskGauge + Severity Chip + Confidence */}
              {/* ───────────────────────────────────────────────────────────── */}
              <div className="p-5 rounded-2xl bg-[var(--bg-surface)] border border-[var(--border-subtle)] shadow-xs flex flex-col sm:flex-row items-center justify-between gap-6">
                <div className="flex items-center gap-5">
                  <VerdictGauge
                    score={isMarkedBenign ? 5 : selectedDetail.risk_score}
                    level={isMarkedBenign ? ('LOW' as RiskLevel) : selectedDetail.risk_level}
                    size={96}
                  />

                  <div className="space-y-1.5 text-left">
                    <div className="flex items-center gap-2">
                      <SeverityChip
                        severity={isMarkedBenign ? ('LOW' as RiskLevel) : selectedDetail.risk_level}
                        score={isMarkedBenign ? 5 : selectedDetail.risk_score}
                        size="md"
                      />
                      {isMarkedBenign && (
                        <Badge variant="success" size="xs">
                          User Marked Benign
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-[var(--text-secondary)]">
                      Threat Score: <strong>{isMarkedBenign ? '5 / 100' : (selectedDetail.risk_score != null ? `${selectedDetail.risk_score} / 100` : '—')}</strong>
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="px-3.5 py-2 rounded-xl bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-right">
                    <span className="block text-[10px] uppercase font-bold text-[var(--text-tertiary)]">
                      Model Confidence
                    </span>
                    <span className="text-sm font-black text-emerald-400">
                      {selectedDetail.confidence != null
                        ? `${Math.round(selectedDetail.confidence > 1 ? selectedDetail.confidence : selectedDetail.confidence * 100)}%`
                        : '—'}
                    </span>
                  </div>
                </div>
              </div>

              {/* ───────────────────────────────────────────────────────────── */}
              {/* c. AuthResultsPanel (SPF, DKIM, DMARC) */}
              {/* ───────────────────────────────────────────────────────────── */}
              {authResult && (
                <div className="space-y-2">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-tertiary)] px-1">
                    Authentication Telemetry
                  </h3>
                  <AuthResultsPanel authResult={authResult} />
                </div>
              )}

              {/* ───────────────────────────────────────────────────────────── */}
              {/* d. GeoPanel + WorldMapMarker (One per sender IP) */}
              {/* ───────────────────────────────────────────────────────────── */}
              {geoResults && geoResults.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-tertiary)] px-1">
                    Origin Geolocation & Routing
                  </h3>
                  {geoResults.map((geo: any, idx: number) => (
                    <div key={geo.ip || idx} className="space-y-2">
                      <WorldMapMarker
                        lat={geo.lat}
                        lon={geo.lon}
                        country={geo.country}
                        city={geo.city}
                        ip={geo.ip}
                      />
                      <GeoPanel geolocation={geo} ip={geo.ip} hopIndex={idx + 1} />
                    </div>
                  ))}
                </div>
              )}

              {/* ───────────────────────────────────────────────────────────── */}
              {/* e. AI Analysis Section (Mandatory LLM reasoning + Anonymized) */}
              {/* ───────────────────────────────────────────────────────────── */}
              <div className="space-y-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-tertiary)] px-1">
                  AI Forensic Reasoning
                </h3>
                <AIAnalysisSection
                  llmResult={llmResult}
                  anonymizedPrompt={anonymizedPrompt}
                />
              </div>

              {/* ───────────────────────────────────────────────────────────── */}
              {/* f. AttachmentList */}
              {/* ───────────────────────────────────────────────────────────── */}
              {attachments && attachments.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-tertiary)] px-1">
                    Extracted Attachments ({attachments.length})
                  </h3>
                  <AttachmentList attachments={attachments} />
                </div>
              )}

              {/* ───────────────────────────────────────────────────────────── */}
              {/* g. SanitizedBodyViewer */}
              {/* ───────────────────────────────────────────────────────────── */}
              {(sanitizedHtml || plainBody) && (
                <div className="space-y-2">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-tertiary)] px-1">
                    Sanitized Email Body
                  </h3>
                  <SanitizedBodyViewer
                    sanitizedHtml={sanitizedHtml}
                    plainBody={plainBody}
                  />
                </div>
              )}

              {/* ───────────────────────────────────────────────────────────── */}
              {/* h. Action Buttons: [Open Full Report] [Mark Not Threat] */}
              {/* ───────────────────────────────────────────────────────────── */}
              <div className="pt-4 border-t border-[var(--border-subtle)] flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Button
                    variant="primary"
                    size="md"
                    onClick={() => navigate(`/scan/${selectedDetail.id}`)}
                    className="flex items-center gap-2 font-medium"
                  >
                    <ExternalLink className="w-4 h-4" />
                    <span>Open Full Report</span>
                  </Button>

                  <Button
                    variant="secondary"
                    size="md"
                    onClick={handleMarkBenign}
                    disabled={isMarkedBenign}
                    className="flex items-center gap-2 font-medium"
                  >
                    <CheckCircle2
                      className={`w-4 h-4 ${isMarkedBenign ? 'text-emerald-400' : ''}`}
                    />
                    <span>{isMarkedBenign ? 'Marked Benign' : 'Mark Not Threat'}</span>
                  </Button>
                </div>

                <span className="text-xs text-[var(--text-tertiary)] font-mono">
                  Scan ID: {selectedDetail.id}
                </span>
              </div>
            </div>
          ) : null}
        </main>
      </div>
    </div>
  );
};
