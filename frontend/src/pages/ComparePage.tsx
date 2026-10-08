import React, { useState, useEffect, useMemo } from 'react';
import { useParams, Link, useNavigate, useSearchParams } from 'react-router-dom';
import {
  ArrowLeft,
  ArrowRight,
  TrendingUp,
  TrendingDown,
  Minus,
  AlertTriangle,
  ShieldCheck,
  GitCompare,
  Clock,
  ExternalLink,
  ChevronRight,
  Layers,
  Sparkles,
  Info,
  RotateCcw,
  Network,
  CornerDownRight,
  ShieldAlert,
  CheckCircle2,
  ListFilter,
} from 'lucide-react';
import { api } from '../api/client';
import type { CompareResult, Scan, RiskLevel } from '../types/threat';
import { Button } from '../components/primitives/Button';
import { Badge } from '../components/primitives/Badge';
import { EmptyState } from '../components/primitives/EmptyState';
import { ErrorState } from '../components/primitives/ErrorState';
import { Skeleton } from '../components/primitives/Skeleton';
import { DiffHeader } from '../components/domain/DiffHeader';
import { DiffRow } from '../components/domain/DiffRow';
import { DefangText } from '../components/domain/DefangText';
import { SeverityChip } from '../components/primitives/SeverityChip';

export function ComparePage() {
  const { id1, id2 } = useParams<{ id1?: string; id2?: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const stateOverride = searchParams.get('state');

  const [compareData, setCompareData] = useState<CompareResult | null>(null);
  const [scanA, setScanA] = useState<Scan | null>(null);
  const [scanB, setScanB] = useState<Scan | null>(null);
  const [allScans, setAllScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Picker selection state when /compare is loaded without two IDs
  const [pickerId1, setPickerId1] = useState<string>(id1 || '');
  const [pickerId2, setPickerId2] = useState<string>(id2 || '');

  const scenarioOverride = searchParams.get('scenario');

  useEffect(() => {
    if (scenarioOverride) {
      loadScenario(scenarioOverride);
    } else if (id1 && id2) {
      loadComparison(id1, id2);
    } else {
      loadScansForPicker();
    }
  }, [id1, id2, scenarioOverride]);

  const loadScenario = (scenario: string) => {
    setLoading(false);
    const baseScan: Scan = {
      id: 'scan-baseline-01',
      target: 'api.service-cdn.org/auth',
      target_type: 'url',
      timestamp: '2026-03-29T10:00:00Z',
      risk_score: 25,
      risk_level: 'LOW',
      confidence: 88,
      detection_count: 0,
      total_engines: 5,
      factors: [],
      group_breakdown: {},
      raw_summary: {},
      sources: {},
      attack_chain: { nodes: [], links: [] },
      is_demo: true,
      explanation: 'Baseline investigation.',
      recommended_action: 'Continue monitoring.',
    };

    if (scenario === 'no-change') {
      const sA: Scan = { ...baseScan, id: 'scan-base-101', risk_score: 25, risk_level: 'LOW' };
      const sB: Scan = { ...baseScan, id: 'scan-curr-102', risk_score: 25, risk_level: 'LOW', timestamp: '2026-03-29T11:00:00Z' };
      setScanA(sA);
      setScanB(sB);
      setCompareData({
        score_delta: 0,
        detection_delta: 0,
        level_change: { from: 'LOW', to: 'LOW', changed: false },
        factors_added: [],
        factors_removed: [],
        factors_changed: [],
        redirect_chain_change: { final_domain_changed: false, hop_count_delta: 0, from_domain: '', to_domain: '', from_hops: 0, to_hops: 0 },
        reputation_changes: { newly_flagged: [], unflagged: [] },
        summary: 'No material change between scans',
      });
    } else if (scenario === 'escalation') {
      const sA: Scan = { ...baseScan, id: 'scan-base-101', risk_score: 25, risk_level: 'LOW' };
      const sB: Scan = { ...baseScan, id: 'scan-curr-102', risk_score: 82, risk_level: 'HIGH', timestamp: '2026-03-29T11:00:00Z' };
      setScanA(sA);
      setScanB(sB);
      setCompareData({
        score_delta: 57,
        detection_delta: 2,
        level_change: { from: 'LOW', to: 'HIGH', changed: true },
        factors_added: [
          { id: 'f-gsb', group: 'REPUTATION_LISTS', type: 'indicator', severity: 'high', points: 30, title: 'Google Safe Browsing Flag', description: 'Listed for deceptive content', source: 'SafeBrowsing' }
        ],
        factors_removed: [],
        factors_changed: [
          { id: 'f-rdap', title: 'Domain Registration Age', old_points: 10, new_points: 25, old_severity: 'low', new_severity: 'high', source: 'RDAP' }
        ],
        redirect_chain_change: { final_domain_changed: false, hop_count_delta: 0, from_domain: '', to_domain: '', from_hops: 0, to_hops: 0 },
        reputation_changes: { newly_flagged: ['SafeBrowsing'], unflagged: [] },
        summary: 'Score escalated significantly',
      });
    } else if (scenario === 'de-escalation') {
      const sA: Scan = { ...baseScan, id: 'scan-base-101', risk_score: 82, risk_level: 'HIGH' };
      const sB: Scan = { ...baseScan, id: 'scan-curr-102', risk_score: 25, risk_level: 'LOW', timestamp: '2026-03-29T11:00:00Z' };
      setScanA(sA);
      setScanB(sB);
      setCompareData({
        score_delta: -57,
        detection_delta: -2,
        level_change: { from: 'HIGH', to: 'LOW', changed: true },
        factors_added: [],
        factors_removed: [
          { id: 'f-gsb', group: 'REPUTATION_LISTS', type: 'indicator', severity: 'high', points: 30, title: 'Google Safe Browsing Flag', description: 'Remediated', source: 'SafeBrowsing' }
        ],
        factors_changed: [
          { id: 'f-rdap', title: 'Domain Registration Age', old_points: 25, new_points: 10, old_severity: 'high', new_severity: 'low', source: 'RDAP' }
        ],
        redirect_chain_change: { final_domain_changed: false, hop_count_delta: 0, from_domain: '', to_domain: '', from_hops: 0, to_hops: 0 },
        reputation_changes: { newly_flagged: [], unflagged: ['SafeBrowsing'] },
        summary: 'Risk resolved',
      });
    } else if (scenario === 'added-only') {
      const sA: Scan = { ...baseScan, id: 'scan-base-101', risk_score: 25, risk_level: 'LOW' };
      const sB: Scan = { ...baseScan, id: 'scan-curr-102', risk_score: 45, risk_level: 'MEDIUM', timestamp: '2026-03-29T11:00:00Z' };
      setScanA(sA);
      setScanB(sB);
      setCompareData({
        score_delta: 20,
        detection_delta: 1,
        level_change: { from: 'LOW', to: 'MEDIUM', changed: true },
        factors_added: [
          { id: 'f-dns', group: 'DOMAIN_INFRA', type: 'indicator', severity: 'medium', points: 20, title: 'Fast-Flux DNS Resolution Pattern', description: 'Anomalous IP rotation', source: 'DNS' }
        ],
        factors_removed: [],
        factors_changed: [],
        redirect_chain_change: { final_domain_changed: false, hop_count_delta: 0, from_domain: '', to_domain: '', from_hops: 0, to_hops: 0 },
        reputation_changes: { newly_flagged: [], unflagged: [] },
        summary: 'Added factor detected',
      });
    } else if (scenario === 'removed-only') {
      const sA: Scan = { ...baseScan, id: 'scan-base-101', risk_score: 45, risk_level: 'MEDIUM' };
      const sB: Scan = { ...baseScan, id: 'scan-curr-102', risk_score: 25, risk_level: 'LOW', timestamp: '2026-03-29T11:00:00Z' };
      setScanA(sA);
      setScanB(sB);
      setCompareData({
        score_delta: -20,
        detection_delta: -1,
        level_change: { from: 'MEDIUM', to: 'LOW', changed: true },
        factors_added: [],
        factors_removed: [
          { id: 'f-dns', group: 'DOMAIN_INFRA', type: 'indicator', severity: 'medium', points: 20, title: 'Fast-Flux DNS Resolution Pattern', description: 'Resolved', source: 'DNS' }
        ],
        factors_changed: [],
        redirect_chain_change: { final_domain_changed: false, hop_count_delta: 0, from_domain: '', to_domain: '', from_hops: 0, to_hops: 0 },
        reputation_changes: { newly_flagged: [], unflagged: [] },
        summary: 'Factor removed',
      });
    }
  };

  const loadScansForPicker = async () => {
    setLoading(true);
    try {
      const scansList = await api.getScans(undefined, 50);
      setAllScans(scansList);
      if (scansList.length >= 2) {
        setPickerId1(scansList[1].id);
        setPickerId2(scansList[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve available scans');
    } finally {
      setLoading(false);
    }
  };

  const loadComparison = async (scanId1: string, scanId2: string) => {
    setLoading(true);
    setError(null);
    try {
      const [diff, s1, s2] = await Promise.all([
        api.compareScans(scanId1, scanId2),
        api.getScan(scanId1),
        api.getScan(scanId2),
      ]);
      setCompareData(diff);
      setScanA(s1);
      setScanB(s2);
    } catch (err: any) {
      setError(err.message || 'Failed to compare scans.');
    } finally {
      setLoading(false);
    }
  };

  // Deterministic summary sentence
  const conclusionSentence = useMemo(() => {
    if (!scanA || !scanB) return '';
    const delta = scanB.risk_score - scanA.risk_score;

    if (delta > 0) {
      return `Target risk escalated from ${scanA.risk_level} (${scanA.risk_score}/100) to ${scanB.risk_level} (${scanB.risk_score}/100) (+${delta} pts) due to newly detected threat indicators.`;
    } else if (delta < 0) {
      return `Target risk improved from ${scanA.risk_level} (${scanA.risk_score}/100) to ${scanB.risk_level} (${scanB.risk_score}/100) (${delta} pts) following resolution of suspicious factors.`;
    }
    return `No material delta detected: target risk remained stable at ${scanA.risk_level} (${scanA.risk_score}/100) across both investigation checkpoints.`;
  }, [scanA, scanB]);

  // Redirect hops diff calculation
  const hopsDiff = useMemo(() => {
    const hopsA = scanA?.raw_summary?.redirects?.hops || [];
    const hopsB = scanB?.raw_summary?.redirects?.hops || [];
    const maxLen = Math.max(hopsA.length, hopsB.length);

    const diffs: {
      index: number;
      hopA?: any;
      hopB?: any;
      status: 'identical' | 'changed' | 'added' | 'removed';
    }[] = [];

    for (let i = 0; i < maxLen; i++) {
      const hA = hopsA[i];
      const hB = hopsB[i];

      if (hA && !hB) {
        diffs.push({ index: i, hopA: hA, status: 'removed' });
      } else if (!hA && hB) {
        diffs.push({ index: i, hopB: hB, status: 'added' });
      } else if (hA && hB) {
        const isSame = (hA.url || hA.domain) === (hB.url || hB.domain);
        diffs.push({ index: i, hopA: hA, hopB: hB, status: isSame ? 'identical' : 'changed' });
      }
    }

    return diffs;
  }, [scanA, scanB]);

  // Reputation sources diff
  const sourcesDiff = useMemo(() => {
    if (!scanA?.sources || !scanB?.sources) return [];
    const keysA = Object.keys(scanA.sources);
    const keysB = Object.keys(scanB.sources);
    const allKeys = Array.from(new Set([...keysA, ...keysB]));

    return allKeys.map((k) => {
      const srcA = scanA.sources[k];
      const srcB = scanB.sources[k];
      const flagA = srcA?.flagged || (srcA?.malicious ?? 0) > 0;
      const flagB = srcB?.flagged || (srcB?.malicious ?? 0) > 0;

      return {
        key: k,
        statusA: flagA ? 'Flagged' : 'Clean',
        statusB: flagB ? 'Flagged' : 'Clean',
        changed: flagA !== flagB,
      };
    });
  }, [scanA, scanB]);

  // State Matrix Overrides
  if (stateOverride === 'loading' || (loading && !scanA && id1 && id2)) {
    return (
      <div className="max-w-6xl mx-auto py-8 px-4 space-y-6">
        <Skeleton className="w-1/3 h-8 rounded-lg" />
        <Skeleton className="w-full h-32 rounded-2xl" />
        <Skeleton className="w-full h-64 rounded-2xl" />
      </div>
    );
  }

  if (stateOverride === 'error' || (error && !scanA)) {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4">
        <ErrorState
          title="Comparison Failed"
          message={error || 'Unable to compute delta between specified scans.'}
          onRetry={() => id1 && id2 && loadComparison(id1, id2)}
        />
      </div>
    );
  }

  if (stateOverride === 'empty' || (!scenarioOverride && (!id1 || !id2))) {
    return (
      <div className="max-w-4xl mx-auto py-12 px-4 space-y-6 animate-in fade-in duration-150">
        <div className="text-center space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-xs font-mono">
            <GitCompare className="w-3.5 h-3.5" />
            <span>Investigation Drift Diff</span>
          </div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">Compare Threat Telemetry</h1>
          <p className="text-xs text-[var(--text-secondary)] max-w-md mx-auto">
            Select two investigation snapshots to inspect factor accretion, score evolution, and redirect hops.
          </p>
        </div>

        <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-[var(--text-primary)] block mb-1">
                Baseline Investigation (Prior)
              </label>
              <select
                value={pickerId1}
                aria-label="Baseline investigation snapshot"
                onChange={(e) => setPickerId1(e.target.value)}
                className="w-full p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-xs text-[var(--text-primary)] font-mono cursor-pointer"
              >
                {allScans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id} — {s.risk_level} ({s.risk_score} pts) · {s.target}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs font-semibold text-[var(--text-primary)] block mb-1">
                Current Investigation (Target)
              </label>
              <select
                value={pickerId2}
                aria-label="Current investigation snapshot"
                onChange={(e) => setPickerId2(e.target.value)}
                className="w-full p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-xs text-[var(--text-primary)] font-mono cursor-pointer"
              >
                {allScans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id} — {s.risk_level} ({s.risk_score} pts) · {s.target}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <Button
              variant="primary"
              size="md"
              disabled={!pickerId1 || !pickerId2 || pickerId1 === pickerId2}
              onClick={() => navigate(`/compare/${pickerId1}/${pickerId2}`)}
              className="flex items-center gap-2"
            >
              <span>Compute Diff</span>
              <ArrowRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </div>
    );
  }

  if (!scanA || !scanB || !compareData) return null;

  const scoreDelta = scanB.risk_score - scanA.risk_score;
  const addedFactors = (compareData as any).added_factors || compareData.factors_added || [];
  const removedFactors = (compareData as any).removed_factors || compareData.factors_removed || [];
  const changedFactors = (compareData as any).changed_factors || compareData.factors_changed || [];
  const totalFactorChanges = addedFactors.length + removedFactors.length + changedFactors.length;

  return (
    <div className="max-w-6xl mx-auto py-8 px-4 space-y-6 pb-16 animate-in fade-in duration-150">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Button variant="secondary" size="xs" onClick={() => navigate(-1)}>
            <ArrowLeft className="w-3.5 h-3.5 mr-1" />
            Back
          </Button>
          <div>
            <h1 className="text-xl font-bold text-[var(--text-primary)] flex items-center gap-2">
              <GitCompare className="w-5 h-5 text-blue-400" />
              <span>Comparative Threat Evolution</span>
            </h1>
            <div className="text-xs text-[var(--text-secondary)] mt-0.5 flex items-center gap-1.5">
              <span>Target:</span>
              <DefangText value={scanA.target} showCopy={true} className="font-mono text-blue-400 font-semibold" />
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="secondary" size="xs" onClick={() => navigate(`/scans/${scanA.id}`)}>
            View Baseline ({scanA.id})
          </Button>
          <Button variant="secondary" size="xs" onClick={() => navigate(`/scans/${scanB.id}`)}>
            View Current ({scanB.id})
          </Button>
        </div>
      </div>

      {/* 1. DIFF HEADER */}
      <DiffHeader
        scanA={{
          id: scanA.id,
          timestamp: scanA.timestamp,
          score: scanA.risk_score,
          level: scanA.risk_level,
        }}
        scanB={{
          id: scanB.id,
          timestamp: scanB.timestamp,
          score: scanB.risk_score,
          level: scanB.risk_level,
        }}
        scoreDelta={scoreDelta}
        summarySentence={conclusionSentence}
      />

      {/* 2. FACTOR ACCRETION / REMOVAL DIFF */}
      <div className="p-5 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
            <ListFilter className="w-4 h-4 text-blue-400" />
            Contributing Factor Accretion & Delta ({totalFactorChanges} changes)
          </h3>
          <span className="text-[11px] font-mono text-[var(--text-tertiary)]">
            Deterministic scoring delta
          </span>
        </div>

        {totalFactorChanges > 0 ? (
          <div className="space-y-2">
            {/* ADDED FACTORS */}
            {addedFactors.map((f, i) => (
              <DiffRow
                key={`added-${i}`}
                changeType="added"
                title={f.title}
                source={f.source || f.group}
                points={f.points}
                severity={f.severity}
              />
            ))}

            {/* CHANGED FACTORS */}
            {changedFactors.map((f, i) => (
              <DiffRow
                key={`changed-${i}`}
                changeType="changed"
                title={f.title}
                source={f.source || f.group}
                oldPoints={f.old_points}
                newPoints={f.new_points}
                oldSeverity={f.old_severity}
                newSeverity={f.new_severity}
              />
            ))}

            {/* REMOVED FACTORS */}
            {removedFactors.map((f, i) => (
              <DiffRow
                key={`removed-${i}`}
                changeType="removed"
                title={f.title}
                source={f.source || f.group}
                points={f.points}
                severity={f.severity}
              />
            ))}
          </div>
        ) : (
          <div className="p-8 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] text-center space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
            <div className="text-sm font-semibold text-[var(--text-primary)]">
              No material change between these scans
            </div>
            <p className="text-xs text-[var(--text-secondary)] max-w-sm mx-auto">
              All scoring factors, threat weights, and detections remained identical across both checkpoints.
            </p>
          </div>
        )}
      </div>

      {/* 3. REDIRECT CHAIN HOP-BY-HOP DIFF */}
      {hopsDiff.length > 0 && (
        <div className="p-5 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
              <Network className="w-4 h-4 text-indigo-400" />
              Redirect Flow Hop-by-Hop Alignment
            </h3>
            <p className="text-[11px] text-[var(--text-secondary)] mt-0.5">
              Execution path verification between baseline and current request chain.
            </p>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {hopsDiff.map((d) => (
              <div
                key={`hop-${d.index}`}
                className={`p-3 rounded-xl border flex items-center justify-between gap-4 ${
                  d.status === 'added'
                    ? 'border-red-500/30 bg-red-500/5 text-red-400'
                    : d.status === 'removed'
                    ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-400'
                    : d.status === 'changed'
                    ? 'border-amber-500/30 bg-amber-500/5 text-amber-300'
                    : 'border-[var(--border-subtle)] bg-[var(--bg-inset)] text-[var(--text-secondary)]'
                }`}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-[10px] uppercase font-bold text-[var(--text-tertiary)] shrink-0">
                    Hop #{d.index}
                  </span>
                  <div className="truncate">
                    {d.hopB ? (
                      <DefangText value={d.hopB.url || d.hopB.domain || `Hop ${d.index}`} />
                    ) : (
                      <span className="line-through opacity-70">
                        <DefangText value={d.hopA.url || d.hopA.domain || `Hop ${d.index}`} />
                      </span>
                    )}
                  </div>
                </div>

                <div className="shrink-0">
                  {d.status === 'added' && <Badge variant="critical" size="xs">Inserted Hop</Badge>}
                  {d.status === 'removed' && <Badge variant="low" size="xs">Bypassed Hop</Badge>}
                  {d.status === 'changed' && <Badge variant="medium" size="xs">Altered Destination</Badge>}
                  {d.status === 'identical' && <Badge variant="neutral" size="xs">Consistent</Badge>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. REPUTATION SOURCES DIFF */}
      {sourcesDiff.length > 0 && (
        <div className="p-5 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-purple-400" />
              Provider Intelligence Reputation Delta
            </h3>
            <p className="text-[11px] text-[var(--text-secondary)] mt-0.5">
              Blacklist listing changes observed between scan events.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {sourcesDiff.map((s) => (
              <div
                key={s.key}
                className={`p-3 rounded-xl border flex items-center justify-between text-xs ${
                  s.changed
                    ? 'border-amber-500/40 bg-amber-500/5'
                    : 'border-[var(--border-subtle)] bg-[var(--bg-inset)]'
                }`}
              >
                <span className="font-semibold text-[var(--text-primary)]">{s.key}</span>
                <div className="flex items-center gap-1.5 font-mono text-[11px]">
                  <span className={s.statusA === 'Flagged' ? 'text-red-400 font-bold' : 'text-[var(--text-tertiary)]'}>
                    {s.statusA}
                  </span>
                  <ArrowRight className="w-3 h-3 text-[var(--text-tertiary)]" />
                  <span className={s.statusB === 'Flagged' ? 'text-red-400 font-bold' : 'text-[var(--text-tertiary)]'}>
                    {s.statusB}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
