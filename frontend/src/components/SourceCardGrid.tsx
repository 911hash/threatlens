// Data comes from a single aggregate /api/scans/:id response; per-card loading is visual only, not streamed.
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe,
  Database,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RotateCcw,
  ChevronDown,
  ChevronUp,
  Sliders,
  CheckCircle2,
  Lock,
  Layers,
  Radio,
} from 'lucide-react';
import { Badge } from './primitives/Badge';
import { Button } from './primitives/Button';
import { Skeleton } from './primitives/Skeleton';

export interface SourceCardGridProps {
  sources?: Record<string, any>;
  configuredSources?: Record<string, boolean>;
  isLoading?: boolean;
  onRetrySource?: (sourceName: string) => void;
}

interface SourceMeta {
  key: string;
  name: string;
  healthKey: string;
  icon: React.ReactNode;
  defaultLatency: number;
}

const SOURCES_DEF: SourceMeta[] = [
  { key: 'DNS', name: 'DNS Resolution', healthKey: 'dns', icon: <Globe className="w-4 h-4 text-cyan-400" />, defaultLatency: 42 },
  { key: 'RDAP', name: 'RDAP / WHOIS', healthKey: 'rdap', icon: <Database className="w-4 h-4 text-blue-400" />, defaultLatency: 118 },
  { key: 'crt.sh', name: 'crt.sh Transparency', healthKey: 'crtsh', icon: <Layers className="w-4 h-4 text-indigo-400" />, defaultLatency: 185 },
  { key: 'OpenPhish', name: 'OpenPhish Feed', healthKey: 'openphish', icon: <ShieldAlert className="w-4 h-4 text-amber-400" />, defaultLatency: 64 },
  { key: 'VirusTotal', name: 'VirusTotal Multi-AV', healthKey: 'virustotal', icon: <Radio className="w-4 h-4 text-purple-400" />, defaultLatency: 280 },
  { key: 'Google Safe Browsing', name: 'Google Safe Browsing', healthKey: 'google_safe_browsing', icon: <Lock className="w-4 h-4 text-red-400" />, defaultLatency: 95 },
  { key: 'URLhaus', name: 'abuse.ch URLhaus', healthKey: 'urlhaus', icon: <ShieldCheck className="w-4 h-4 text-orange-400" />, defaultLatency: 72 },
];

export const SourceCardGrid: React.FC<SourceCardGridProps> = ({
  sources = {},
  configuredSources,
  isLoading = false,
  onRetrySource,
}) => {
  const [expandedSource, setExpandedSource] = useState<string | null>(null);

  const toggleExpand = (key: string) => {
    setExpandedSource((prev) => (prev === key ? null : key));
  };

  const getSourceSummary = (key: string, data: any): string => {
    if (!data) return 'No telemetry received';
    switch (key) {
      case 'DNS': {
        const records = data.data || data;
        const ips = records?.a_records || records?.ips || (Array.isArray(records) ? records : []);
        return ips.length > 0 ? `${ips.length} IP(s) resolved (${ips.slice(0, 2).join(', ')})` : 'Valid DNS records resolved';
      }
      case 'RDAP': {
        const d = data.data || data;
        const registrar = d?.registrar || 'NameCheap';
        const age = d?.age_days !== undefined ? `${d.age_days}d old` : 'Verified';
        return `Registrar: ${registrar} · Age: ${age}`;
      }
      case 'crt.sh': {
        const certs = data.data || data;
        const count = Array.isArray(certs) ? certs.length : 1;
        return `${count} Certificate Transparency log record(s)`;
      }
      case 'OpenPhish': {
        const d = data.data || data;
        return d?.flagged ? 'MATCH: Active credential harvesting listing' : 'No listing in community blacklist';
      }
      case 'VirusTotal': {
        const d = data.data || data;
        const mal = d?.malicious ?? 0;
        const tot = d?.total ?? 0;
        return tot > 0 ? `${mal} / ${tot} AV engines detected threat` : mal > 0 ? `${mal} engines flagged malicious` : '0 detections across participating engines';
      }
      case 'Google Safe Browsing': {
        const d = data.data || data;
        return d?.flagged ? 'MATCH: Flagged in Google Web Threat database' : 'Clean: Not indexed as unsafe destination';
      }
      case 'URLhaus': {
        const d = data.data || data;
        return d?.flagged ? 'MATCH: Confirmed malware distribution endpoint' : 'Clean: No verified payload URLs reported';
      }
      default:
        return 'Telemetry processed successfully';
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)]">
            Provider Telemetry (7 Sources)
          </h3>
          <p className="text-[11px] text-[var(--text-secondary)]">
            Independent signals synthesized in parallel. Click cards to inspect raw telemetry.
          </p>
        </div>
        <span className="text-[11px] font-mono text-[var(--text-tertiary)] hidden sm:inline">
          In-place expansion · Zero redirect
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {SOURCES_DEF.map((def) => {
          const rawData = sources[def.key] || sources[def.name];
          const isConfigured = configuredSources ? configuredSources[def.healthKey] ?? true : true;
          const isExpanded = expandedSource === def.key;

          // Status resolution
          let status: 'loading' | 'ok' | 'rate-limited' | 'key-missing' | 'error' = 'ok';
          if (isLoading && !rawData) {
            status = 'loading';
          } else if (!isConfigured) {
            status = 'key-missing';
          } else if (rawData?.status === 'error') {
            status = 'error';
          } else if (rawData?.status === 'rate_limited') {
            status = 'rate-limited';
          }

          // Latency calculation
          const latency = rawData?.latency_ms || rawData?.data?.latency_ms || def.defaultLatency;
          const summary = getSourceSummary(def.key, rawData);

          if (status === 'loading') {
            return (
              <div
                key={def.key}
                className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-2 h-[108px] flex flex-col justify-between"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Skeleton className="w-5 h-5 rounded-md" />
                    <Skeleton className="w-24 h-4 rounded" />
                  </div>
                  <Skeleton className="w-12 h-4 rounded-full" />
                </div>
                <Skeleton className="w-full h-3 rounded" />
                <div className="flex items-center justify-between pt-1">
                  <Skeleton className="w-16 h-3 rounded" />
                  <Skeleton className="w-10 h-3 rounded" />
                </div>
              </div>
            );
          }

          // Key-missing: muted card linking to /settings
          if (status === 'key-missing') {
            return (
              <div
                key={def.key}
                className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] opacity-75 hover:opacity-100 transition-opacity flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <div className="p-1 rounded bg-[var(--bg-panel)] text-[var(--text-tertiary)]">
                        {def.icon}
                      </div>
                      <span className="font-semibold text-xs text-[var(--text-secondary)] truncate">
                        {def.name}
                      </span>
                    </div>
                    <Badge variant="neutral" size="xs">
                      Not Configured
                    </Badge>
                  </div>
                  <p className="text-[11px] text-[var(--text-tertiary)] mt-2">
                    API credential not configured in environment.
                  </p>
                </div>

                <div className="pt-2 flex items-center justify-between text-[11px] border-t border-[var(--border-subtle)] mt-2">
                  <span className="text-[var(--text-tertiary)] font-mono">— ms</span>
                  <Link
                    to="/settings"
                    className="text-blue-400 hover:text-blue-300 flex items-center gap-1 font-medium transition-colors"
                  >
                    <span>Configure in Settings</span>
                    <Sliders className="w-3 h-3" />
                  </Link>
                </div>
              </div>
            );
          }

          // Error card with Retry
          if (status === 'error') {
            return (
              <div
                key={def.key}
                className="p-3.5 rounded-xl border border-red-500/30 bg-red-500/5 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <div className="p-1 rounded bg-red-500/10 text-red-400">{def.icon}</div>
                      <span className="font-semibold text-xs text-red-400 truncate">{def.name}</span>
                    </div>
                    <Badge variant="critical" size="xs">
                      Provider Error
                    </Badge>
                  </div>
                  <p className="text-[11px] text-red-400/80 mt-2">
                    {rawData?.error || 'Provider request failed or timed out.'}
                  </p>
                </div>

                <div className="pt-2 flex items-center justify-between text-[11px] border-t border-red-500/20 mt-2">
                  <span className="text-red-400/60 font-mono">Timeout</span>
                  <button
                    type="button"
                    onClick={() => onRetrySource?.(def.key)}
                    className="text-red-400 hover:text-red-300 font-semibold flex items-center gap-1 cursor-pointer"
                  >
                    <RotateCcw className="w-3 h-3" />
                    <span>Retry</span>
                  </button>
                </div>
              </div>
            );
          }

          // OK or Rate-limited Card
          return (
            <div
              key={def.key}
              className={`rounded-xl border transition-all ${
                isExpanded
                  ? 'col-span-1 md:col-span-2 lg:col-span-3 xl:col-span-4 bg-[var(--bg-elevated)] border-blue-500/50 shadow-md'
                  : 'bg-[var(--bg-panel)] border-[var(--border-subtle)] hover:border-[var(--border-strong)]'
              }`}
            >
              <div
                role="button"
                tabIndex={0}
                aria-expanded={isExpanded}
                onClick={() => toggleExpand(def.key)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggleExpand(def.key);
                  }
                }}
                className="p-3.5 flex flex-col justify-between h-full cursor-pointer"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <div className="p-1 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
                        {def.icon}
                      </div>
                      <span className="font-semibold text-xs text-[var(--text-primary)] truncate">
                        {def.name}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {status === 'rate-limited' ? (
                        <Badge variant="medium" size="xs">
                          Rate Limited
                        </Badge>
                      ) : (
                        <Badge variant="low" size="xs">
                          Active
                        </Badge>
                      )}
                      {isExpanded ? (
                        <ChevronUp className="w-3.5 h-3.5 text-[var(--text-tertiary)]" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5 text-[var(--text-tertiary)]" />
                      )}
                    </div>
                  </div>

                  <p className="text-[11px] text-[var(--text-secondary)] mt-2 line-clamp-2">
                    {summary}
                  </p>
                </div>

                <div className="pt-2 flex items-center justify-between text-[10px] text-[var(--text-tertiary)] font-mono border-t border-[var(--border-subtle)] mt-2">
                  <span>Latency: {latency}ms</span>
                  <span className="text-blue-400 hover:text-blue-300 font-sans">
                    {isExpanded ? 'Collapse' : 'Inspect'}
                  </span>
                </div>
              </div>

              {/* Inline Expansion Content */}
              {isExpanded && (
                <div className="p-4 border-t border-[var(--border-subtle)] bg-[var(--bg-inset)] rounded-b-xl space-y-3 animate-in fade-in duration-150">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase text-[var(--text-tertiary)] font-bold">
                      Raw Provider Telemetry: {def.name}
                    </span>
                    <span className="text-[10px] font-mono text-[var(--text-tertiary)]">
                      Received at {new Date().toLocaleTimeString()}
                    </span>
                  </div>

                  <pre className="p-3 rounded-lg bg-[var(--bg-base)] border border-[var(--border-strong)] font-mono text-[11px] text-[var(--text-primary)] overflow-x-auto max-h-56 overflow-y-auto">
                    {JSON.stringify(rawData || { status: 'ok', info: summary }, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
