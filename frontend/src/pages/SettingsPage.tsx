import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Sliders,
  Key,
  Shield,
  Eye,
  EyeOff,
  Sparkles,
  Lock,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  FileText,
  Clock,
  Compass,
  Palette,
  Layout,
  Database,
  Trash2,
} from 'lucide-react';
import { useTheme } from '../design/ThemeContext';
import { useDefang } from '../design/DefangContext';
import { useLocalStorage } from '../hooks/useLocalStorage';
import { useHealth } from '../hooks/useHealth';
import { useThreatQuery } from '../hooks/useThreatQuery';
import { useToast } from '../components/primitives/Toast';
import { Button } from '../components/primitives/Button';
import { Badge } from '../components/primitives/Badge';
import { StatusDot } from '../components/primitives/StatusDot';
import { Modal } from '../components/primitives/Modal';
import { ErrorState } from '../components/primitives/ErrorState';
import { Skeleton } from '../components/primitives/Skeleton';
import { api } from '../api/client';
import type { HealthConfig } from '../types/threat';

export const SettingsPage: React.FC = () => {
  const toast = useToast();
  const [searchParams] = useSearchParams();
  const stateOverride = searchParams.get('state');

  const { theme, setTheme, density, setDensity } = useTheme();
  const { isDefanged, setDefanged } = useDefang();
  const [reportDefaultView, setReportDefaultView] = useLocalStorage<'plain' | 'technical'>('threatlens_report_view', 'plain');
  const { data: health } = useHealth();
  const {
    data: config,
    isLoading: isConfigLoading,
    isError: isConfigError,
    refetch: refetchConfig,
  } = useThreatQuery<HealthConfig>('health_config', () => api.getHealthConfig(), {
    staleMs: 30000,
  });

  const sourceDefinitions = [
    {
      key: 'virustotal',
      name: 'VirusTotal API Key',
      envVar: 'VIRUSTOTAL_API_KEY',
      type: 'keyed',
      description: 'Multi-engine antivirus correlation and malicious file reputation scoring.',
    },
    {
      key: 'google_safe_browsing',
      name: 'Google Safe Browsing Key',
      envVar: 'GOOGLE_SAFE_BROWSING_API_KEY',
      type: 'keyed',
      description: 'Google Web Threat blacklists for phishing, deceptive sites, and malware.',
    },
    {
      key: 'urlhaus',
      name: 'abuse.ch URLhaus Auth Key',
      envVar: 'ABUSECH_AUTH_KEY',
      type: 'keyed',
      description: 'High-confidence community malware URL and active payload distribution feed.',
    },
    {
      key: 'openphish',
      name: 'OpenPhish Phishing Feed',
      envVar: 'Public Feed (Keyless)',
      type: 'keyless',
      description: 'Zero-day phishing feed for targeted credentials theft and brand impersonation.',
    },
    {
      key: 'rdap',
      name: 'RDAP Domain Registry',
      envVar: 'RFC 7480/7481 (Keyless)',
      type: 'keyless',
      description: 'Registration Data Access Protocol for authoritative domain registry data.',
    },
    {
      key: 'dns',
      name: 'DNS Resolution Engine',
      envVar: 'System Socket (Keyless)',
      type: 'keyless',
      description: 'Authoritative nameserver and standard socket DNS record queries.',
    },
    {
      key: 'crtsh',
      name: 'crt.sh Certificate Logs',
      envVar: 'CT Logs (Keyless)',
      type: 'keyless',
      description: 'Certificate Transparency log search for subdomains and SSL history.',
    },
  ];

  // Privacy toggles state (stored in localStorage)
  const [allowVtUrlSubmission, setAllowVtUrlSubmission] = useLocalStorage<boolean>(
    'threatlens_allow_vt_url_submission',
    false
  );
  const [allowVtFileUpload, setAllowVtFileUpload] = useLocalStorage<boolean>(
    'threatlens_allow_vt_file_upload',
    false
  );

  // Scanning parameters state
  const [watchlistInterval, setWatchlistInterval] = useLocalStorage<number>(
    'threatlens_watchlist_interval',
    6
  );
  const [redirectBudget, setRedirectBudget] = useLocalStorage<number>(
    'threatlens_redirect_budget',
    5
  );
  const [requestTimeout, setRequestTimeout] = useLocalStorage<number>(
    'threatlens_request_timeout',
    15
  );

  // Demo modal confirmations
  const [isSeedModalOpen, setIsSeedModalOpen] = useState(false);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const [isSeeding, setIsSeeding] = useState(false);
  const [isResetting, setIsResetting] = useState(false);

  const handleSeedDemo = async () => {
    try {
      setIsSeeding(true);
      await api.seedDemo(false);
      toast.success('Demo intelligence dataset seeded', 'Dataset Ready');
      setIsSeedModalOpen(false);
    } catch (err: any) {
      toast.error(err.message || 'Seeding failed');
    } finally {
      setIsSeeding(false);
    }
  };

  const handleResetDemo = async () => {
    try {
      setIsResetting(true);
      await api.resetDemo();
      toast.success('Investigation history reset and cleanly re-seeded', 'Clean Slate');
      setIsResetModalOpen(false);
    } catch (err: any) {
      toast.error(err.message || 'Reset failed');
    } finally {
      setIsResetting(false);
    }
  };

  // State Matrix Overrides
  if (stateOverride === 'loading') {
    return (
      <div className="max-w-4xl mx-auto py-8 px-4 space-y-6">
        <Skeleton className="w-1/3 h-8 rounded-lg" />
        <Skeleton className="w-full h-44 rounded-2xl" />
        <Skeleton className="w-full h-44 rounded-2xl" />
      </div>
    );
  }

  if (stateOverride === 'error') {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4">
        <ErrorState
          title="Settings Configuration Failed"
          message="Simulated error: unable to synchronize system configuration."
          onRetry={() => window.location.reload()}
        />
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto py-8 px-4 space-y-8 pb-16 animate-in fade-in duration-150">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2">
          <Sliders className="w-6 h-6 text-blue-400" />
          <span>System & Engine Settings</span>
        </h1>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Provider credentials, scanning telemetry parameters, privacy safeguards, and interface appearance.
        </p>
      </div>

      {/* Top Banner: Single Demo Mode Banner when demo_mode is active */}
      {config?.demo_mode && (
        <div className="p-4 rounded-xl border border-purple-500/30 bg-purple-500/10 text-purple-300 flex items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 text-purple-400 shrink-0" />
            <span>
              <strong>Simulation Active:</strong> Some live threat intelligence credentials are not configured. Falling back to offline simulated datasets.
            </span>
          </div>
          <Badge variant="demo" size="xs">
            Simulation Active
          </Badge>
        </div>
      )}

      {/* SECTION 1: API KEYS & CREDENTIALS */}
      <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
        <div>
          <h2 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Key className="w-4 h-4 text-indigo-400" />
            <span>Threat Intelligence Sources & API Status</span>
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Live configuration status for third-party intelligence feeds. Secret keys are loaded securely server-side.
          </p>
        </div>

        {isConfigLoading && !config ? (
          <div className="space-y-3">
            {[1, 2, 3, 4].map((i) => (
              <Skeleton key={i} className="w-full h-16 rounded-xl" />
            ))}
          </div>
        ) : isConfigError && !config ? (
          <div className="p-6 rounded-xl border border-red-500/30 bg-red-500/5 text-center space-y-3">
            <p className="text-xs text-red-400 font-medium">Could not load configuration</p>
            <Button variant="outline" size="xs" onClick={() => refetchConfig()}>
              Retry
            </Button>
          </div>
        ) : (
          <div className="space-y-3 font-mono text-xs">
            {sourceDefinitions.map((item) => {
              const live = config?.sources?.[item.key];
              const isConfigured = live?.configured ?? false;
              const type = live?.type ?? item.type;

              let dotStatus: 'healthy' | 'degraded' | 'unavailable' = 'healthy';
              let statusText = 'Configured';
              let badgeVariant: 'success' | 'warning' | 'neutral' = 'success';

              if (isConfigured) {
                dotStatus = 'healthy';
                statusText = 'Configured';
                badgeVariant = 'success';
              } else if (type === 'keyed') {
                dotStatus = 'degraded';
                statusText = 'Not set';
                badgeVariant = 'warning';
              } else {
                dotStatus = 'unavailable';
                statusText = 'Unavailable';
                badgeVariant = 'neutral';
              }

              return (
                <div
                  key={item.key}
                  className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-[var(--text-primary)] font-sans">{item.name}</span>
                      <code className="text-[10px] text-[var(--text-tertiary)] bg-[var(--bg-panel)] px-1.5 py-0.5 rounded border border-[var(--border-subtle)]">
                        {item.envVar}
                      </code>
                    </div>
                    <p className="text-[11px] text-[var(--text-secondary)] font-sans">
                      {item.description}
                    </p>
                  </div>

                  <div className="flex items-center gap-2.5 shrink-0">
                    <StatusDot
                      status={dotStatus}
                      size="sm"
                      pulse={isConfigured}
                    />
                    <span className="text-[11px] text-[var(--text-secondary)] select-none">
                      {statusText}
                    </span>
                    <Badge variant={badgeVariant} size="xs">
                      {statusText}
                    </Badge>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* SECTION: PROVIDER CHAIN */}
      <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
        <div>
          <h2 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-amber-400" />
            <span>LLM Reasoning Provider Chain</span>
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Provider-agnostic AI reasoning pipeline. Automatically cascades through fallbacks upon rate limits.
          </p>
        </div>

        {isConfigLoading && !config ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="w-full h-16 rounded-xl" />
            ))}
          </div>
        ) : isConfigError && !config ? (
          <div className="p-6 rounded-xl border border-red-500/30 bg-red-500/5 text-center space-y-3">
            <p className="text-xs text-red-400 font-medium">Could not load configuration</p>
            <Button variant="outline" size="xs" onClick={() => refetchConfig()}>
              Retry
            </Button>
          </div>
        ) : (
          <div className="space-y-3 font-mono text-xs">
            {[
              {
                role: 'Primary Provider',
                name: 'Groq',
                model: 'llama-3.3-70b-versatile',
                configured: config?.llm?.primary?.configured ?? false,
                desc: 'Sub-second ultrafast LPU inference for real-time inbox scanning and email triage.',
              },
              {
                role: 'Fallback 1',
                name: 'Cloudflare Workers AI',
                model: '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
                configured: config?.llm?.fallback_1?.configured ?? false,
                desc: 'Global edge inference fallback with 10k daily neuron headroom.',
              },
              {
                role: 'Fallback 2',
                name: 'Mistral',
                model: 'mistral-small-latest',
                configured: config?.llm?.fallback_2?.configured ?? false,
                desc: 'Secondary resilient reasoning fallback with 1.1s rate pacing.',
              },
            ].map((provider) => (
              <div
                key={provider.name}
                className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-[var(--text-primary)] font-sans">{provider.name}</span>
                    <Badge variant="outline" size="xs" className="font-mono text-[10px]">
                      {provider.role}
                    </Badge>
                    <code className="text-[10px] text-[var(--text-tertiary)] bg-[var(--bg-panel)] px-1.5 py-0.5 rounded border border-[var(--border-subtle)]">
                      {provider.model}
                    </code>
                  </div>
                  <p className="text-[11px] text-[var(--text-secondary)] font-sans">
                    {provider.desc}
                  </p>
                </div>

                <div className="flex items-center gap-2.5 shrink-0">
                  <StatusDot
                    status={provider.configured ? 'healthy' : 'degraded'}
                    size="sm"
                    pulse={provider.configured}
                  />
                  <span className="text-[11px] text-[var(--text-secondary)] select-none">
                    {provider.configured ? 'Configured' : 'Not set'}
                  </span>
                  <Badge variant={provider.configured ? 'success' : 'warning'} size="xs">
                    {provider.configured ? 'Configured' : 'Not set'}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* SECTION 2: PRIVACY & OUTBOUND SUBMISSIONS */}
      <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
        <div>
          <h2 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Lock className="w-4 h-4 text-emerald-400" />
            <span>Privacy Safeguards & Outbound Telemetry</span>
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Controls for third-party submissions. ThreatLens defaults to query-only mode to prevent confidential indicator leakage.
          </p>
        </div>

        <div className="space-y-4">
          {/* Toggle 1: ALLOW_VT_URL_SUBMISSION */}
          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] flex items-start justify-between gap-4">
            <div className="space-y-1">
              <div className="text-xs font-semibold text-[var(--text-primary)] flex items-center gap-2">
                <span>Submit Unseen URLs to VirusTotal</span>
                <code className="text-[10px] text-[var(--text-tertiary)]">ALLOW_VT_URL_SUBMISSION</code>
              </div>
              <p className="text-xs text-amber-500/90 leading-relaxed">
                <span className="font-semibold">Privacy Consequence: </span>
                Enabling this will submit the URL to VirusTotal, where it becomes publicly visible to other VirusTotal users and security researchers. Leave disabled when investigating private corporate intranet endpoints.
              </p>
            </div>

            <label className="relative inline-flex items-center cursor-pointer shrink-0 mt-1">
              <input
                type="checkbox"
                checked={allowVtUrlSubmission}
                onChange={(e) => {
                  setAllowVtUrlSubmission(e.target.checked);
                  toast.info(`VirusTotal URL submission ${e.target.checked ? 'enabled' : 'disabled'}`);
                }}
                className="sr-only peer"
              />
              <div className="w-10 h-6 bg-[var(--border-subtle)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>

          {/* Toggle 2: ALLOW_FILE_UPLOAD_TO_VT */}
          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] flex items-start justify-between gap-4">
            <div className="space-y-1">
              <div className="text-xs font-semibold text-[var(--text-primary)] flex items-center gap-2">
                <span>Upload Sample Binaries to VirusTotal Corpus</span>
                <code className="text-[10px] text-[var(--text-tertiary)]">ALLOW_FILE_UPLOAD_TO_VT</code>
              </div>
              <p className="text-xs text-amber-500/90 leading-relaxed">
                <span className="font-semibold">Privacy Consequence: </span>
                Enabling this will upload the full sample file to VirusTotal's public corpus. Hashes alone are queried by default to safeguard confidential internal scripts, proprietary binaries, and sensitive attachments.
              </p>
            </div>

            <label className="relative inline-flex items-center cursor-pointer shrink-0 mt-1">
              <input
                type="checkbox"
                checked={allowVtFileUpload}
                onChange={(e) => {
                  setAllowVtFileUpload(e.target.checked);
                  toast.info(`VirusTotal file upload ${e.target.checked ? 'enabled' : 'disabled'}`);
                }}
                className="sr-only peer"
              />
              <div className="w-10 h-6 bg-[var(--border-subtle)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>
        </div>
      </div>

      {/* SECTION 3: SCANNING PARAMETERS */}
      <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
        <div>
          <h2 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Clock className="w-4 h-4 text-blue-400" />
            <span>Scanning Telemetry & Budget Parameters</span>
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Cadence intervals, execution timeouts, and redirect hop budgets.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
            <label className="text-xs font-semibold text-[var(--text-primary)] block">
              Watchlist Check Cadence
            </label>
            <select
              value={watchlistInterval}
              aria-label="Watchlist Check Cadence"
              onChange={(e) => {
                const val = Number(e.target.value);
                setWatchlistInterval(val);
                toast.success(`Watchlist interval set to ${val} hours`);
              }}
              className="w-full p-2 rounded-lg bg-[var(--bg-panel)] border border-[var(--border-subtle)] text-xs text-[var(--text-primary)] cursor-pointer"
            >
              <option value={6}>Every 6 Hours (Recommended)</option>
              <option value={12}>Every 12 Hours</option>
              <option value={24}>Every 24 Hours</option>
            </select>
            <p className="text-[11px] text-[var(--text-tertiary)]">
              Automated re-scan frequency for pinned targets.
            </p>
          </div>

          <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
            <label className="text-xs font-semibold text-[var(--text-primary)] block">
              Redirect Hop Budget
            </label>
            <select
              value={redirectBudget}
              aria-label="Redirect Hop Budget"
              onChange={(e) => {
                const val = Number(e.target.value);
                setRedirectBudget(val);
                toast.success(`Redirect hop budget set to ${val} hops`);
              }}
              className="w-full p-2 rounded-lg bg-[var(--bg-panel)] border border-[var(--border-subtle)] text-xs text-[var(--text-primary)] cursor-pointer"
            >
              <option value={3}>3 Hops (Strict)</option>
              <option value={5}>5 Hops (Standard)</option>
              <option value={8}>8 Hops (Deep Trace)</option>
            </select>
            <p className="text-[11px] text-[var(--text-tertiary)]">
              Max HTTP 301/302 jumps before landing.
            </p>
          </div>

          <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
            <label className="text-xs font-semibold text-[var(--text-primary)] block">
              Network Request Timeout
            </label>
            <select
              value={requestTimeout}
              aria-label="Network Request Timeout"
              onChange={(e) => {
                const val = Number(e.target.value);
                setRequestTimeout(val);
                toast.success(`Timeout set to ${val} seconds`);
              }}
              className="w-full p-2 rounded-lg bg-[var(--bg-panel)] border border-[var(--border-subtle)] text-xs text-[var(--text-primary)] cursor-pointer"
            >
              <option value={10}>10 Seconds (Fast Fail)</option>
              <option value={15}>15 Seconds (Default)</option>
              <option value={30}>30 Seconds (Tolerant)</option>
            </select>
            <p className="text-[11px] text-[var(--text-tertiary)]">
              Max per-provider wait time before skipping feed.
            </p>
          </div>
        </div>
      </div>

      {/* SECTION 4: APPEARANCE & PREFERENCES */}
      <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
        <div>
          <h2 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Palette className="w-4 h-4 text-purple-400" />
            <span>Appearance & Presentation Defaults</span>
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Theme palette, table density, defanging behavior, and default report explainability view.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
          {/* Theme */}
          <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
            <span className="text-xs font-semibold text-[var(--text-primary)] block">Theme Palette</span>
            <div className="flex gap-2">
              <Button
                variant={theme === 'dark' ? 'primary' : 'secondary'}
                size="xs"
                onClick={() => setTheme('dark')}
                className="flex-1"
              >
                Dark
              </Button>
              <Button
                variant={theme === 'light' ? 'primary' : 'secondary'}
                size="xs"
                onClick={() => setTheme('light')}
                className="flex-1"
              >
                Light
              </Button>
            </div>
            <p className="text-[11px] text-[var(--text-tertiary)]">Scoped severity tokens</p>
          </div>

          {/* Density */}
          <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
            <span className="text-xs font-semibold text-[var(--text-primary)] block">Row Density</span>
            <div className="flex gap-2">
              <Button
                variant={density === 'compact' ? 'primary' : 'secondary'}
                size="xs"
                onClick={() => setDensity('compact')}
                className="flex-1"
              >
                Compact (36px)
              </Button>
              <Button
                variant={density === 'comfortable' ? 'primary' : 'secondary'}
                size="xs"
                onClick={() => setDensity('comfortable')}
                className="flex-1"
              >
                Comfort (44px)
              </Button>
            </div>
            <p className="text-[11px] text-[var(--text-tertiary)]">Data table row height</p>
          </div>

          {/* Defang Default */}
          <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
            <span className="text-xs font-semibold text-[var(--text-primary)] block">Defang Indicators</span>
            <div className="flex gap-2">
              <Button
                variant={isDefanged ? 'primary' : 'secondary'}
                size="xs"
                onClick={() => setDefanged(true)}
                className="flex-1"
              >
                Enabled
              </Button>
              <Button
                variant={!isDefanged ? 'primary' : 'secondary'}
                size="xs"
                onClick={() => setDefanged(false)}
                className="flex-1"
              >
                Live URL
              </Button>
            </div>
            <p className="text-[11px] text-[var(--text-tertiary)]">hxxp:// sanitization</p>
          </div>

          {/* Report View Default */}
          <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
            <span className="text-xs font-semibold text-[var(--text-primary)] block">Report Default View</span>
            <div className="flex gap-2">
              <Button
                variant={reportDefaultView === 'plain' ? 'primary' : 'secondary'}
                size="xs"
                onClick={() => setReportDefaultView('plain')}
                className="flex-1"
              >
                Plain
              </Button>
              <Button
                variant={reportDefaultView === 'technical' ? 'primary' : 'secondary'}
                size="xs"
                onClick={() => setReportDefaultView('technical')}
                className="flex-1"
              >
                Technical
              </Button>
            </div>
            <p className="text-[11px] text-[var(--text-tertiary)]">Report load layout</p>
          </div>
        </div>
      </div>

      {/* SECTION 5: DEMO DATASET MANAGEMENT */}
      <div className="p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
        <div>
          <h2 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Database className="w-4 h-4 text-amber-400" />
            <span>Demo Data & Environment Reset</span>
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Load mock threat evolutions or purge investigation logs to restore a clean state.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setIsSeedModalOpen(true)}
            className="flex items-center gap-1.5"
          >
            <Sparkles className="w-3.5 h-3.5 text-blue-400" />
            <span>Seed Demo Dataset</span>
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => setIsResetModalOpen(true)}
            className="flex items-center gap-1.5 text-red-400 hover:text-red-300"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset All Demo Data</span>
          </Button>
        </div>
      </div>

      {/* MODAL 1: SEED DEMO */}
      <Modal
        isOpen={isSeedModalOpen}
        onClose={() => setIsSeedModalOpen(false)}
        title="Seed Simulated Demo Dataset"
        description="Populates investigations, watchlist targets, and evolution checkpoints for executive presentations."
      >
        <div className="space-y-4 py-2 text-xs text-[var(--text-secondary)]">
          <p>
            This action queries <code>POST /api/demo/seed</code> to inject realistic multi-hop phishing investigations, simulated VirusTotal detections, and drift alerts.
          </p>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" size="sm" onClick={() => setIsSeedModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" size="sm" onClick={handleSeedDemo} disabled={isSeeding}>
              {isSeeding ? 'Seeding...' : 'Confirm Seed'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* MODAL 2: RESET DEMO */}
      <Modal
        isOpen={isResetModalOpen}
        onClose={() => setIsResetModalOpen(false)}
        title="Reset & Restore Clean Demo State"
        description="Purges historical drift records and resets demo scans to clean initial values."
      >
        <div className="space-y-4 py-2 text-xs text-[var(--text-secondary)]">
          <div className="p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Warning: All custom scan history and watchlist entries will be reset to default baseline scores.</span>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" size="sm" onClick={() => setIsResetModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" size="sm" onClick={handleResetDemo} disabled={isResetting}>
              {isResetting ? 'Resetting...' : 'Confirm Reset'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
