import React, { useMemo, useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Search, Eye, EyeOff, Sun, Moon, RefreshCw } from 'lucide-react';
import { useTheme } from '../../design/ThemeContext';
import { useDefang } from '../../design/DefangContext';
import { useCommandPalette } from '../../context/CommandPaletteContext';
import { useHealth } from '../../hooks/useHealth';
import { Breadcrumb } from '../primitives/Breadcrumb';
import type { BreadcrumbItem } from '../primitives/Breadcrumb';
import { KeyHint } from '../primitives/KeyHint';
import { Tooltip } from '../primitives/Tooltip';
import { StatusDot } from '../primitives/StatusDot';
import type { StatusDotState } from '../primitives/StatusDot';
import { Badge } from '../primitives/Badge';

export const TopBar: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();
  const { isDefanged, toggleDefanged } = useDefang();
  const palette = useCommandPalette();
  const { status, data, lastChecked } = useHealth();
  const [isSyncing, setIsSyncing] = useState(false);

  useEffect(() => {
    const handleSyncStatus = (e: any) => {
      setIsSyncing(Boolean(e.detail?.syncing));
    };
    window.addEventListener('threatlens:inbox-syncing', handleSyncStatus);
    return () => window.removeEventListener('threatlens:inbox-syncing', handleSyncStatus);
  }, []);

  const isMac = typeof navigator !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform);

  // Compute breadcrumbs driven by active path
  const breadcrumbs: BreadcrumbItem[] = useMemo(() => {
    const p = location.pathname;
    const base: BreadcrumbItem[] = [{ label: 'ThreatLens', onClick: () => navigate('/') }];

    if (p === '/' || p === '/dashboard' || p === '/overview') {
      return [...base, { label: 'Overview' }];
    }
    if (p.startsWith('/inbox')) {
      return [...base, { label: 'Gmail Inbox' }];
    }
    if (p.startsWith('/analyze')) {
      const sub = p.replace('/analyze', '').replace('/', '');
      if (sub) {
        return [
          ...base,
          { label: 'Analyze', onClick: () => navigate('/analyze') },
          { label: sub.toUpperCase() },
        ];
      }
      return [...base, { label: 'Analyze' }];
    }
    if (p.startsWith('/scans') || p.startsWith('/history') || p.startsWith('/investigations')) {
      return [...base, { label: 'Investigations' }];
    }
    if (p.startsWith('/scan/')) {
      const scanId = p.replace('/scan/', '');
      return [
        ...base,
        { label: 'Investigations', onClick: () => navigate('/scans') },
        { label: scanId },
      ];
    }
    if (p.startsWith('/compare')) {
      return [...base, { label: 'Compare Threats' }];
    }
    if (p.startsWith('/watchlist')) {
      return [...base, { label: 'Watchlist' }];
    }
    if (p.startsWith('/alerts')) {
      return [...base, { label: 'Alerts' }];
    }
    if (p.startsWith('/settings')) {
      return [...base, { label: 'Settings' }];
    }
    if (p.startsWith('/design-system')) {
      return [...base, { label: 'Design System' }];
    }
    return [...base, { label: 'Not Found' }];
  }, [location.pathname, navigate]);

  // Backend status tooltip text
  const healthTooltip = useMemo(() => {
    if (status === 'offline') {
      const secondsAgo = lastChecked
        ? Math.max(0, Math.round((Date.now() - lastChecked.getTime()) / 1000))
        : 0;
      return `Backend unreachable — last checked ${secondsAgo}s ago`;
    }
    if (data?.configured_sources) {
      const activeCount = Object.values(data.configured_sources).filter(Boolean).length;
      const totalCount = Object.keys(data.configured_sources).length;
      return `Backend healthy — ${activeCount}/${totalCount} telemetry feeds active`;
    }
    return 'Backend operational';
  }, [status, data, lastChecked]);

  const dotState: StatusDotState =
    status === 'healthy' ? 'healthy' : status === 'degraded' ? 'degraded' : 'offline';

  return (
    <header
      role="banner"
      aria-label="Top navigation bar"
      className="sticky top-0 z-20 flex items-center justify-between gap-3 px-4 py-2.5 bg-[var(--bg-panel)]/90 backdrop-blur-md border-b border-[var(--border-subtle)] transition-colors"
    >
      {/* Left: Breadcrumbs */}
      <div className="flex items-center min-w-0 pr-2">
        <Breadcrumb items={breadcrumbs} className="truncate" />
      </div>

      {/* Center Spacer */}
      <div className="flex-1" />

      {/* Right Controls: CommandPalette trigger, Defang toggle, Theme toggle, Health dot, Demo badge */}
      <div className="flex items-center gap-2 sm:gap-3 shrink-0">
        {/* Command Palette Trigger */}
        <button
          type="button"
          onClick={() => palette.open()}
          aria-label="Search and quick actions (Cmd+K)"
          className="flex items-center gap-2 h-7 px-2.5 rounded-md bg-[var(--bg-inset)] hover:bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 cursor-pointer shadow-xs"
        >
          <Search className="w-3.5 h-3.5 text-[var(--text-tertiary)]" />
          <span className="hidden sm:inline">Search</span>
          <KeyHint keys={[isMac ? '⌘' : 'Ctrl', 'K']} />
        </button>

        {/* Defang Toggle Button */}
        <Tooltip content={`Defang indicators (${isDefanged ? 'enabled' : 'disabled'})`}>
          <button
            type="button"
            onClick={toggleDefanged}
            aria-label="Toggle indicator defanging"
            aria-pressed={isDefanged}
            className={`flex items-center justify-center w-7 h-7 rounded-md border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 cursor-pointer ${
              isDefanged
                ? 'bg-amber-500/10 border-amber-500/30 text-amber-500 hover:bg-amber-500/20'
                : 'bg-[var(--bg-inset)] border-[var(--border-subtle)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)]'
            }`}
          >
            {isDefanged ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
        </Tooltip>

        {/* Theme Toggle Button */}
        <Tooltip content={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={`Toggle theme (currently ${theme})`}
            aria-pressed={theme === 'dark'}
            className="flex items-center justify-center w-7 h-7 rounded-md border border-[var(--border-subtle)] bg-[var(--bg-inset)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 cursor-pointer"
          >
            {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
          </button>
        </Tooltip>

        {/* Inbox Sync Indicator */}
        {isSyncing && (
          <div
            role="status"
            aria-live="polite"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-blue-500/10 border border-blue-500/25 text-xs font-semibold text-blue-400 animate-pulse"
          >
            <RefreshCw className="w-3 h-3 animate-spin text-blue-400" />
            <span className="hidden sm:inline">Syncing Inbox...</span>
          </div>
        )}

        {/* Health Status Dot */}
        <Tooltip content={healthTooltip}>
          <div
            tabIndex={0}
            role="status"
            aria-label={`System health: ${status}`}
            className="flex items-center px-1.5 py-1 rounded cursor-default focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <StatusDot status={dotState} size="sm" pulse={status === 'healthy'} />
          </div>
        </Tooltip>

        {/* Demo Mode Badge */}
        {data?.demo_mode && (
          <Badge variant="demo" size="xs" className="hidden sm:inline-flex">
            Demo
          </Badge>
        )}
      </div>
    </header>
  );
};
