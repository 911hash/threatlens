import React, { useState } from 'react';
import {
  Sun,
  Moon,
  Layers,
  Shield,
  Zap,
  Activity,
  AlertCircle,
  Copy,
  Info,
  Check,
  Search,
  Filter,
  ExternalLink,
  Sliders,
  Maximize2,
} from 'lucide-react';
import { useTheme } from '../design/ThemeContext';
import { useDefang } from '../design/DefangContext';
import type { SeverityLevel } from '../design/tokens';
import { SEVERITY_TOKENS, getSeverityToken, SURFACES, BORDERS, TEXT_TOKENS } from '../design/tokens';
import { Button } from '../components/primitives/Button';
import { IconButton } from '../components/primitives/IconButton';
import { Input } from '../components/primitives/Input';
import { Textarea } from '../components/primitives/Textarea';
import { Select } from '../components/primitives/Select';
import { Combobox } from '../components/primitives/Combobox';
import { Checkbox } from '../components/primitives/Checkbox';
import { Radio, RadioGroup } from '../components/primitives/Radio';
import { Switch } from '../components/primitives/Switch';
import { Slider } from '../components/primitives/Slider';
import { Tabs } from '../components/primitives/Tabs';
import { SegmentedControl } from '../components/primitives/SegmentedControl';
import { Tooltip } from '../components/primitives/Tooltip';
import { Popover } from '../components/primitives/Popover';
import { Modal } from '../components/primitives/Modal';
import { Drawer } from '../components/primitives/Drawer';
import { useToast } from '../components/primitives/Toast';
import { Badge } from '../components/primitives/Badge';
import { SeverityChip } from '../components/primitives/SeverityChip';
import type { StatusDotState } from '../components/primitives/StatusDot';
import { StatusDot } from '../components/primitives/StatusDot';
import { ProgressBar } from '../components/primitives/ProgressBar';
import { Skeleton } from '../components/primitives/Skeleton';
import { EmptyState } from '../components/primitives/EmptyState';
import { ErrorState } from '../components/primitives/ErrorState';
import { CopyButton } from '../components/primitives/CopyButton';
import { Kbd } from '../components/primitives/Kbd';
import { KeyHint } from '../components/primitives/KeyHint';
import { Callout } from '../components/primitives/Callout';
import type { ColumnDef } from '../components/primitives/DataTable';
import { DataTable } from '../components/primitives/DataTable';
import { Pagination } from '../components/primitives/Pagination';
import { Breadcrumb } from '../components/primitives/Breadcrumb';

import { DefangText } from '../components/domain/DefangText';
import { IndicatorChip } from '../components/domain/IndicatorChip';
import { TimelineDrift } from '../components/domain/TimelineDrift';
import { DiffHeader } from '../components/domain/DiffHeader';
import { DiffRow } from '../components/domain/DiffRow';
import { AlertRow } from '../components/domain/AlertRow';
import { TargetRow } from '../components/domain/TargetRow';
import { FileDropZone } from '../components/shell/FileDropZone';

export const DesignSystemPage: React.FC = () => {
  const { theme, toggleTheme, density, toggleDensity, reducedMotion, toggleReducedMotion } = useTheme();
  const { isDefanged, toggleDefanged } = useDefang();
  const toast = useToast();

  // Interactive primitive states
  const [activeTab, setActiveTab] = useState('overview');
  const [segmentedVal, setSegmentedVal] = useState<'plain' | 'technical'>('plain');
  const [radioVal, setRadioVal] = useState('url');
  const [sliderVal, setSliderVal] = useState(75);
  const [checkboxChecked, setCheckboxChecked] = useState(true);
  const [comboboxVal, setComboboxVal] = useState<string[]>(['critical', 'high']);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [tableSelectedKeys, setTableSelectedKeys] = useState<string[]>(['row-1', 'row-3']);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Sample data for 220 virtualized rows to verify virtualization above 200 rows!
  const demoTableRows = React.useMemo(() => {
    return Array.from({ length: 220 }).map((_, i) => ({
      id: `row-${i + 1}`,
      target: i % 2 === 0 ? `https://suspicious-node-${i}.xyz/payload.exe` : `d41d8cd98f00b204e9800998ecf8427e${i}`,
      type: i % 2 === 0 ? 'url' : 'hash',
      score: Math.min(100, Math.floor((i * 13) % 95) + 5),
      level: (['critical', 'high', 'medium', 'low', 'clean', 'unknown'] as SeverityLevel[])[i % 6],
      timestamp: new Date(Date.now() - i * 3600000).toISOString(),
    }));
  }, []);

  const tableColumns: ColumnDef<typeof demoTableRows[0]>[] = [
    {
      id: 'target',
      header: 'Indicator / Target',
      width: 280,
      cell: row => <DefangText value={row.target} showCopy={true} truncate={true} />,
    },
    {
      id: 'type',
      header: 'Type',
      width: 90,
      cell: row => (
        <Badge variant="neutral" size="xs">
          {row.type}
        </Badge>
      ),
    },
    {
      id: 'score',
      header: 'Risk Score',
      width: 140,
      sortable: true,
      cell: row => <SeverityChip severity={row.level} score={row.score} size="xs" />,
    },
    {
      id: 'drift',
      header: 'Trend Drift',
      width: 120,
      cell: row => <TimelineDrift currentScore={row.score} previousScore={Math.max(0, row.score - 12)} />,
    },
    {
      id: 'timestamp',
      header: 'Timestamp',
      width: 180,
      cell: row => (
        <span className="font-mono text-[11px] text-[var(--text-tertiary)]">
          {new Date(row.timestamp).toLocaleDateString()}
        </span>
      ),
    },
  ];

  const severityLevels: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'clean', 'unknown'];

  return (
    <div className="min-h-screen bg-[var(--bg-base)] text-[var(--text-primary)] p-3 sm:p-8 max-w-full overflow-x-hidden transition-colors">
      <div className="max-w-7xl mx-auto space-y-10 overflow-x-hidden">
        {/* Top Header & Global Controller Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--border-subtle)] pb-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-blue-500/10 text-blue-500 border border-blue-500/20">
                Phase 2 Delivery
              </span>
              <span className="text-xs text-[var(--text-tertiary)] font-mono">Design System Audit & Review</span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-[var(--text-primary)]">
              ThreatLens Design System
            </h1>
            <p className="text-xs text-[var(--text-secondary)] mt-1 max-w-2xl">
              Zero-dependency SecOps component library tailored for SOC analysts, incident responders, and executives.
              Theme-scoped contrast tokens, density-aware layouts, and strict indicator defanging.
            </p>
          </div>

          {/* Interactive System Control Bar */}
          <div className="flex flex-wrap items-center gap-2 bg-[var(--bg-panel)] p-2 rounded-lg border border-[var(--border-subtle)] shadow-xs">
            <Button
              variant="secondary"
              size="xs"
              leftIcon={theme === 'dark' ? <Moon className="w-3.5 h-3.5 text-blue-400" /> : <Sun className="w-3.5 h-3.5 text-amber-500" />}
              onClick={toggleTheme}
            >
              Theme: <span className="font-semibold uppercase ml-1">{theme}</span>
            </Button>

            <Button
              variant="secondary"
              size="xs"
              leftIcon={<Layers className="w-3.5 h-3.5" />}
              onClick={toggleDensity}
            >
              Density: <span className="font-semibold uppercase ml-1">{density}</span>
            </Button>

            <Button
              variant="secondary"
              size="xs"
              leftIcon={<Shield className="w-3.5 h-3.5 text-emerald-500" />}
              onClick={toggleDefanged}
            >
              Defang: <span className="font-semibold uppercase ml-1">{isDefanged ? 'ON' : 'OFF'}</span>
            </Button>

            <Button
              variant="secondary"
              size="xs"
              leftIcon={<Zap className="w-3.5 h-3.5 text-purple-400" />}
              onClick={toggleReducedMotion}
            >
              Motion: <span className="font-semibold uppercase ml-1">{reducedMotion ? 'Reduced' : 'Full'}</span>
            </Button>
          </div>
        </div>

        {/* SECTION 1: TOKEN GALLERY */}
        <section className="space-y-4">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2">
            <h2 className="text-sm font-semibold tracking-wider uppercase text-[var(--text-secondary)]">
              1. Tokens & Palette (Current Theme: {theme})
            </h2>
            <span className="text-xs text-[var(--text-tertiary)] font-mono">tokens.ts & index.css</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {Object.entries(SURFACES[theme]).map(([name, hex]) => (
              <div
                key={name}
                className="p-3 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-panel)] flex flex-col justify-between h-24 shadow-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase text-[var(--text-primary)]">--bg-{name}</span>
                  <div
                    className="w-4 h-4 rounded-full border border-[var(--border-strong)]"
                    style={{ backgroundColor: hex }}
                  />
                </div>
                <div className="font-mono text-[11px] text-[var(--text-tertiary)]">{hex}</div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-2">
            {Object.entries(TEXT_TOKENS[theme]).map(([name, hex]) => (
              <div
                key={name}
                className="p-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-panel)] flex flex-col justify-between h-20"
              >
                <span className="text-xs font-medium text-[var(--text-secondary)]">--text-{name}</span>
                <span className="font-mono text-xs" style={{ color: hex }}>
                  {hex} Sample Text
                </span>
              </div>
            ))}
            {Object.entries(BORDERS[theme]).map(([name, hex]) => (
              <div
                key={name}
                className="p-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-panel)] flex flex-col justify-between h-20"
              >
                <span className="text-xs font-medium text-[var(--text-secondary)]">--border-{name}</span>
                <div className="h-2 rounded w-full" style={{ backgroundColor: hex }} />
              </div>
            ))}
          </div>
        </section>

        {/* SECTION 2: SEVERITY MATRIX */}
        <section className="space-y-4">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2">
            <div>
              <h2 className="text-sm font-semibold tracking-wider uppercase text-[var(--text-secondary)]">
                2. Theme-Scoped Severity Matrix (Non-Negotiable)
              </h2>
              <p className="text-xs text-[var(--text-tertiary)] mt-0.5">
                Contrast-tested on both dark surfaces and light surfaces via single helper getSeverityToken(severity, theme).
              </p>
            </div>
            <span className="text-xs text-[var(--text-tertiary)] font-mono">6 Risk Levels</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left border border-[var(--border-subtle)] rounded-lg overflow-hidden">
              <thead className="bg-[var(--bg-inset)] border-b border-[var(--border-strong)] font-semibold text-[var(--text-secondary)]">
                <tr>
                  <th className="p-3">Level</th>
                  <th className="p-3">Subtle Chip</th>
                  <th className="p-3">Solid Chip</th>
                  <th className="p-3">Outline Chip</th>
                  <th className="p-3">Visual Fill Token (Canvas / SVG)</th>
                  <th className="p-3">Direct Dark vs Light Spec</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)] bg-[var(--bg-panel)]">
                {severityLevels.map(lvl => {
                  const token = getSeverityToken(lvl, theme);
                  const darkTok = SEVERITY_TOKENS.dark[lvl];
                  const lightTok = SEVERITY_TOKENS.light[lvl];

                  return (
                    <tr key={lvl} className="hover:bg-[var(--bg-elevated)] transition-colors">
                      <td className="p-3 font-semibold uppercase">{lvl}</td>
                      <td className="p-3">
                        <SeverityChip severity={lvl} variant="subtle" score={85} />
                      </td>
                      <td className="p-3">
                        <SeverityChip severity={lvl} variant="solid" score={85} />
                      </td>
                      <td className="p-3">
                        <SeverityChip severity={lvl} variant="outline" score={85} />
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <div
                            className="w-16 h-3 rounded-full"
                            style={{ backgroundColor: token.solid }}
                          />
                          <span className="font-mono text-[11px] text-[var(--text-tertiary)]">{token.solid}</span>
                        </div>
                      </td>
                      <td className="p-3 font-mono text-[11px] text-[var(--text-tertiary)]">
                        Dark: <span style={{ color: darkTok.text }}>{darkTok.text}</span> | Light:{' '}
                        <span style={{ color: lightTok.text }}>{lightTok.text}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* SECTION 3: PRIMITIVE COMPONENT CATALOG */}
        <section className="space-y-6">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2">
            <h2 className="text-sm font-semibold tracking-wider uppercase text-[var(--text-secondary)]">
              3. Primitive Components (32 Complete Hand-Rolled Controls)
            </h2>
            <span className="text-xs text-[var(--text-tertiary)] font-mono">Zero External Component Libs</span>
          </div>

          {/* Buttons and IconButtons */}
          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-3">
            <h3 className="text-xs font-semibold text-[var(--text-secondary)] uppercase">
              Buttons & IconButtons (Variants & Sizes)
            </h3>
            <div className="flex flex-wrap items-center gap-3">
              <Button variant="primary" size="sm">Primary</Button>
              <Button variant="secondary" size="sm">Secondary</Button>
              <Button variant="tertiary" size="sm">Tertiary</Button>
              <Button variant="danger" size="sm">Danger</Button>
              <Button variant="outline" size="sm">Outline</Button>
              <Button variant="secondary" size="sm" isLoading={true}>Loading</Button>
              <Button variant="secondary" size="sm" disabled={true}>Disabled</Button>
              <Button variant="primary" size="xs">XS</Button>
              <Button variant="primary" size="md">MD</Button>
              <Button variant="primary" size="lg">LG</Button>
              <IconButton icon={<Copy className="w-3.5 h-3.5" />} aria-label="Copy button" variant="secondary" size="sm" />
              <IconButton icon={<Sliders className="w-3.5 h-3.5" />} aria-label="Settings button" variant="tertiary" size="sm" />
            </div>
          </div>

          {/* Form Controls */}
          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
            <h3 className="text-xs font-semibold text-[var(--text-secondary)] uppercase">
              Form Controls (Input, Textarea, Select, Combobox, Checkbox, Radio, Switch, Slider)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Input
                label="Indicator Input"
                placeholder="Paste URL, domain, or SHA256..."
                leftIcon={<Search className="w-3.5 h-3.5" />}
                defaultValue="https://malicious-c2.network/beacon"
              />
              <Input
                label="Error State Input"
                placeholder="Invalid indicator..."
                error="Format is not a recognized URL or Hash"
                defaultValue="invalid_target:443"
              />
              <Select
                label="Scan Engine Selection"
                options={[
                  { value: 'all', label: 'All Engines (VirusTotal + AlienVault + AbuseIPDB)' },
                  { value: 'vt', label: 'VirusTotal Only' },
                  { value: 'otx', label: 'AlienVault OTX Only' },
                ]}
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <Combobox
                label="Severity Filter (Multi-select Combobox)"
                options={[
                  { value: 'critical', label: 'Critical Severity', description: 'Score >= 80' },
                  { value: 'high', label: 'High Severity', description: 'Score 60 - 79' },
                  { value: 'medium', label: 'Medium Severity', description: 'Score 40 - 59' },
                  { value: 'low', label: 'Low Severity', description: 'Score 20 - 39' },
                  { value: 'clean', label: 'Clean / Safe', description: 'Score 0 - 19' },
                ]}
                value={comboboxVal}
                onChange={setComboboxVal}
              />
              <Slider
                label="Confidence Threshold Filter"
                value={sliderVal}
                onChange={setSliderVal}
                min={0}
                max={100}
                valueFormatter={v => `${v}% confidence`}
              />
              <div className="flex flex-col gap-2 justify-center">
                <Switch
                  checked={checkboxChecked}
                  onChange={setCheckboxChecked}
                  label="Automated Sandbox detonation"
                  description="Emulate executable in isolated sandbox"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="flex flex-col gap-2">
                <span className="text-xs font-medium text-[var(--text-secondary)]">Checkboxes:</span>
                <Checkbox label="Default checked" checked={true} onChange={() => {}} />
                <Checkbox label="Indeterminate (select-all)" indeterminate={true} checked={false} onChange={() => {}} />
                <Checkbox label="Disabled option" disabled={true} checked={false} onChange={() => {}} />
              </div>
              <div className="flex flex-col gap-2">
                <span className="text-xs font-medium text-[var(--text-secondary)]">Radio Group:</span>
                <RadioGroup
                  name="demo-target-type"
                  value={radioVal}
                  onChange={setRadioVal}
                  options={[
                    { value: 'url', label: 'URL / Domain Inspection' },
                    { value: 'hash', label: 'File Hash (SHA256 / MD5)' },
                    { value: 'file', label: 'Direct Binary Upload' },
                  ]}
                />
              </div>
              <Textarea
                label="Bulk Targets / IOC Paste (Textarea)"
                placeholder="Paste list of indicators, one per line..."
                rows={3}
                isMono={true}
              />
            </div>
          </div>

          {/* Navigation & Display Primitives */}
          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4">
            <h3 className="text-xs font-semibold text-[var(--text-secondary)] uppercase">
              Navigation, Chips, Badges, Status & Feedback
            </h3>

            <div className="flex flex-wrap items-center gap-4">
              <SegmentedControl
                value={segmentedVal}
                onChange={setSegmentedVal}
                options={[
                  { value: 'plain', label: 'Plain English' },
                  { value: 'technical', label: 'Technical Evidence' },
                ]}
              />

              <div className="flex items-center gap-2">
                <StatusDot status="live" label="Live Stream" />
                <StatusDot status="healthy" label="Backend Healthy" />
                <StatusDot status="degraded" label="Degraded" />
                <StatusDot status="stale" label="Cache Stale" />
                <StatusDot status="scanning" label="Scanning" />
                <StatusDot status="offline" label="Offline" />
              </div>

              <div className="flex items-center gap-2">
                <Badge variant="neutral">Neutral</Badge>
                <Badge variant="info">Informational</Badge>
                <Badge variant="success">Safe / Clean</Badge>
                <Badge variant="warning">Suspicious</Badge>
                <Badge variant="danger">Malicious</Badge>
                <Badge variant="demo">Demo / Simulated</Badge>
              </div>

              <div className="flex items-center gap-2">
                <Kbd>⌘K</Kbd>
                <KeyHint keys={['Ctrl', 'Shift', 'P']} />
              </div>
            </div>

            {/* Tabs Demonstration */}
            <div className="space-y-2 pt-2 border-t border-[var(--border-subtle)]">
              <span className="text-xs font-medium text-[var(--text-secondary)]">Tabs Navigation & Panels:</span>
              <Tabs
                tabs={[
                  { id: 'overview', label: 'Overview' },
                  { id: 'indicators', label: 'Indicators', badge: <Badge variant="neutral" size="xs">12</Badge> },
                  { id: 'timeline', label: 'Timeline' },
                ]}
                activeId={activeTab}
                onChange={setActiveTab}
              />
              <div
                id="active-tab-panel"
                role="tabpanel"
                className="p-3 bg-[var(--bg-inset)] rounded text-xs text-[var(--text-secondary)] border border-[var(--border-subtle)]"
              >
                {activeTab === 'overview' && <span>Overview Tab Active: Executive threat level summary and scoring matrix.</span>}
                {activeTab === 'indicators' && <span>Indicators Tab Active: Detailed IOC lists and enrichment metrics.</span>}
                {activeTab === 'timeline' && <span>Timeline Tab Active: Drift timeline of threat evolution across scans.</span>}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <ProgressBar value={78} label="Scan Progress" valueFormatter={v => `${v}% engines completed`} />
              <ProgressBar label="Indeterminate Engine Query" />
            </div>

            <div className="flex items-center gap-4 pt-2">
              <Tooltip content="Tooltip explaining confidence calculation algorithm">
                <Button variant="secondary" size="xs">Hover for Tooltip</Button>
              </Tooltip>

              <Popover
                trigger={<Button variant="secondary" size="xs">Click for Popover</Button>}
              >
                {close => (
                  <div className="flex flex-col gap-2 w-48 text-xs">
                    <span className="font-semibold text-[var(--text-primary)]">Quick Actions</span>
                    <span className="text-[var(--text-secondary)]">Export report as PDF or JSON</span>
                    <Button variant="primary" size="xs" onClick={close}>Close Popover</Button>
                  </div>
                )}
              </Popover>

              <Button variant="secondary" size="xs" onClick={() => setIsModalOpen(true)}>
                Open Sample Modal
              </Button>

              <Button variant="secondary" size="xs" onClick={() => setIsDrawerOpen(true)}>
                Open Inspection Drawer
              </Button>

              <Button
                variant="secondary"
                size="xs"
                onClick={() => toast.warning('Live indicator copied to clipboard with caution notice.', 'Security Warning')}
              >
                Trigger Sample Toast
              </Button>
            </div>
          </div>
        </section>

        {/* SECTION 4: STATE MATRIX */}
        <section className="space-y-4">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2">
            <h2 className="text-sm font-semibold tracking-wider uppercase text-[var(--text-secondary)]">
              4. State Matrix (Loading, Empty, Error, Callouts)
            </h2>
            <span className="text-xs text-[var(--text-tertiary)] font-mono">Edge Case States</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <EmptyState
              title="No Watchlist Targets"
              description="Add suspicious domains, IPs, or file hashes to receive automated alerts upon drift."
              actionLabel="Add First Target"
              onAction={() => {}}
            />
            <ErrorState
              title="VirusTotal Gateway Rate Limit Exceeded"
              message="The API key has hit its quota of 4 requests/min. Retrying in 15 seconds."
              onRetry={() => {}}
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Callout variant="info" title="Executive Summary">
              High confidence phishing campaign targeting OAuth tokens; domain registered 48 hours ago.
            </Callout>
            <Callout variant="warning" title="SSRF & Privacy Warning">
              Targets are never fetched directly by ThreatLens. All telemetry is proxied via third-party scanners.
            </Callout>
            <Callout variant="demo" title="Simulated Scan Environment">
              This target is running on seeded test fixtures. Real threat intel keys are optional.
            </Callout>
          </div>
        </section>

        {/* SECTION 5: DENSITY & VIRTUALIZED DATA TABLE */}
        <section className="space-y-4">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2">
            <div>
              <h2 className="text-sm font-semibold tracking-wider uppercase text-[var(--text-secondary)]">
                5. DataTable Primitive (220 Virtualized Rows Demo)
              </h2>
              <p className="text-xs text-[var(--text-tertiary)] mt-0.5">
                Features: virtualizes above 200 rows, resizable columns, visibility menu, density-aware (36px / 44px), sticky header & column, keyboard selection.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="secondary" size="xs" onClick={toggleDensity}>
                Toggle Density ({density})
              </Button>
            </div>
          </div>

          <DataTable
            data={demoTableRows}
            columns={tableColumns}
            rowKey={row => row.id}
            selectable={true}
            selectedRowKeys={tableSelectedKeys}
            onSelectedRowKeysChange={setTableSelectedKeys}
            maxHeight="380px"
          />

          <Pagination
            page={currentPage}
            pageSize={pageSize}
            totalItems={demoTableRows.length}
            onPageChange={setCurrentPage}
            onPageSizeChange={setPageSize}
          />
        </section>

        {/* SECTION 6: DOMAIN & SHELL COMPONENTS */}
        <section className="space-y-4">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2">
            <h2 className="text-sm font-semibold tracking-wider uppercase text-[var(--text-secondary)]">
              6. Domain & Shell Components
            </h2>
            <span className="text-xs text-[var(--text-tertiary)] font-mono">domain/ & shell/</span>
          </div>

          {/* IndicatorChips */}
          <div className="flex flex-wrap items-center gap-3">
            <IndicatorChip indicator="https://fake-login-service.xyz/account" type="url" source="VirusTotal" />
            <IndicatorChip indicator="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" type="hash" source="AlienVault" />
            <IndicatorChip indicator="185.220.101.5" type="ip" source="AbuseIPDB" />
          </div>

          {/* Compare Page Components */}
          <DiffHeader
            scanA={{ id: 'scan_001', timestamp: '2026-10-08 10:00', score: 25, level: 'low' }}
            scanB={{ id: 'scan_002', timestamp: '2026-10-08 16:30', score: 82, level: 'critical' }}
            scoreDelta={57}
            summarySentence="Threat profile worsened significantly from Low to Critical risk due to weaponized redirect chain."
          />

          <div className="space-y-2">
            <DiffRow
              changeType="added"
              title="Newly Registered Domain (Registered 2 days ago)"
              source="Whois XML"
              points={25}
              severity="high"
            />
            <DiffRow
              changeType="changed"
              title="Antivirus Detections Drift"
              source="VirusTotal"
              oldPoints={10}
              newPoints={35}
              oldSeverity="low"
              newSeverity="critical"
            />
            <DiffRow
              changeType="removed"
              title="Cloudflare TLS Edge Certificate Verification"
              source="SSL Labs"
              points={15}
              severity="clean"
            />
          </div>

          {/* Alert and Target Rows */}
          <div className="space-y-2">
            <AlertRow
              id="alert-1"
              target="https://phishing-portal.com/login"
              kind="risk_jump"
              message="Risk score jumped +45 points in last automated re-scan."
              createdAt={new Date().toISOString()}
              seen={false}
              onInspect={() => {}}
              onDismiss={() => {}}
            />
            <TargetRow
              id="watch-1"
              target="hxxps://crypto-drainer[.]io/app"
              targetType="URL"
              level="critical"
              score={91}
              lastScannedAt={new Date().toISOString()}
              onRescan={() => {}}
              onRemove={() => {}}
              onClick={() => {}}
            />
          </div>

          {/* File Drop Zone */}
          <div className="max-w-xl mx-auto pt-4">
            <FileDropZone onFileSelect={file => toast.info(`Selected file: ${file.name}`)} />
          </div>
        </section>

        {/* Interactive Modal */}
        <Modal
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          title="Manual Investigation Trigger"
          description="Submit an indicator to trigger live multi-source analysis."
          footer={
            <>
              <Button variant="tertiary" size="sm" onClick={() => setIsModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="primary" size="sm" onClick={() => setIsModalOpen(false)}>
                Run Analysis
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Input label="Target Indicator" defaultValue="https://c2-beacon.corp-internal.com" />
            <Select
              label="Inspection Depth"
              options={[
                { value: 'standard', label: 'Standard Intelligence (Reputation + DNS)' },
                { value: 'deep', label: 'Deep Emulation (Sandbox + DOM snapshot)' },
              ]}
            />
          </div>
        </Modal>

        {/* Interactive Drawer */}
        <Drawer
          isOpen={isDrawerOpen}
          onClose={() => setIsDrawerOpen(false)}
          title="Factor Detail Inspector"
          subtitle="FACTOR-DNS-RESOLV-FASTFLUX"
          footer={
            <Button variant="secondary" size="sm" onClick={() => setIsDrawerOpen(false)}>
              Done
            </Button>
          }
        >
          <div className="space-y-4 text-xs">
            <SeverityChip severity="critical" score={30} size="sm" />
            <div>
              <h4 className="font-semibold text-[var(--text-primary)]">Title</h4>
              <p className="text-[var(--text-secondary)]">Fast-flux DNS resolution pattern detected</p>
            </div>
            <div>
              <h4 className="font-semibold text-[var(--text-primary)]">Description</h4>
              <p className="text-[var(--text-secondary)] leading-relaxed">
                Domain IP address was observed changing between 14 distinct autonomous systems within 10 minutes,
                characteristic of bulletproof hosting botnets.
              </p>
            </div>
            <div className="p-3 rounded bg-[var(--bg-inset)] font-mono text-[11px] text-[var(--text-tertiary)] overflow-x-auto">
              {JSON.stringify({ ips: ['185.220.101.5', '194.26.29.112', '45.154.255.89'], ttl: 60 }, null, 2)}
            </div>
          </div>
        </Drawer>
      </div>
    </div>
  );
};
