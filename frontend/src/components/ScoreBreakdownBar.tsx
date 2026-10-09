import React from 'react';
import { ShieldCheck, Info } from 'lucide-react';
import { Tooltip } from './primitives/Tooltip';

export interface ScoreBreakdownBarProps {
  breakdown?: Record<string, number>;
  groupBreakdown?: Record<string, number>;
  totalScore: number;
  hoveredGroup?: string | null;
  onHoverGroup?: (group: string | null) => void;
}

export const ScoreBreakdownBar: React.FC<ScoreBreakdownBarProps> = ({
  breakdown,
  groupBreakdown,
  totalScore,
  hoveredGroup,
  onHoverGroup,
}) => {
  const b = breakdown || groupBreakdown || {};
  const av = b['AV_DETECTIONS'] || 0;
  const rep = b['REPUTATION_LISTS'] || 0;
  const infra = b['DOMAIN_INFRA'] || 0;
  const beh = b['BEHAVIOR'] || 0;
  const geo = b['GEOLOCATION'] || 0;
  const mit = b['MITIGATING'] || 0;

  const groups = [
    {
      id: 'AV_DETECTIONS',
      label: 'AV Detections',
      value: av,
      cap: 50,
      color: 'bg-red-500',
      text: 'text-red-400',
      border: 'border-red-500/30',
      activeRing: 'ring-2 ring-red-500/80',
      tooltip: 'Capped at 50 to prevent double-counting across multi-engine scanners.',
    },
    {
      id: 'REPUTATION_LISTS',
      label: 'Reputation Lists',
      value: rep,
      cap: 35,
      color: 'bg-orange-500',
      text: 'text-orange-400',
      border: 'border-orange-500/30',
      activeRing: 'ring-2 ring-orange-500/80',
      tooltip: 'Capped at 35 to prevent double-counting across feed blocklists.',
    },
    {
      id: 'DOMAIN_INFRA',
      label: 'Domain & Infra',
      value: infra,
      cap: 20,
      color: 'bg-amber-500',
      text: 'text-amber-400',
      border: 'border-amber-500/30',
      activeRing: 'ring-2 ring-amber-500/80',
      tooltip: 'Capped at 20. Evaluates domain age, entropy, and WHOIS flags.',
    },
    {
      id: 'BEHAVIOR',
      label: 'Sandbox Behavior',
      value: beh,
      cap: 30,
      color: 'bg-purple-500',
      text: 'text-purple-400',
      border: 'border-purple-500/30',
      activeRing: 'ring-2 ring-purple-500/80',
      tooltip: 'Capped at 30. Evaluates heuristics, execution behaviors, and anomalies.',
    },
    {
      id: 'GEOLOCATION',
      label: 'Infrastructure & Geo',
      value: geo,
      cap: 15,
      color: 'bg-cyan-500',
      text: 'text-cyan-400',
      border: 'border-cyan-500/30',
      activeRing: 'ring-2 ring-cyan-500/80',
      tooltip: 'Capped at 15. Evaluates Tor exit nodes, VPN/proxy relays, datacenter origins, and country TLD mismatches.',
    },
  ];

  return (
    <div id="score-breakdown-container" className="p-4 rounded-xl bg-[var(--bg-panel)] border border-[var(--border-subtle)] space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-primary)] font-mono">
            Score Assembly & Group Ceilings
          </h3>
          <p className="text-[11px] text-[var(--text-secondary)]">
            Transparent breakdown preventing double-counting. Hover groups to isolate matching factors.
          </p>
        </div>
        <div className="text-right">
          <span className="font-mono text-sm font-bold text-[var(--text-primary)]">{totalScore}</span>
          <span className="text-[11px] text-[var(--text-tertiary)] font-mono"> / 100</span>
        </div>
      </div>

      {/* Visual Stacked Progress Bar */}
      <div className="w-full h-3 bg-[var(--bg-inset)] rounded-full flex overflow-hidden border border-[var(--border-strong)]">
        {groups.map((g) => {
          if (g.value <= 0) return null;
          const isHovered = hoveredGroup === g.id;
          return (
            <div
              key={g.id}
              className={`${g.color} h-full transition-all duration-200 cursor-pointer ${isHovered ? 'brightness-125 opacity-100 scale-y-110' : 'opacity-90'
                }`}
              style={{ width: `${Math.min(100, (g.value / 100) * 100)}%` }}
              onMouseEnter={() => onHoverGroup?.(g.id)}
              onMouseOver={() => onHoverGroup?.(g.id)}
              onMouseLeave={() => onHoverGroup?.(null)}
              title={`${g.label}: +${g.value} pts (capped at +${g.cap})`}
            />
          );
        })}
      </div>

      {/* Group Pills & Breakdown Chips with Ceilings */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 pt-1 text-[11px]">
        {groups.map((g) => {
          const isHovered = hoveredGroup === g.id;
          return (
            <div
              key={g.id}
              data-group-id={g.id}
              onMouseEnter={() => onHoverGroup?.(g.id)}
              onMouseOver={() => onHoverGroup?.(g.id)}
              onPointerEnter={() => onHoverGroup?.(g.id)}
              onMouseLeave={() => onHoverGroup?.(null)}
              className={`p-2.5 rounded-lg border transition-all cursor-pointer flex items-center justify-between ${isHovered
                  ? `bg-[var(--bg-elevated)] ${g.border} ${g.activeRing} shadow-sm`
                  : 'bg-[var(--bg-inset)] border-[var(--border-subtle)] hover:border-[var(--border-strong)]'
                }`}
            >
              <span className="text-[var(--text-secondary)] truncate font-medium">{g.label}</span>
              <Tooltip content={g.tooltip} position="top">
                <span className={`font-mono font-bold ml-1.5 shrink-0 flex items-center gap-1 ${g.value > 0 ? g.text : 'text-[var(--text-tertiary)]'}`}>
                  +{g.value}
                  <span className="text-[10px] text-[var(--text-tertiary)] font-normal">/ {g.cap}</span>
                  <Info className="w-3 h-3 text-[var(--text-tertiary)] opacity-60 hover:opacity-100" />
                </span>
              </Tooltip>
            </div>
          );
        })}
      </div>

      {/* Mitigating Subtraction Group */}
      <div
        data-group-id="MITIGATING"
        onMouseEnter={() => onHoverGroup?.('MITIGATING')}
        onMouseLeave={() => onHoverGroup?.(null)}
        className={`p-2.5 rounded-lg border transition-all cursor-pointer flex items-center justify-between text-xs ${hoveredGroup === 'MITIGATING'
            ? 'bg-emerald-500/15 border-emerald-500/40 ring-2 ring-emerald-500/80 shadow-sm'
            : 'bg-emerald-500/5 border-emerald-500/20 hover:border-emerald-500/30'
          }`}
      >
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span className="text-emerald-400 font-medium">
            Mitigating Factors (Verified Trust / Proven History)
          </span>
        </div>
        <Tooltip content="Capped at -30 to prevent double-counting." position="top">
          <div className="flex items-center gap-1 font-mono font-bold text-emerald-400">
            <span>{mit < 0 ? `${mit} pts` : '0 pts'}</span>
            <span className="text-[10px] text-emerald-500/70 font-normal">(floor -30)</span>
            <Info className="w-3 h-3 text-emerald-500/70 opacity-80 hover:opacity-100" />
          </div>
        </Tooltip>
      </div>
    </div>
  );
};
