import React from 'react';
import {
  Flame,
  ShieldAlert,
  Globe,
  Terminal,
  ShieldCheck,
  AlertCircle,
  FileCode,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import type { Factor } from '../types/threat';
import { useDrawer } from '../context/DrawerContext';
import { IndicatorChip } from './domain/IndicatorChip';
import { Badge } from './primitives/Badge';
import { Button } from './primitives/Button';
import { getPlainSentenceForFactor } from './ExplainSimplyCard';

export interface FactorsListProps {
  factors: Factor[];
  viewMode?: 'plain' | 'technical';
  hoveredGroup?: string | null;
}

export const FactorsList: React.FC<FactorsListProps> = ({
  factors,
  viewMode = 'technical',
  hoveredGroup,
}) => {
  const drawer = useDrawer();

  const getGroupIcon = (group: string, type: string) => {
    if (type === 'mitigating') return <ShieldCheck className="w-4 h-4 text-emerald-400" />;
    if (type === 'conflict') return <AlertCircle className="w-4 h-4 text-amber-400" />;

    switch (group) {
      case 'AV_DETECTIONS':
        return <Flame className="w-4 h-4 text-red-400" />;
      case 'REPUTATION_LISTS':
        return <ShieldAlert className="w-4 h-4 text-orange-400" />;
      case 'DOMAIN_INFRA':
        return <Globe className="w-4 h-4 text-amber-400" />;
      case 'BEHAVIOR':
        return <Terminal className="w-4 h-4 text-purple-400" />;
      default:
        return <FileCode className="w-4 h-4 text-blue-400" />;
    }
  };

  const handleOpenFactorDrawer = (factor: Factor) => {
    drawer.open(
      <div className="space-y-5 text-xs text-[var(--text-secondary)]">
        <div>
          <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)] tracking-wider">
            Evidence Factor Telemetry
          </span>
          <h3 className="text-base font-bold text-[var(--text-primary)] mt-1">
            {factor.title}
          </h3>
          <p className="text-xs text-[var(--text-secondary)] mt-1.5 leading-relaxed">
            {factor.description}
          </p>
        </div>

        {/* Telemetry Metrics */}
        <div className="grid grid-cols-2 gap-2.5">
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Evidence Group</span>
            <div className="font-mono font-bold text-[var(--text-primary)] text-xs mt-0.5">
              {factor.group}
            </div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Point Impact</span>
            <div
              className={`font-mono font-bold text-xs mt-0.5 ${
                factor.points > 0 ? 'text-red-400' : factor.points < 0 ? 'text-emerald-400' : 'text-slate-400'
              }`}
            >
              {factor.points > 0 ? `+${factor.points}` : factor.points} pts
            </div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Source Provider</span>
            <div className="font-mono text-[var(--text-primary)] text-xs mt-0.5 truncate">
              {factor.source}
            </div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Severity Level</span>
            <div className="font-mono uppercase font-bold text-xs mt-0.5 text-[var(--text-primary)]">
              {factor.severity}
            </div>
          </div>
        </div>

        {/* Plain English Translation */}
        <div className="p-3 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-subtle)] space-y-1">
          <div className="text-[10px] font-mono uppercase text-[var(--text-tertiary)]">
            Plain English Explanation
          </div>
          <div className="text-xs text-[var(--text-primary)]">
            {getPlainSentenceForFactor(factor)}
          </div>
        </div>

        {/* Raw Evidence Object */}
        {factor.evidence_ref && (
          <div className="space-y-1.5">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">
              Raw Evidence Reference
            </span>
            <pre className="p-3 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-strong)] font-mono text-[11px] text-[var(--text-primary)] overflow-x-auto max-h-48 overflow-y-auto">
              {JSON.stringify(factor.evidence_ref, null, 2)}
            </pre>
          </div>
        )}
      </div>,
      {
        title: `Factor: ${factor.id}`,
        fullPageAction: (
          <Button variant="secondary" size="xs" onClick={() => drawer.close()}>
            Dismiss
          </Button>
        ),
      }
    );
  };

  if (!factors || factors.length === 0) {
    return (
      <div className="p-8 rounded-xl bg-[var(--bg-panel)] border border-[var(--border-subtle)] text-center space-y-2">
        <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
        <h4 className="text-sm font-semibold text-[var(--text-primary)]">
          No Negative Risk Factors Identified
        </h4>
        <p className="text-xs text-[var(--text-secondary)] max-w-md mx-auto">
          No security indicators or blacklist matches were flagged in the available telemetry for this target.
        </p>
      </div>
    );
  }

  // Organize factors by group
  const groupOrder = ['AV_DETECTIONS', 'REPUTATION_LISTS', 'DOMAIN_INFRA', 'BEHAVIOR', 'MITIGATING'];
  const groupedFactors = groupOrder.reduce((acc, g) => {
    const list = factors.filter((f) => f.group === g);
    if (list.length > 0) acc[g] = list;
    return acc;
  }, {} as Record<string, Factor[]>);

  // Catch any remaining groups
  factors.forEach((f) => {
    if (!groupOrder.includes(f.group)) {
      if (!groupedFactors[f.group]) groupedFactors[f.group] = [];
      groupedFactors[f.group].push(f);
    }
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between pb-1">
        <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)]">
          Evidence Factors ({factors.length} total)
        </h3>
        <span className="text-[11px] text-[var(--text-tertiary)] font-mono">
          Click any factor row for full evidence telemetry
        </span>
      </div>

      <div className="space-y-4">
        {Object.entries(groupedFactors).map(([groupName, groupFactors]) => {
          const isGroupHovered = hoveredGroup === groupName;

          return (
            <div key={groupName} className="space-y-2">
              <div className="flex items-center gap-2 text-xs font-mono font-semibold text-[var(--text-tertiary)] uppercase">
                <span>{groupName.replace(/_/g, ' ')}</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-tertiary)]">
                  {groupFactors.length}
                </span>
              </div>

              <div className="space-y-2">
                {groupFactors.map((f, idx) => {
                  const plainSentence = getPlainSentenceForFactor(f);
                  const isHighlighted = isGroupHovered;

                  return (
                    <div
                      key={`${f.id}-${idx}`}
                      role="button"
                      tabIndex={0}
                      data-factor-group={f.group}
                      data-highlighted={isHighlighted ? 'true' : 'false'}
                      onClick={() => handleOpenFactorDrawer(f)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleOpenFactorDrawer(f);
                        }
                      }}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between gap-3 ${
                        isHighlighted
                          ? 'ring-2 ring-blue-500/80 bg-[var(--bg-elevated)] border-blue-500/50 shadow-md'
                          : f.type === 'mitigating'
                          ? 'bg-emerald-500/5 border-emerald-500/20 hover:border-emerald-500/40'
                          : f.type === 'conflict'
                          ? 'bg-amber-500/5 border-amber-500/20 hover:border-amber-500/40'
                          : 'bg-[var(--bg-panel)] border-[var(--border-subtle)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-elevated)]'
                      }`}
                    >
                      <div className="flex items-start gap-3 flex-1 min-w-0">
                        <div className="mt-0.5 p-2 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] shrink-0">
                          {getGroupIcon(f.group, f.type)}
                        </div>

                        <div className="space-y-1 flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-semibold text-xs text-[var(--text-primary)]">
                              {f.title}
                            </span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-secondary)]">
                              {f.source}
                            </span>
                            {f.evidence_ref?.target && (
                              <IndicatorChip
                                target={String(f.evidence_ref.target)}
                                className="text-[10px] py-0 px-1.5"
                              />
                            )}
                          </div>

                          <p className="text-xs text-[var(--text-secondary)] line-clamp-2">
                            {viewMode === 'plain' ? plainSentence : f.description}
                          </p>
                        </div>
                      </div>

                      {/* Right: Point impact and expand indicator */}
                      <div className="flex items-center gap-3 shrink-0">
                        <div className="text-right">
                          <span
                            className={`font-mono text-xs font-bold ${
                              f.points > 0
                                ? 'text-red-400'
                                : f.points < 0
                                ? 'text-emerald-400'
                                : 'text-[var(--text-tertiary)]'
                            }`}
                          >
                            {f.points > 0 ? `+${f.points}` : f.points} pts
                          </span>
                        </div>
                        <ChevronRight className="w-4 h-4 text-[var(--text-tertiary)]" />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
