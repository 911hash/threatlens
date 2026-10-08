import React from 'react';

interface ScoreAssemblyBarProps {
  breakdown?: Record<string, number>;
  groupBreakdown?: Record<string, number>;
  totalScore: number;
}

export const ScoreAssemblyBar: React.FC<ScoreAssemblyBarProps> = ({ breakdown, groupBreakdown, totalScore }) => {
  const b = breakdown || groupBreakdown || {};
  const av = b['AV_DETECTIONS'] || 0;
  const rep = b['REPUTATION_LISTS'] || 0;
  const infra = b['DOMAIN_INFRA'] || 0;
  const beh = b['BEHAVIOR'] || 0;
  const mit = b['MITIGATING'] || 0;

  // Maximum caps defined in risk engine
  const groups = [
    { label: 'AV Detections', value: av, cap: 50, color: 'bg-red-500', text: 'text-red-400' },
    { label: 'Reputation Lists', value: rep, cap: 35, color: 'bg-orange-500', text: 'text-orange-400' },
    { label: 'Domain & Infra', value: infra, cap: 20, color: 'bg-amber-500', text: 'text-amber-400' },
    { label: 'Sandbox Behavior', value: beh, cap: 30, color: 'bg-purple-500', text: 'text-purple-400' },
  ];

  return (
    <div className="p-4 rounded-xl bg-threat-card border border-threat-border space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
            Transparent Score Assembly
          </h3>
          <p className="text-[11px] text-slate-400">
            Anti-double-counting engine caps point contributions within independent groups.
          </p>
        </div>
        <div className="text-right">
          <span className="font-mono text-sm font-bold text-slate-200">{totalScore}</span>
          <span className="text-[11px] text-slate-500"> / 100</span>
        </div>
      </div>

      {/* Visual Stacked Progress Bar */}
      <div className="w-full h-3 bg-slate-900 rounded-full flex overflow-hidden border border-slate-800">
        {groups.map((g) => {
          if (g.value <= 0) return null;
          return (
            <div
              key={g.label}
              className={`${g.color} h-full transition-all`}
              style={{ width: `${Math.min(100, g.value)}%` }}
              title={`${g.label}: +${g.value} pts (capped at +${g.cap})`}
            />
          );
        })}
      </div>

      {/* Group Pills & Breakdown Chips */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[11px]">
        {groups.map((g) => (
          <div
            key={g.label}
            className="p-2 rounded bg-slate-950/40 border border-threat-border/80 flex items-center justify-between"
          >
            <span className="text-slate-400 truncate">{g.label}</span>
            <span className={`font-mono font-bold ${g.value > 0 ? g.text : 'text-slate-500'}`}>
              +{g.value} <span className="text-[10px] text-slate-600 font-normal">/ {g.cap}</span>
            </span>
          </div>
        ))}
      </div>

      {mit < 0 && (
        <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-between text-xs text-emerald-400">
          <span>Mitigating Protection Applied (Verified Credentials / Known-Good)</span>
          <span className="font-mono font-bold">{mit} pts (floor -30)</span>
        </div>
      )}
    </div>
  );
};
