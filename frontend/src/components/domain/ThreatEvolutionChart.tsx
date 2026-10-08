import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ReferenceLine,
} from 'recharts';

export interface ThreatEvolutionPoint {
  label: string;
  score: number;
  level: string;
  id: string;
}

export interface ThreatEvolutionChartProps {
  data: ThreatEvolutionPoint[];
}

export const ThreatEvolutionChart: React.FC<ThreatEvolutionChartProps> = ({ data }) => {
  if (!data || data.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-xs text-[var(--text-tertiary)] font-mono">
        Insufficient history data points recorded for evolution chart.
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.35} />
            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} opacity={0.4} />
        <XAxis dataKey="label" stroke="var(--text-tertiary)" fontSize={11} tickLine={false} />
        <YAxis domain={[0, 100]} stroke="var(--text-tertiary)" fontSize={11} tickLine={false} />
        <ReferenceLine y={75} stroke="#ef4444" strokeDasharray="3 3" opacity={0.6} label={{ value: 'CRITICAL', fill: '#ef4444', fontSize: 10 }} />
        <ReferenceLine y={50} stroke="#f59e0b" strokeDasharray="3 3" opacity={0.5} label={{ value: 'HIGH', fill: '#f59e0b', fontSize: 10 }} />
        <Tooltip
          content={({ active, payload }) => {
            if (active && payload && payload.length) {
              const pt = payload[0].payload as ThreatEvolutionPoint;
              return (
                <div className="p-2.5 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-strong)] shadow-md text-xs font-mono space-y-1">
                  <div className="text-[var(--text-primary)] font-bold">{pt.id}</div>
                  <div className="text-blue-400 font-bold">Risk Score: {pt.score} / 100</div>
                  <div className="text-[var(--text-secondary)]">{pt.level}</div>
                </div>
              );
            }
            return null;
          }}
        />
        <Area
          type="monotone"
          dataKey="score"
          stroke="#3b82f6"
          strokeWidth={2.5}
          fillOpacity={1}
          fill="url(#scoreGrad)"
          dot={{ r: 4, fill: '#3b82f6', strokeWidth: 1, stroke: '#ffffff' }}
          activeDot={{ r: 6, fill: '#60a5fa' }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
};
export default ThreatEvolutionChart;
