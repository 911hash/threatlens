import React from 'react';
import { AlertOctagon, CheckCircle2, AlertTriangle, ShieldQuestion } from 'lucide-react';
import type { RiskLevel } from '../types/threat';

interface RecommendedActionCardProps {
  action: string;
  level: RiskLevel;
}

export const RecommendedActionCard: React.FC<RecommendedActionCardProps> = ({ action, level }) => {
  const getBannerStyle = (lvl: RiskLevel) => {
    switch (lvl) {
      case 'CRITICAL':
      case 'HIGH':
        return {
          icon: <AlertOctagon className="w-5 h-5 text-red-400 shrink-0" />,
          cardBg: 'bg-red-950/20 border-red-500/40 text-red-200',
          title: 'Immediate Defensive Action Required',
        };
      case 'MEDIUM':
        return {
          icon: <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />,
          cardBg: 'bg-amber-950/20 border-amber-500/40 text-amber-200',
          title: 'Caution Advised',
        };
      case 'SAFE':
      case 'LOW':
        return {
          icon: <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />,
          cardBg: 'bg-emerald-950/15 border-emerald-500/30 text-emerald-200',
          title: 'Standard Operational Guidance',
        };
      default:
        return {
          icon: <ShieldQuestion className="w-5 h-5 text-slate-400 shrink-0" />,
          cardBg: 'bg-slate-900/60 border-slate-700 text-slate-300',
          title: 'Unverified Entity - Heightened Scrutiny',
        };
    }
  };

  const style = getBannerStyle(level);

  return (
    <div className={`p-5 rounded-xl border flex items-start gap-4 shadow-md ${style.cardBg}`}>
      <div className="mt-0.5">{style.icon}</div>
      <div className="space-y-1">
        <h4 className="text-sm font-bold uppercase tracking-wider font-mono">{style.title}</h4>
        <p className="text-sm font-medium leading-relaxed">{action}</p>
        <p className="text-[11px] opacity-75 pt-1">
          ThreatLens assessments represent multi-engine intelligence synthesis; absence of detection is not a warranty of safety.
        </p>
      </div>
    </div>
  );
};
