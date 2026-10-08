import React from 'react';
import { Sparkles, ArrowRight, ShieldCheck, ShieldAlert, AlertTriangle, Users, CheckSquare } from 'lucide-react';
import type { Factor, RiskLevel } from '../types/threat';
import { Badge } from './primitives/Badge';

export function getPlainSentenceForFactor(factor: Factor): string {
  if (!factor) return 'Security indicator identified in scan telemetry.';
  const id = (factor.id || '').toLowerCase();
  const title = (factor.title || '').toLowerCase();
  const desc = factor.description || '';

  // 1. Antivirus & Engine detections
  if (
    id.includes('av_detections') ||
    id.includes('antivirus') ||
    title.includes('av engine') ||
    title.includes('flagged target')
  ) {
    return 'Multiple antivirus security scanners identified harmful malware or trojan files in this target.';
  }

  // 2. Phishing and Blocklists
  if (id.includes('openphish') || title.includes('openphish')) {
    return 'Flagged by OpenPhish as a fake login portal built to steal passwords and credentials.';
  }
  if (id.includes('safe_browsing') || title.includes('safe browsing')) {
    return 'Blacklisted by Google Safe Browsing due to deceptive content or dangerous software downloads.';
  }
  if (id.includes('urlhaus') || title.includes('urlhaus')) {
    return 'Listed in abuse.ch URLhaus as a site actively distributing malicious malware payloads.';
  }
  if (id.includes('vt_category') || title.includes('category')) {
    return 'Categorized as malicious or phishing by global security reputation services.';
  }

  // 3. Domain Infrastructure & Redirects
  if (id.includes('new_domain') || title.includes('newly registered') || title.includes('domain age')) {
    return 'This website domain was registered only days ago — a classic tactic used in throwaway attack campaigns.';
  }
  if (id.includes('redirect') || title.includes('redirect')) {
    return 'The link bounces your browser through intermediate websites to conceal where you actually end up.';
  }
  if (id.includes('malicious_ip') || title.includes('ip')) {
    return 'Hosted on an internet server address with a recorded history of malicious activity.';
  }
  if (id.includes('suspicious_cert') || id.includes('cert') || title.includes('certificate')) {
    return 'Security certificate patterns suggest disposable or suspicious registration details.';
  }

  // 4. Sandbox Behavior
  if (id.includes('powershell') || title.includes('powershell')) {
    return 'The program attempts to launch hidden Windows system scripts (PowerShell) behind the scenes.';
  }
  if (id.includes('persistence') || title.includes('persistence')) {
    return 'The file configures itself to automatically start every time your computer boots up.';
  }
  if (id.includes('executable') || title.includes('executable')) {
    return 'Displays suspicious program execution behavior indicative of unauthorized tampering.';
  }

  // 5. Mitigating and Conflicts
  if (id.includes('trusted_signature') || title.includes('signature')) {
    return 'Digitally signed by a verified, trustworthy software publisher.';
  }
  if (
    id.includes('known_good') ||
    id.includes('established_reputation') ||
    title.includes('reputation')
  ) {
    return 'Long-established domain with verified benign operational history.';
  }
  if (id.includes('high_prevalence') || title.includes('prevalence')) {
    return 'Observed widely across the internet with no recorded security incidents.';
  }
  if (id.includes('conflict') || title.includes('conflict')) {
    return 'Even though the file claims to be digitally signed, security engines detected malware inside it.';
  }

  // 6. Group-level fallback
  switch (factor.group) {
    case 'AV_DETECTIONS':
      return 'Security engines flagged harmful software patterns in this target.';
    case 'REPUTATION_LISTS':
      return 'Identified on recognized security blocklists as a confirmed threat.';
    case 'DOMAIN_INFRA':
      return 'Network routing and registration patterns indicate suspicious infrastructure.';
    case 'BEHAVIOR':
      return 'Demonstrates unauthorized background actions or system modifications.';
    case 'MITIGATING':
      return 'Displays verified characteristics consistent with legitimate software.';
    default:
      // 7. Universal fallback from description or title
      return desc || factor.title || 'Contributing risk indicator identified in scan evidence.';
  }
}

export function buildPlainEnglishSummary(
  level: RiskLevel,
  score: number,
  factors: Factor[],
  explanation: string,
  recommendedAction: string
): {
  overviewText: string;
  bulletPoints: string[];
  actionText: string;
} {
  const bullets: string[] = [];
  const actionText = recommendedAction ? recommendedAction.trim() : '';

  // Case A: Zero factors or UNKNOWN verdict
  if (!factors || factors.length === 0 || level === 'UNKNOWN') {
    const overview =
      'No reputation data was found across analyzed security sources. This does NOT mean it is safe; proceed with caution.';
    const action =
      actionText || 'Treat this target with suspicion until verified by trusted security channels.';
    return {
      overviewText: overview,
      bulletPoints: ['No previous records or engine detections found in threat intelligence databases.'],
      actionText: action,
    };
  }

  // Case B: Clean / SAFE target
  if (level === 'SAFE' && score < 10) {
    const overview =
      'No malicious activity or suspicious patterns were detected across security sources. The target appears clean and legitimate based on current telemetry.';
    const action = actionText || 'Safe to access under normal security practices.';
    return {
      overviewText: overview,
      bulletPoints:
        factors.length > 0
          ? factors.map(getPlainSentenceForFactor)
          : ['Verified authority databases show clean operational records.'],
      actionText: action,
    };
  }

  // Case C: Suspicious / Malicious targets (LOW, MEDIUM, HIGH, CRITICAL)
  let verdictSummary = '';
  if (level === 'CRITICAL') {
    verdictSummary = `This target scored ${score}/100 and represents an active, confirmed danger to your computer or personal data.`;
  } else if (level === 'HIGH') {
    verdictSummary = `This target scored ${score}/100 and exhibits multiple dangerous signals consistent with an active attack campaign.`;
  } else if (level === 'MEDIUM') {
    verdictSummary = `This target scored ${score}/100 and exhibits suspicious signals that warrant caution before interacting.`;
  } else {
    verdictSummary = `This target scored ${score}/100 with minor anomalies detected, though overall risk remains low.`;
  }

  // Translate all factors that actually exist in the scan
  factors.forEach((f) => {
    bullets.push(getPlainSentenceForFactor(f));
  });

  // Compose 2-4 sentences narrative
  const topFindings = bullets.slice(0, 2).join(' ');
  const fullOverview = `${verdictSummary} ${topFindings} ${actionText}`.trim();

  return {
    overviewText: fullOverview,
    bulletPoints: bullets,
    actionText: actionText,
  };
}

export interface ExplainSimplyCardProps {
  score: number;
  level: RiskLevel;
  factors: Factor[];
  explanation: string;
  recommendedAction?: string;
  isDemo?: boolean;
}

export const ExplainSimplyCard: React.FC<ExplainSimplyCardProps> = ({
  score,
  level,
  factors,
  explanation,
  recommendedAction = '',
  isDemo = false,
}) => {
  const { overviewText, bulletPoints, actionText } = buildPlainEnglishSummary(
    level,
    score,
    factors,
    explanation,
    recommendedAction
  );

  // Derive "Who should care" audience based on severity
  const getAudience = () => {
    switch (level) {
      case 'CRITICAL':
        return 'Security Operations Center (SOC) Tier 1/2, Incident Response Team, Network Perimeter Engineers';
      case 'HIGH':
        return 'Security Operations Team, Firewall & Endpoint Administrators, IT Security Lead';
      case 'MEDIUM':
        return 'IT Helpdesk, System Administrators, Security Awareness Officers';
      case 'LOW':
      case 'SAFE':
        return 'End Users, General IT Support';
      default:
        return 'Threat Intelligence Analysts, Security Researchers';
    }
  };

  // Derive structured "What to do" action items
  const getActionChecklist = () => {
    if (level === 'CRITICAL') {
      return [
        { step: 1, title: 'Block Target at Perimeter', detail: 'Add indicator to firewall blocklists and email security filters immediately.', priority: 'P1 - Immediate' },
        { step: 2, title: 'Isolate Impacted Endpoints', detail: 'Quarantine any host machines that initiated outbound requests to this URL or executed this hash.', priority: 'P1 - Immediate' },
        { step: 3, title: 'Revoke Associated Credentials', detail: 'Force password reset and terminate active OAuth sessions for users who interacted with this portal.', priority: 'P2 - High' },
      ];
    }
    if (level === 'HIGH') {
      return [
        { step: 1, title: 'Perimeter Quarantine', detail: 'Block network routing and quarantine inbound email containing this indicator.', priority: 'P2 - High' },
        { step: 2, title: 'Scan User Endpoints', detail: 'Trigger an automated antivirus endpoint scan on machines associated with recent requests.', priority: 'P2 - High' },
      ];
    }
    if (level === 'MEDIUM') {
      return [
        { step: 1, title: 'Monitor & Advise', detail: 'Alert relevant personnel to exercise caution and verify request authenticity.', priority: 'P3 - Medium' },
        { step: 2, title: 'Add to Watchlist', detail: 'Track target telemetry for score escalation or newly published blacklist listings.', priority: 'P3 - Medium' },
      ];
    }
    return [
      { step: 1, title: 'Standard Operational Access', detail: 'No blocking required. Follow normal corporate internet usage guidelines.', priority: 'Normal' },
    ];
  };

  const checklist = getActionChecklist();

  return (
    <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] p-5 md:p-6 space-y-5 shadow-xs">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-[var(--border-subtle)]">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-[var(--text-primary)]">
                In Plain English
              </h3>
              {isDemo && <Badge variant="demo" size="xs">Demo Record</Badge>}
            </div>
            <p className="text-[11px] text-[var(--text-secondary)]">
              Clear, non-technical synthesis for decision makers and analysts
            </p>
          </div>
        </div>

        <Badge variant={level === 'CRITICAL' ? 'critical' : level === 'HIGH' ? 'high' : level === 'MEDIUM' ? 'medium' : 'low'} size="sm">
          {level} RISK
        </Badge>
      </div>

      {/* Main Narrative Paragraph */}
      <div className="p-4 rounded-xl bg-[var(--bg-inset)] border border-[var(--border-subtle)]">
        <p className="text-sm font-sans font-medium text-[var(--text-primary)] leading-relaxed">
          {overviewText}
        </p>
      </div>

      {/* What to do Checklist */}
      <div className="space-y-2.5">
        <div className="flex items-center gap-2 text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)]">
          <CheckSquare className="w-3.5 h-3.5 text-blue-400" />
          <span>What to do (Recommended Action Checklist)</span>
        </div>

        <div className="space-y-2">
          {checklist.map((item) => (
            <div
              key={item.step}
              className="p-3 rounded-xl bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex items-start gap-3 transition-colors"
            >
              <div className="w-6 h-6 rounded-md bg-[var(--bg-inset)] border border-[var(--border-strong)] flex items-center justify-center text-xs font-mono font-bold text-[var(--text-primary)] shrink-0 mt-0.5">
                {item.step}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-xs text-[var(--text-primary)]">
                    {item.title}
                  </span>
                  <Badge variant={item.priority.includes('P1') ? 'critical' : item.priority.includes('P2') ? 'high' : 'neutral'} size="xs">
                    {item.priority}
                  </Badge>
                </div>
                <p className="text-xs text-[var(--text-secondary)] mt-0.5 leading-relaxed">
                  {item.detail}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Who should care line */}
      <div className="p-3 rounded-xl bg-[var(--bg-inset)] border border-[var(--border-subtle)] flex items-center gap-2.5 text-xs text-[var(--text-secondary)]">
        <Users className="w-4 h-4 text-blue-400 shrink-0" />
        <div>
          <span className="font-bold text-[var(--text-primary)]">Who should care: </span>
          <span>{getAudience()}</span>
        </div>
      </div>
    </div>
  );
};
