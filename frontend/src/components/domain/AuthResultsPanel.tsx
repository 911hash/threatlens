import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  HelpCircle,
  Key,
  Globe,
  FileCheck2,
  Lock,
  Layers,
} from 'lucide-react';
import type { EmailAuthResult } from '../../types/threat';
import { Badge } from '../primitives/Badge';
import { DefangText } from './DefangText';

export interface AuthResultsPanelProps {
  authResult?: EmailAuthResult;
  className?: string;
}

export const AuthResultsPanel: React.FC<AuthResultsPanelProps> = ({
  authResult,
  className = '',
}) => {
  if (!authResult) {
    return null;
  }

  const renderStatusBadge = (status: string) => {
    const s = (status || 'none').toLowerCase();
    if (s === 'pass') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-500/10 border border-emerald-500/25 text-emerald-400">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>PASS</span>
        </span>
      );
    }
    if (s === 'fail') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-red-500/10 border border-red-500/25 text-red-400">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>FAIL</span>
        </span>
      );
    }
    if (s === 'neutral') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-500/10 border border-amber-500/25 text-amber-400">
          <HelpCircle className="w-3.5 h-3.5" />
          <span>NEUTRAL</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-gray-500/10 border border-gray-500/25 text-[var(--text-tertiary)]">
        <ShieldX className="w-3.5 h-3.5" />
        <span>NONE</span>
      </span>
    );
  };

  const getBorderColor = (status: string) => {
    const s = (status || 'none').toLowerCase();
    if (s === 'pass') return 'border-emerald-500/25 bg-emerald-500/5';
    if (s === 'fail') return 'border-red-500/25 bg-red-500/5';
    if (s === 'neutral') return 'border-amber-500/25 bg-amber-500/5';
    return 'border-[var(--border-subtle)] bg-[var(--bg-inset)]';
  };

  return (
    <div className={`p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center shrink-0">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-black text-[var(--text-primary)] flex items-center gap-2">
              <span>Email Authentication Protocol Forensics</span>
              <Badge variant="neutral" size="xs">RFC 8601</Badge>
            </h3>
            <p className="text-xs text-[var(--text-secondary)]">
              Cryptographic integrity, sender authorization records, and domain alignment verification.
            </p>
          </div>
        </div>

        {/* Global Alignment State Badge */}
        <div className="flex items-center gap-2">
          {authResult.dmarc === 'pass' && (
            <Badge variant="low" size="sm">DMARC Aligned & Enforced</Badge>
          )}
          {authResult.dmarc === 'fail' && (
            <Badge variant="critical" size="sm">DMARC Alignment Failed</Badge>
          )}
        </div>
      </div>

      {/* 4 Protocol Badges Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* 1. SPF */}
        <div className={`p-4 rounded-xl border ${getBorderColor(authResult.spf)} transition-all space-y-3`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-[var(--text-primary)]">
              <Globe className="w-4 h-4 text-blue-400" />
              <span>SPF</span>
            </div>
            {renderStatusBadge(authResult.spf)}
          </div>
          <div className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
            Sender Policy Framework validates whether sending server IP was authorized by domain DNS TXT records.
          </div>
          {authResult.spf_domain && (
            <div className="text-[10px] font-mono text-[var(--text-tertiary)] pt-1 border-t border-[var(--border-subtle)]">
              Domain: <DefangText value={authResult.spf_domain} showCopy />
            </div>
          )}
        </div>

        {/* 2. DKIM */}
        <div className={`p-4 rounded-xl border ${getBorderColor(authResult.dkim)} transition-all space-y-3`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-[var(--text-primary)]">
              <Key className="w-4 h-4 text-purple-400" />
              <span>DKIM</span>
            </div>
            {renderStatusBadge(authResult.dkim)}
          </div>
          <div className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
            DomainKeys Identified Mail verifies cryptographic public-key signature of message headers and body.
          </div>
          {authResult.dkim_domain && (
            <div className="text-[10px] font-mono text-[var(--text-tertiary)] pt-1 border-t border-[var(--border-subtle)]">
              Signing: <DefangText value={authResult.dkim_domain} showCopy />
            </div>
          )}
        </div>

        {/* 3. DMARC */}
        <div className={`p-4 rounded-xl border ${getBorderColor(authResult.dmarc)} transition-all space-y-3`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-[var(--text-primary)]">
              <FileCheck2 className="w-4 h-4 text-indigo-400" />
              <span>DMARC</span>
            </div>
            {renderStatusBadge(authResult.dmarc)}
          </div>
          <div className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
            Domain-based Message Authentication combines SPF + DKIM alignment to protect domain brand identity.
          </div>
          {authResult.dmarc_policy && (
            <div className="text-[10px] font-mono text-[var(--text-tertiary)] pt-1 border-t border-[var(--border-subtle)] flex items-center justify-between">
              <span>Policy:</span>
              <span className="uppercase font-bold text-amber-400">{authResult.dmarc_policy}</span>
            </div>
          )}
        </div>

        {/* 4. ARC */}
        <div className={`p-4 rounded-xl border ${getBorderColor(authResult.arc)} transition-all space-y-3`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-[var(--text-primary)]">
              <Layers className="w-4 h-4 text-teal-400" />
              <span>ARC</span>
            </div>
            {renderStatusBadge(authResult.arc)}
          </div>
          <div className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
            Authenticated Received Chain preserves original authentication through intermediate mailing list forwarders.
          </div>
          <div className="text-[10px] font-mono text-[var(--text-tertiary)] pt-1 border-t border-[var(--border-subtle)]">
            Chain: {authResult.arc === 'pass' ? 'Sealed' : 'None / Broken'}
          </div>
        </div>
      </div>

      {/* Domain Alignment Section */}
      <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] space-y-3">
        <div className="text-xs font-bold text-[var(--text-primary)] flex items-center gap-2">
          <span>Domain Alignment Forensics</span>
          <span className="text-[10px] font-normal text-[var(--text-secondary)]">(DMARC Alignment Requirement)</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          {/* Header From */}
          <div className="p-3 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1">
            <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Header From Domain</span>
            <div className="font-mono text-sm font-bold text-[var(--text-primary)] truncate">
              {authResult.from_domain ? (
                <DefangText value={authResult.from_domain} showCopy />
              ) : (
                <span className="text-[var(--text-tertiary)]">Not specified</span>
              )}
            </div>
          </div>

          {/* SPF Domain Alignment */}
          <div className="p-3 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">SPF Alignment</span>
              {authResult.spf_aligned === true && (
                <Badge variant="low" size="xs">Aligned</Badge>
              )}
              {authResult.spf_aligned === false && (
                <Badge variant="critical" size="xs">Unaligned</Badge>
              )}
              {authResult.spf_aligned === undefined && (
                <Badge variant="neutral" size="xs">Unknown</Badge>
              )}
            </div>
            <div className="font-mono text-sm text-[var(--text-secondary)] truncate">
              {authResult.spf_domain ? (
                <DefangText value={authResult.spf_domain} showCopy />
              ) : (
                <span className="text-[var(--text-tertiary)]">No MailFrom domain</span>
              )}
            </div>
          </div>

          {/* DKIM Domain Alignment */}
          <div className="p-3 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">DKIM Alignment</span>
              {authResult.dkim_aligned === true && (
                <Badge variant="low" size="xs">Aligned</Badge>
              )}
              {authResult.dkim_aligned === false && (
                <Badge variant="critical" size="xs">Unaligned</Badge>
              )}
              {authResult.dkim_aligned === undefined && (
                <Badge variant="neutral" size="xs">Unknown</Badge>
              )}
            </div>
            <div className="font-mono text-sm text-[var(--text-secondary)] truncate">
              {authResult.dkim_domain ? (
                <DefangText value={authResult.dkim_domain} showCopy />
              ) : (
                <span className="text-[var(--text-tertiary)]">No signing domain</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
