import React from 'react';
import {
  GitCommit,
  Clock,
  AlertTriangle,
  Server,
  ArrowRight,
  Mail,
  Send,
  CornerDownRight,
  ShieldAlert,
} from 'lucide-react';
import type { EmailHeaderAnalysis } from '../../types/threat';
import { Badge } from '../primitives/Badge';
import { DefangText } from './DefangText';
import { IndicatorChip } from './IndicatorChip';

export interface HeaderChainPanelProps {
  headerAnalysis?: EmailHeaderAnalysis;
  sender?: string;
  replyTo?: string;
  subject?: string;
  date?: string;
  className?: string;
}

export const HeaderChainPanel: React.FC<HeaderChainPanelProps> = ({
  headerAnalysis,
  sender,
  replyTo,
  subject,
  date,
  className = '',
}) => {
  if (!headerAnalysis) {
    return null;
  }

  const {
    hop_count,
    hops,
    timing_gaps,
    unexpected_relays,
    sender_reply_to_mismatch,
    mismatch_details,
    x_spam_status,
    x_mailer,
    x_originating_ip,
    anomalies,
  } = headerAnalysis;

  return (
    <div className={`p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center shrink-0">
            <GitCommit className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-black text-[var(--text-primary)] flex items-center gap-2">
              <span>Received-Chain Routing & Header Forensics</span>
              <Badge variant="neutral" size="xs">{hop_count} Relays</Badge>
            </h3>
            <p className="text-xs text-[var(--text-secondary)]">
              Multi-hop relay provenance, MTA transit latency, and routing path anomaly detection.
            </p>
          </div>
        </div>

        {anomalies.length > 0 && (
          <Badge variant="critical" size="sm" className="flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>{anomalies.length} Header Anomalies</span>
          </Badge>
        )}
      </div>

      {/* SENDER / REPLY-TO MISMATCH CALLOUT */}
      {sender_reply_to_mismatch && (
        <div className="p-4 rounded-xl border border-red-500/30 bg-red-500/10 space-y-2">
          <div className="flex items-center gap-2 text-red-400 text-xs font-bold">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            <span>Sender & Reply-To Routing Deception Detected</span>
            <Badge variant="critical" size="xs">High Risk</Badge>
          </div>
          <p className="text-xs text-red-300 leading-relaxed">
            {(mismatch_details || 'The claimed sender address differs from the Reply-To address. Responses will be routed to an alternate destination.').replace(/&#x27;/g, "'").replace(/&quot;/g, '"')}
          </p>
          <div className="pt-2 grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
            <div className="p-2 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-0.5">
              <span className="text-[10px] text-[var(--text-tertiary)] uppercase font-sans">Claimed From Header:</span>
              <div className="text-[var(--text-primary)] truncate font-semibold">
                <DefangText value={sender || 'Unknown'} showCopy />
              </div>
            </div>
            <div className="p-2 rounded bg-[var(--bg-inset)] border border-red-500/30 space-y-0.5">
              <span className="text-[10px] text-red-400 uppercase font-sans font-bold">Redirected Reply-To:</span>
              <div className="text-red-400 truncate font-semibold">
                <DefangText value={replyTo || 'Unknown'} showCopy />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* X-HEADERS & METADATA GRID */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
        {/* Originating IP */}
        <div className="p-3 rounded-xl bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1">
          <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Originating Sender IP</span>
          <div className="font-mono text-sm font-bold text-[var(--text-primary)] truncate">
            {x_originating_ip ? (
              <IndicatorChip indicator={x_originating_ip} type="ip" size="xs" />
            ) : (
              <span className="text-[var(--text-tertiary)] text-xs">Not reported</span>
            )}
          </div>
        </div>

        {/* Mailer Software */}
        <div className="p-3 rounded-xl bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1">
          <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Mail Client / MTA Software</span>
          <div className="font-mono text-xs text-[var(--text-primary)] truncate font-semibold">
            {x_mailer ? (
              <span title={x_mailer}>{x_mailer}</span>
            ) : (
              <span className="text-[var(--text-tertiary)]">Standard / None</span>
            )}
          </div>
        </div>

        {/* Spam Status */}
        <div className="p-3 rounded-xl bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1">
          <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">Upstream Spam Classification</span>
          <div className="font-mono text-xs truncate">
            {x_spam_status ? (
              <span className={x_spam_status.toLowerCase().includes('yes') ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                {x_spam_status}
              </span>
            ) : (
              <span className="text-[var(--text-tertiary)]">Not tagged</span>
            )}
          </div>
        </div>
      </div>

      {/* RECEIVED CHAIN TIMELINE / HOPS */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs font-bold text-[var(--text-primary)]">
          <span className="flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-blue-400" />
            <span>MTA Relay Sequence (Sender → Recipient)</span>
          </span>
          <span className="text-[11px] font-normal text-[var(--text-secondary)]">Ordered chronologically</span>
        </div>

        {hops.length === 0 ? (
          <div className="p-4 rounded-xl bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-xs text-[var(--text-tertiary)] text-center">
            No Received hops documented in message headers.
          </div>
        ) : (
          <div className="space-y-2">
            {hops.map((hop, i) => {
              const isFirst = i === 0;
              const isLast = i === hops.length - 1;
              const isSuspiciousDelay = hop.delay_seconds !== undefined && hop.delay_seconds !== null && (hop.delay_seconds > 3600 || hop.delay_seconds < -60);

              return (
                <div
                  key={hop.hop_index}
                  className={`p-3.5 rounded-xl border transition-all text-xs font-mono ${isSuspiciousDelay
                      ? 'border-amber-500/30 bg-amber-500/5'
                      : 'border-[var(--border-subtle)] bg-[var(--bg-inset)]'
                    }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    {/* Hop Identifier */}
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[var(--bg-panel)] border border-[var(--border-subtle)] text-[var(--text-secondary)]">
                        Hop {hop.hop_index}
                      </span>
                      {isFirst && <Badge variant="low" size="xs">Origin MTA</Badge>}
                      {isLast && <Badge variant="neutral" size="xs">Inbound Gateway</Badge>}
                      {hop.ip && (
                        <IndicatorChip indicator={hop.ip} type="ip" size="xs" />
                      )}
                    </div>

                    {/* Delay / Timestamp */}
                    <div className="flex items-center gap-2 font-sans text-[11px] text-[var(--text-tertiary)]">
                      {hop.delay_seconds !== undefined && hop.delay_seconds !== null && (
                        <span className={`inline-flex items-center gap-1 font-mono font-semibold ${isSuspiciousDelay ? 'text-amber-400' : 'text-[var(--text-secondary)]'}`}>
                          <Clock className="w-3 h-3" />
                          <span>
                            {hop.delay_seconds < 0
                              ? `Clock skew (${Math.abs(hop.delay_seconds)}s earlier)`
                              : `${hop.delay_seconds}s latency`}
                          </span>
                        </span>
                      )}
                      {hop.timestamp && (
                        <span>· {new Date(hop.timestamp).toLocaleTimeString()}</span>
                      )}
                    </div>
                  </div>

                  {/* Routing Details */}
                  <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-[var(--text-secondary)] pt-2 border-t border-[var(--border-subtle)]">
                    <div className="truncate">
                      <span className="text-[var(--text-tertiary)]">From: </span>
                      <span className="text-[var(--text-primary)]" title={hop.from_host || 'Unknown'}>
                        {hop.from_host || 'Direct / Undisclosed'}
                      </span>
                    </div>
                    <div className="truncate">
                      <span className="text-[var(--text-tertiary)]">By: </span>
                      <span className="text-[var(--text-primary)]" title={hop.by_host || 'Unknown'}>
                        {hop.by_host || 'Unknown'}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* TIMING GAPS CALLOUT */}
      {timing_gaps.length > 0 && (
        <div className="p-3 rounded-xl border border-amber-500/25 bg-amber-500/5 text-xs text-amber-300 space-y-1">
          <div className="font-semibold flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-amber-400" />
            <span>Relay Timing Gap Discrepancies Noted:</span>
          </div>
          <ul className="list-disc list-inside space-y-0.5 text-[11px] text-amber-200/90 font-mono">
            {timing_gaps.map((gap, i) => (
              <li key={i}>{gap}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
