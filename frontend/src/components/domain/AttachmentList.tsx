import React from 'react';
import {
  Paperclip,
  FileText,
  AlertOctagon,
  ShieldCheck,
  Hash,
} from 'lucide-react';
import type { EmailAttachment } from '../../types/threat';
import { Badge } from '../primitives/Badge';
import { DefangText } from './DefangText';
import { CopyButton } from '../primitives/CopyButton';
import { useDefang } from '../../design/DefangContext';

export interface AttachmentListProps {
  attachments?: EmailAttachment[];
  className?: string;
}

export const AttachmentList: React.FC<AttachmentListProps> = ({
  attachments = [],
  className = '',
}) => {
  const { copyIndicator } = useDefang();

  const formatFileSize = (bytes?: number | null): string => {
    if (bytes == null) return '—';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const handleCopyHash = (hash: string, e: React.MouseEvent) => {
    const isLive = e.altKey || e.metaKey;
    copyIndicator(hash, { live: isLive });
  };

  if (!attachments || attachments.length === 0) {
    return (
      <div className={`p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-3 ${className}`}>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gray-500/10 text-[var(--text-tertiary)] flex items-center justify-center shrink-0">
            <Paperclip className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-black text-[var(--text-primary)]">
              Email Attachments (0)
            </h3>
            <p className="text-xs text-[var(--text-secondary)]">
              No file attachments or binaries were extracted from this email sample.
            </p>
          </div>
        </div>
      </div>
    );
  }

  const suspiciousCount = attachments.filter((a) => a.is_suspicious).length;

  return (
    <div className={`p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-5 ${className}`}>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center shrink-0">
            <Paperclip className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-black text-[var(--text-primary)] flex items-center gap-2">
              <span>Extracted Attachments</span>
              <Badge variant="neutral" size="xs">{attachments.length} Total</Badge>
            </h3>
            <p className="text-xs text-[var(--text-secondary)]">
              Stream-hashed in-memory. Zero execution, zero payload persistence to disk.
            </p>
          </div>
        </div>

        {suspiciousCount > 0 ? (
          <Badge variant="critical" size="sm" className="flex items-center gap-1.5">
            <AlertOctagon className="w-3.5 h-3.5" />
            <span>{suspiciousCount} Dangerous Payload File(s)</span>
          </Badge>
        ) : (
          <Badge variant="low" size="sm" className="flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Non-Executable Format Types</span>
          </Badge>
        )}
      </div>

      {/* Attachments Cards List */}
      <div className="space-y-3">
        {attachments.map((att, i) => (
          <div
            key={i}
            className={`p-4 rounded-xl border transition-all ${att.is_suspicious
              ? 'border-red-500/40 bg-red-500/5'
              : 'border-[var(--border-subtle)] bg-[var(--bg-inset)]'
              }`}
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              {/* File details */}
              <div className="flex items-start gap-3 min-w-0">
                <div
                  className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${att.is_suspicious
                    ? 'bg-red-500/20 text-red-400'
                    : 'bg-[var(--bg-panel)] border border-[var(--border-subtle)] text-blue-400'
                    }`}
                >
                  {att.is_suspicious ? <AlertOctagon className="w-5 h-5" /> : <FileText className="w-5 h-5" />}
                </div>

                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-bold text-[var(--text-primary)] font-mono break-all">
                      <DefangText value={att.filename} showCopy />
                    </span>
                    {att.is_suspicious && (
                      <Badge variant="critical" size="xs">Suspicious Extension</Badge>
                    )}
                  </div>

                  <div className="text-[11px] text-[var(--text-secondary)] font-mono mt-0.5">
                    {formatFileSize(att.size_bytes)} · {att.mime_type}
                  </div>
                </div>
              </div>

              {/* Action badge */}
              <div className="shrink-0 flex items-center gap-2">
                <Badge variant={att.is_suspicious ? 'critical' : 'neutral'} size="xs">
                  {att.is_suspicious ? 'HIGH RISK' : 'INSPECTED'}
                </Badge>
              </div>
            </div>

            {/* In-Memory SHA-256 Digest */}
            <div className="mt-3 pt-3 border-t border-[var(--border-subtle)] space-y-1">
              <div className="flex items-center justify-between text-[10px] uppercase font-mono text-[var(--text-tertiary)]">
                <span className="flex items-center gap-1">
                  <Hash className="w-3 h-3 text-purple-400" />
                  <span>In-Memory SHA-256 Digest</span>
                </span>
                <span className="text-[9px] text-[var(--text-secondary)]">Alt+click to copy un-defanged hash</span>
              </div>

              <div className="p-2 rounded-lg bg-[var(--bg-panel)] border border-[var(--border-subtle)] flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-blue-400 break-all select-all">
                  <DefangText value={att.sha256} />
                </span>
                <CopyButton
                  value={att.sha256}
                  onCopy={(e) => handleCopyHash(att.sha256, e)}
                  tooltip="Copy SHA-256 (Alt+click for live)"
                  size="xs"
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
