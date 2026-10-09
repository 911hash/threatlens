import React, { useState, useEffect, useRef } from 'react';
import {
  FileCode,
  FileText,
  ShieldCheck,
  Eye,
  EyeOff,
  Lock,
} from 'lucide-react';
import { SegmentedControl } from '../primitives/SegmentedControl';
import { Badge } from '../primitives/Badge';
import { useTheme } from '../../design/ThemeContext';

export interface SanitizedBodyViewerProps {
  sanitizedHtml?: string;
  plainBody?: string;
  className?: string;
}

export const SanitizedBodyViewer: React.FC<SanitizedBodyViewerProps> = ({
  sanitizedHtml,
  plainBody,
  className = '',
}) => {
  const { mode } = useTheme();
  const [activeView, setActiveView] = useState<'html' | 'plain'>('html');
  const iframeRef = useRef<HTMLIFrameElement>(null);

  // If only one view is available, default to it
  useEffect(() => {
    if (!sanitizedHtml && plainBody) {
      setActiveView('plain');
    } else if (sanitizedHtml && !plainBody) {
      setActiveView('html');
    }
  }, [sanitizedHtml, plainBody]);

  // Construct iframe document with safe styling adapted to app theme
  const srcDoc = React.useMemo(() => {
    if (!sanitizedHtml) return '';

    const isDark = mode === 'dark';
    const bg = isDark ? '#0f172a' : '#ffffff';
    const text = isDark ? '#e2e8f0' : '#1e293b';
    const link = isDark ? '#60a5fa' : '#2563eb';
    const border = isDark ? '#334155' : '#e2e8f0';

    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body {
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
              font-size: 13px;
              line-height: 1.6;
              color: ${text};
              background-color: ${bg};
              margin: 16px;
              word-wrap: break-word;
            }
            a { color: ${link}; text-decoration: underline; pointer-events: none; }
            table { border-collapse: collapse; max-width: 100%; margin: 8px 0; }
            th, td { border: 1px solid ${border}; padding: 6px 10px; }
            img { display: none !important; }
            blockquote { border-left: 3px solid ${border}; margin: 8px 0; padding-left: 12px; color: #94a3b8; }
            pre, code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
          </style>
        </head>
        <body>
          ${sanitizedHtml}
        </body>
      </html>
    `;
  }, [sanitizedHtml, mode]);

  if (!sanitizedHtml && !plainBody) {
    return (
      <div className={`p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] text-center text-xs text-[var(--text-tertiary)] ${className}`}>
        No plain text or HTML body was found in this email message.
      </div>
    );
  }

  return (
    <div className={`p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-4 ${className}`}>
      {/* Header and View Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-500/10 text-indigo-400 flex items-center justify-center shrink-0">
            <FileCode className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-black text-[var(--text-primary)] flex items-center gap-2">
              <span>Sanitized Message Body</span>
              <Badge variant="low" size="xs">Sandboxed</Badge>
            </h3>
            <p className="text-xs text-[var(--text-secondary)]">
              Isolated sandboxed render. Active scripts, external CSS, remote images, and tracking pixels neutralized.
            </p>
          </div>
        </div>

        {/* View Switcher */}
        {sanitizedHtml && plainBody && (
          <div className="flex justify-end">
            <SegmentedControl<'html' | 'plain'>
              options={[
                { value: 'html', label: 'Sanitized HTML', icon: <Eye className="w-3.5 h-3.5" /> },
                { value: 'plain', label: 'Plain Text', icon: <FileText className="w-3.5 h-3.5" /> },
              ]}
              value={activeView}
              onChange={setActiveView}
              size="sm"
            />
          </div>
        )}
      </div>

      {/* Security Privacy Notice */}
      <div className="p-3 rounded-xl border border-blue-500/20 bg-blue-500/5 text-xs text-[var(--text-secondary)] flex items-start gap-2.5">
        <Lock className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <span className="font-semibold text-[var(--text-primary)]">Anti-Tracking Guarantee: </span>
          Remote images and tracking web beacons were automatically stripped from the markup. Opening this report does not alert the sender or transmit read-receipt telemetry.
        </div>
      </div>

      {/* Content Container */}
      <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] overflow-hidden">
        {activeView === 'html' && sanitizedHtml ? (
          <div className="relative w-full h-[400px]">
            <iframe
              ref={iframeRef}
              title="Sanitized Email Body"
              srcDoc={srcDoc}
              sandbox=""
              className="w-full h-full border-0 rounded-xl bg-[var(--bg-panel)]"
            />
          </div>
        ) : (
          <div className="p-4 max-h-[400px] overflow-y-auto font-mono text-xs text-[var(--text-primary)] whitespace-pre-wrap leading-relaxed select-text">
            {plainBody || 'No plain text alternative available.'}
          </div>
        )}
      </div>
    </div>
  );
};
