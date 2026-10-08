import React, { useState, useMemo } from 'react';
import { ChevronDown, ChevronUp, Code, Copy, Check, Search } from 'lucide-react';
import { useToast } from './primitives/Toast';

export interface RawJsonViewerProps {
  data: any;
  title?: string;
  defaultOpen?: boolean;
}

export const RawJsonViewer: React.FC<RawJsonViewerProps> = ({
  data,
  title = 'Raw Telemetry JSON',
  defaultOpen = false,
}) => {
  const toast = useToast();
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState(false);

  const formattedJson = useMemo(() => {
    try {
      return JSON.stringify(data, null, 2);
    } catch {
      return String(data);
    }
  }, [data]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(formattedJson);
      setCopied(true);
      toast.success('Raw JSON copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error('Failed to copy JSON');
    }
  };

  // Filter lines if searchQuery is non-empty
  const displayLines = useMemo(() => {
    const lines = formattedJson.split('\n');
    if (!searchQuery.trim()) return lines;
    const q = searchQuery.toLowerCase();
    return lines.filter((l) => l.toLowerCase().includes(q));
  }, [formattedJson, searchQuery]);

  return (
    <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] overflow-hidden">
      {/* Accordion Header */}
      <div className="p-3.5 flex items-center justify-between bg-[var(--bg-inset)] border-b border-[var(--border-subtle)]">
        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          aria-expanded={isOpen}
          className="flex items-center gap-2 text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] hover:text-blue-400 transition-colors cursor-pointer"
        >
          {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          <Code className="w-4 h-4 text-blue-400" />
          <span>{title}</span>
        </button>

        <div className="flex items-center gap-2">
          {isOpen && (
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-tertiary)]" />
              <input
                type="text"
                aria-label="Search JSON payload"
                placeholder="Search JSON..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-7 pl-8 pr-2.5 rounded-md bg-[var(--bg-base)] border border-[var(--border-subtle)] text-xs text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-1 focus:ring-blue-500 w-36 sm:w-48"
              />
            </div>
          )}

          <button
            type="button"
            onClick={handleCopy}
            aria-label="Copy JSON to clipboard"
            className="flex items-center gap-1.5 h-7 px-2.5 rounded-md bg-[var(--bg-base)] hover:bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-xs font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Content */}
      {isOpen && (
        <div className="p-4 bg-[var(--bg-visual)]">
          <pre className="font-mono text-[11px] leading-relaxed text-[var(--text-secondary)] overflow-x-auto max-h-96 overflow-y-auto">
            {searchQuery.trim() && displayLines.length === 0 ? (
              <span className="text-[var(--text-tertiary)] italic">
                No JSON lines match "{searchQuery}"
              </span>
            ) : (
              displayLines.map((line, idx) => (
                <div key={idx} className="hover:bg-[var(--bg-inset)]/50 px-1 rounded">
                  {line}
                </div>
              ))
            )}
          </pre>
        </div>
      )}
    </div>
  );
};
