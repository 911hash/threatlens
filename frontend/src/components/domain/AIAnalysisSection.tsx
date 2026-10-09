import React, { useState } from 'react';
import {
  Sparkles,
  ShieldCheck,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Cpu,
  Clock,
  Database,
  Eye,
  EyeOff,
  Copy,
  Check,
} from 'lucide-react';
import type { LLMResult } from '../../types/threat';

export interface AIAnalysisSectionProps {
  llmResult?: LLMResult | null;
  anonymizedPrompt?: string | null;
  error?: string | null;
  className?: string;
}

export const AIAnalysisSection: React.FC<AIAnalysisSectionProps> = ({
  llmResult,
  anonymizedPrompt,
  error,
  className = '',
}) => {
  const [showAnonymized, setShowAnonymized] = useState(false);
  const [showTechnical, setShowTechnical] = useState(false);
  const [copied, setCopied] = useState(false);

  const PROVIDER_DISPLAY_NAMES: Record<string, string> = {
    cloudflare: 'Cloudflare Workers AI',
    mistral: 'Mistral',
    groq: 'Groq',
  };

  const providerName = llmResult?.provider_used
    ? (PROVIDER_DISPLAY_NAMES[llmResult.provider_used.toLowerCase()] ||
       llmResult.provider_used.charAt(0).toUpperCase() + llmResult.provider_used.slice(1))
    : 'AI';

  const handleCopyPrompt = () => {
    if (anonymizedPrompt) {
      navigator.clipboard.writeText(anonymizedPrompt);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // If AI errored or failed
  if (error || (!llmResult && !error)) {
    return (
      <div className={`p-4 rounded-xl border border-red-500/30 bg-red-500/5 text-left ${className}`}>
        <div className="flex items-center gap-2.5 text-red-400 font-semibold text-sm mb-1.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-500" />
          <span>AI reasoning unavailable — see raw evidence</span>
        </div>
        <p className="text-xs text-[var(--text-secondary)]">
          The threat reasoning model could not be reached. Rely on raw authentication and transport signals below.
        </p>
      </div>
    );
  }

  return (
    <section
      aria-label="AI Forensic Analysis"
      className={`p-5 rounded-2xl border border-amber-500/20 bg-gradient-to-b from-amber-500/[0.04] to-transparent shadow-xs text-left relative overflow-hidden ${className}`}
    >
      {/* Decorative ambient aura */}
      <div className="absolute top-0 right-0 w-48 h-48 bg-amber-500/5 rounded-full blur-2xl pointer-events-none" />

      {/* 1. Privacy Banner */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 mb-4 rounded-xl bg-[var(--bg-panel)]/90 border border-[var(--border-subtle)] text-xs text-[var(--text-secondary)]">
        <div className="flex items-center gap-2 min-w-0">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          <span className="truncate">Body anonymized before AI call.</span>
        </div>

        {anonymizedPrompt && (
          <button
            type="button"
            onClick={() => setShowAnonymized(!showAnonymized)}
            className="inline-flex items-center gap-1 font-semibold text-amber-400 hover:text-amber-300 transition-colors text-xs cursor-pointer focus:outline-none"
          >
            {showAnonymized ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            <span>[{showAnonymized ? 'Hide' : 'View what was sent'}]</span>
          </button>
        )}
      </div>

      {/* Anonymized Prompt Inspection Drawer */}
      {showAnonymized && anonymizedPrompt && (
        <div className="mb-4 p-3.5 rounded-xl bg-[var(--bg-inset)] border border-[var(--border-muted)] text-xs text-[var(--text-secondary)]">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-[var(--border-subtle)]">
            <span className="font-mono text-[11px] font-semibold text-[var(--text-primary)]">
              Outbound Anonymized Prompt Payload
            </span>
            <button
              type="button"
              onClick={handleCopyPrompt}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[var(--bg-panel)] hover:bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-[11px] text-[var(--text-secondary)] transition-colors"
            >
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <pre className="font-mono text-[11px] leading-relaxed whitespace-pre-wrap max-h-48 overflow-y-auto text-[var(--text-muted)] select-all">
            {anonymizedPrompt}
          </pre>
        </div>
      )}

      {/* 2. Header with Provider Name */}
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2 text-sm font-bold text-[var(--text-primary)]">
          <span className="p-1 rounded-lg bg-amber-500/10 text-amber-400">
            <Sparkles className="w-4 h-4" />
          </span>
          <h3>AI Analysis ({providerName})</h3>
        </div>

        {/* Technical toggle button */}
        <button
          type="button"
          onClick={() => setShowTechnical(!showTechnical)}
          className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] transition-colors"
        >
          <span>Metadata</span>
          {showTechnical ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {/* 3. Summary Paragraph */}
      <p className="text-sm text-[var(--text-primary)] leading-relaxed font-normal mb-3">
        {llmResult?.summary || 'No summary available.'}
      </p>

      {/* 4. Collapsible Technical Details */}
      {showTechnical && llmResult && (
        <div className="mt-3 pt-3 border-t border-[var(--border-subtle)]/70 flex flex-wrap items-center gap-4 text-xs text-[var(--text-secondary)]">
          <div className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-amber-400" />
            <span>Provider: <strong>{llmResult.provider_used}</strong></span>
          </div>

          <div className="flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-sky-400" />
            <span>Latency: <strong>{llmResult.latency_ms ?? 0} ms</strong></span>
          </div>

          <div className="flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-emerald-400" />
            <span>Cache: <strong>{llmResult.cache_hit ? 'HIT (0ms)' : 'MISS (fresh)'}</strong></span>
          </div>
        </div>
      )}
    </section>
  );
};
