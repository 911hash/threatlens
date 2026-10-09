import React from 'react';
import { Mail, ShieldCheck, Lock, ExternalLink, Sparkles } from 'lucide-react';
import { Button } from '../primitives/Button';

export const GmailConnectCard: React.FC = () => {
  const handleConnect = () => {
    const apiBase = import.meta.env.VITE_API_BASE_URL || '';
    window.location.href = `${apiBase}/api/auth/gmail/start`;
  };

  return (
    <div className="max-w-xl mx-auto my-12 p-8 rounded-2xl bg-[var(--bg-surface)] border border-[var(--border-subtle)] shadow-xl relative overflow-hidden text-center">
      {/* Decorative ambient gradient backdrop */}
      <div className="absolute -top-24 -left-24 w-64 h-64 bg-red-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-24 -right-24 w-64 h-64 bg-amber-500/10 rounded-full blur-3xl pointer-events-none" />

      {/* Gmail Icon Badge */}
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-tr from-red-600/20 to-amber-500/20 border border-red-500/30 text-red-500 mb-6 shadow-inner">
        <Mail className="w-8 h-8" />
      </div>

      <h2 className="text-2xl font-bold tracking-tight text-[var(--text-primary)] mb-3">
        Connect Your Gmail Inbox
      </h2>

      <p className="text-base text-[var(--text-secondary)] leading-relaxed mb-6 max-w-md mx-auto">
        ThreatLens reads your inbox to detect phishing, spoofing, and infrastructure threats in real-time.
      </p>

      {/* Security Scope Banner */}
      <div className="flex items-center justify-center gap-2 p-3 mb-8 rounded-xl bg-[var(--bg-panel)] border border-[var(--border-subtle)] text-xs text-[var(--text-muted)] max-w-md mx-auto">
        <Lock className="w-4 h-4 text-emerald-500 shrink-0" />
        <span>
          <strong>ThreatLens reads your inbox.</strong> It cannot send, delete, or modify email. Read-only access.
        </span>
      </div>

      {/* Connect Button */}
      <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
        <Button
          variant="primary"
          size="lg"
          onClick={handleConnect}
          className="w-full sm:w-auto px-8 py-3 bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white font-medium rounded-xl shadow-lg shadow-red-600/25 transition-all flex items-center justify-center gap-2"
        >
          <Mail className="w-4 h-4" />
          <span>Connect Gmail</span>
          <ExternalLink className="w-3.5 h-3.5 opacity-80" />
        </Button>
      </div>

      <div className="mt-6 flex items-center justify-center gap-4 text-xs text-[var(--text-muted)]">
        <span className="flex items-center gap-1">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" /> AES-256 Token Encryption
        </span>
        <span>•</span>
        <span className="flex items-center gap-1">
          <Sparkles className="w-3.5 h-3.5 text-amber-500" /> Automated AI Forensic Analysis
        </span>
      </div>
    </div>
  );
};
