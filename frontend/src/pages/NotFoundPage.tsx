import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Home, Search } from 'lucide-react';
import { Button } from '../components/primitives/Button';
import { Kbd } from '../components/primitives/Kbd';
import { useCommandPalette } from '../context/CommandPaletteContext';

export const NotFoundPage: React.FC = () => {
  const navigate = useNavigate();
  const palette = useCommandPalette();
  const isMac = typeof navigator !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform);

  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] px-4 text-center animate-in fade-in duration-200">
      <div className="w-16 h-16 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mb-6 shadow-lg shadow-blue-500/5">
        <ShieldAlert className="w-8 h-8 text-blue-400" />
      </div>

      <span className="font-mono text-xs font-semibold uppercase tracking-widest text-blue-400 mb-2">
        404 — Route Not Located
      </span>

      <h1 className="text-3xl sm:text-4xl font-extrabold text-[var(--text-primary)] tracking-tight mb-3">
        Page not found
      </h1>

      <p className="text-sm text-[var(--text-secondary)] max-w-md mx-auto mb-8 leading-relaxed">
        The requested indicator, route, or resource does not exist in the threat navigation map.
      </p>

      <div className="flex flex-wrap items-center justify-center gap-3 mb-8">
        <Button
          variant="primary"
          leftIcon={<Home className="w-4 h-4" />}
          onClick={() => navigate('/')}
        >
          Go Home
        </Button>

        <Button
          variant="secondary"
          leftIcon={<Search className="w-4 h-4" />}
          onClick={() => palette.open()}
        >
          Search Actions
        </Button>
      </div>

      <div className="inline-flex items-center gap-2 p-2 px-3 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-xs text-[var(--text-tertiary)] font-mono">
        <span>Quick navigation:</span>
        <Kbd>{isMac ? '⌘K' : 'Ctrl+K'}</Kbd>
        <span>opens the Command Palette</span>
      </div>
    </div>
  );
};
