import React, { useState, useEffect, useRef, useMemo, useId } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  Globe,
  Hash,
  UploadCloud,
  Eye,
  EyeOff,
  Sun,
  Moon,
  Sparkles,
  RotateCcw,
  GitCompare,
  LayoutDashboard,
  Clock,
  Bookmark,
  Bell,
  Sliders,
  Layers,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';
import { useCommandPalette } from '../../context/CommandPaletteContext';
import { useTheme } from '../../design/ThemeContext';
import { useDefang } from '../../design/DefangContext';
import { useToast } from '../primitives/Toast';
import { useThreatQuery } from '../../hooks/useThreatQuery';
import { api } from '../../api/client';
import { Modal } from '../primitives/Modal';
import { Kbd } from '../primitives/Kbd';

interface PaletteItem {
  id: string;
  group: 'actions' | 'navigate' | 'recent' | 'watchlist' | 'comparisons';
  label: string;
  sublabel?: string;
  icon: React.ReactNode;
  onSelect: () => void;
}

function matchesFuzzy(text: string, search: string): boolean {
  const t = text.toLowerCase();
  const s = search.toLowerCase().trim();
  if (!s) return true;
  if (t.includes(s)) return true;
  let searchIdx = 0;
  for (let i = 0; i < t.length && searchIdx < s.length; i++) {
    if (t[i] === s[searchIdx]) {
      searchIdx++;
    }
  }
  return searchIdx === s.length;
}

export const CommandPalette: React.FC = () => {
  const { isOpen, close } = useCommandPalette();
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();
  const { isDefanged, toggleDefanged } = useDefang();
  const toast = useToast();

  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const searchId = useId();

  // 250ms debounce for query
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(query);
      setSelectedIndex(0);
    }, 250);
    return () => clearTimeout(timer);
  }, [query]);

  // Reset query and focus input when palette opens
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setDebouncedQuery('');
      setSelectedIndex(0);
      const timer = setTimeout(() => {
        inputRef.current?.focus();
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  // Load recent scans and watchlist via useThreatQuery
  const { data: scans } = useThreatQuery('palette-scans', () => api.getScans('all', 10), {
    enabled: isOpen,
    staleMs: 30000,
  });

  const { data: watchlist } = useThreatQuery('palette-watchlist', () => api.getWatchlist(), {
    enabled: isOpen,
    staleMs: 30000,
  });

  // Build items catalogue
  const allItems: PaletteItem[] = useMemo(() => {
    const items: PaletteItem[] = [];

    // Group 1: Actions (verbs)
    items.push(
      {
        id: 'act-scan-url',
        group: 'actions',
        label: 'Scan URL',
        sublabel: 'Analyze a suspicious link or web host',
        icon: <Globe className="w-4 h-4 text-blue-400" />,
        onSelect: () => navigate('/analyze/url'),
      },
      {
        id: 'act-scan-hash',
        group: 'actions',
        label: 'Scan Hash',
        sublabel: 'Query SHA256 / MD5 reputation',
        icon: <Hash className="w-4 h-4 text-purple-400" />,
        onSelect: () => navigate('/analyze/hash'),
      },
      {
        id: 'act-scan-file',
        group: 'actions',
        label: 'Scan File',
        sublabel: 'Upload payload for sandbox detonation',
        icon: <UploadCloud className="w-4 h-4 text-emerald-400" />,
        onSelect: () => navigate('/analyze/file'),
      },
      {
        id: 'act-toggle-defang',
        group: 'actions',
        label: isDefanged ? 'Disable URL Defanging' : 'Enable URL Defanging',
        sublabel: 'Toggle hxxp:// safe display mode',
        icon: isDefanged ? <Eye className="w-4 h-4 text-amber-400" /> : <EyeOff className="w-4 h-4 text-amber-400" />,
        onSelect: () => {
          toggleDefanged();
          toast.info(isDefanged ? 'URL defanging disabled' : 'URL defanging enabled', 'Defang Preference');
        },
      },
      {
        id: 'act-toggle-theme',
        group: 'actions',
        label: theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme',
        sublabel: 'Change surface contrast mode',
        icon: theme === 'dark' ? <Sun className="w-4 h-4 text-yellow-400" /> : <Moon className="w-4 h-4 text-slate-400" />,
        onSelect: () => {
          toggleTheme();
          toast.info(`Theme set to ${theme === 'dark' ? 'light' : 'dark'} mode`);
        },
      },
      {
        id: 'act-seed-demo',
        group: 'actions',
        label: 'Seed Demo Data',
        sublabel: 'Load 5-day threat evolution dataset',
        icon: <Sparkles className="w-4 h-4 text-blue-400" />,
        onSelect: async () => {
          try {
            await api.seedDemo();
            toast.success('Simulated demo threat seeded successfully');
            navigate('/scans');
          } catch {
            toast.error('Failed to seed demo data');
          }
        },
      },
      {
        id: 'act-reset-demo',
        group: 'actions',
        label: 'Reset Demo Data',
        sublabel: 'Wipe and restore pristine baseline state',
        icon: <RotateCcw className="w-4 h-4 text-slate-400" />,
        onSelect: async () => {
          try {
            await api.resetDemo();
            toast.success('Demo environment restored to baseline');
            window.location.reload();
          } catch {
            toast.error('Failed to reset demo data');
          }
        },
      },
      {
        id: 'act-compare-last',
        group: 'actions',
        label: 'Compare Last Two Scans',
        sublabel: 'Side-by-side threat evolution comparison',
        icon: <GitCompare className="w-4 h-4 text-indigo-400" />,
        onSelect: () => navigate('/compare'),
      }
    );

    // Group 2: Navigate
    items.push(
      {
        id: 'nav-overview',
        group: 'navigate',
        label: 'Navigate to Overview',
        sublabel: 'Dashboard stats and charts',
        icon: <LayoutDashboard className="w-4 h-4 text-blue-400" />,
        onSelect: () => navigate('/'),
      },
      {
        id: 'nav-analyze',
        group: 'navigate',
        label: 'Navigate to Analyze',
        sublabel: 'Multi-source intel query interface',
        icon: <Search className="w-4 h-4 text-blue-400" />,
        onSelect: () => navigate('/analyze'),
      },
      {
        id: 'nav-investigations',
        group: 'navigate',
        label: 'Navigate to Investigations',
        sublabel: 'Scan history and archive',
        icon: <Clock className="w-4 h-4 text-blue-400" />,
        onSelect: () => navigate('/scans'),
      },
      {
        id: 'nav-watchlist',
        group: 'navigate',
        label: 'Navigate to Watchlist',
        sublabel: 'Monitored targets and alerts',
        icon: <Bookmark className="w-4 h-4 text-blue-400" />,
        onSelect: () => navigate('/watchlist'),
      },
      {
        id: 'nav-alerts',
        group: 'navigate',
        label: 'Navigate to Alerts',
        sublabel: 'Real-time threat notification log',
        icon: <Bell className="w-4 h-4 text-blue-400" />,
        onSelect: () => navigate('/alerts'),
      },
      {
        id: 'nav-settings',
        group: 'navigate',
        label: 'Navigate to Settings',
        sublabel: 'Engine credentials and scoring config',
        icon: <Sliders className="w-4 h-4 text-blue-400" />,
        onSelect: () => navigate('/settings'),
      },
      {
        id: 'nav-design-system',
        group: 'navigate',
        label: 'Navigate to Design System',
        sublabel: 'Primitive catalog and audit',
        icon: <Layers className="w-4 h-4 text-blue-400" />,
        onSelect: () => navigate('/design-system'),
      }
    );

    // Group 3: Recent Scans (last 10)
    if (scans && scans.length > 0) {
      scans.forEach(s => {
        items.push({
          id: `scan-${s.id}`,
          group: 'recent',
          label: s.target,
          sublabel: `Scan ${s.id} • ${s.risk_level} (${s.risk_score}/100)`,
          icon: <ShieldAlert className="w-4 h-4 text-slate-400" />,
          onSelect: () => navigate(`/scan/${s.id}`),
        });
      });
    }

    // Group 4: Watchlist
    if (watchlist && watchlist.length > 0) {
      watchlist.forEach(w => {
        items.push({
          id: `watch-${w.id}`,
          group: 'watchlist',
          label: w.target,
          sublabel: `Watchlist item • Type: ${w.target_type}`,
          icon: <Bookmark className="w-4 h-4 text-amber-400" />,
          onSelect: () => navigate('/watchlist'),
        });
      });
    }

    // Group 5: Comparisons (derive pairs of scans for the same target)
    if (scans && scans.length > 1) {
      const byTarget: Record<string, typeof scans> = {};
      scans.forEach(s => {
        if (!byTarget[s.target]) byTarget[s.target] = [];
        byTarget[s.target].push(s);
      });

      Object.entries(byTarget).forEach(([target, targetScans]) => {
        if (targetScans.length >= 2) {
          const s1 = targetScans[0];
          const s2 = targetScans[1];
          items.push({
            id: `comp-${s1.id}-${s2.id}`,
            group: 'comparisons',
            label: `Compare: ${target}`,
            sublabel: `Diff between ${s1.id} and ${s2.id}`,
            icon: <GitCompare className="w-4 h-4 text-indigo-400" />,
            onSelect: () => navigate(`/compare/${s2.id}/${s1.id}`),
          });
        }
      });
    }

    return items;
  }, [isDefanged, theme, scans, watchlist, toggleDefanged, toggleTheme, toast, navigate]);

  // Filter items based on debounced query
  const filteredItems: PaletteItem[] = useMemo(() => {
    if (!debouncedQuery.trim()) {
      // When query is empty: index all 5 groups (Actions, Navigate, Recent, Watchlist, Comparisons)
      const actions = allItems.filter(i => i.group === 'actions');
      const navs = allItems.filter(i => i.group === 'navigate');
      const recents = allItems.filter(i => i.group === 'recent').slice(0, 5);
      const watches = allItems.filter(i => i.group === 'watchlist').slice(0, 5);
      const comps = allItems.filter(i => i.group === 'comparisons').slice(0, 5);
      return [...actions, ...navs, ...recents, ...watches, ...comps];
    }

    return allItems.filter(
      item =>
        matchesFuzzy(item.label, debouncedQuery) ||
        (item.sublabel && matchesFuzzy(item.sublabel, debouncedQuery))
    );
  }, [allItems, debouncedQuery]);

  // Group filtered items in the exact required order:
  // 1. Actions, 2. Navigate, 3. Recent Scans, 4. Watchlist, 5. Comparisons
  const groupedSections = useMemo(() => {
    const groupOrder: Array<{ key: PaletteItem['group']; title: string }> = [
      { key: 'actions', title: 'Actions' },
      { key: 'navigate', title: 'Navigate' },
      { key: 'recent', title: 'Recent Scans' },
      { key: 'watchlist', title: 'Watchlist' },
      { key: 'comparisons', title: 'Comparisons' },
    ];

    const result: Array<{ title: string; items: PaletteItem[] }> = [];
    groupOrder.forEach(g => {
      const itemsInGroup = filteredItems.filter(i => i.group === g.key);
      if (itemsInGroup.length > 0) {
        result.push({ title: g.title, items: itemsInGroup });
      }
    });

    return result;
  }, [filteredItems]);

  // Flattened visible items for index-based keyboard selection
  const flatVisibleItems = useMemo(() => {
    return groupedSections.flatMap(sec => sec.items);
  }, [groupedSections]);

  // Handle keyboard navigation inside palette
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (flatVisibleItems.length === 0) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => (prev + 1) % flatVisibleItems.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => (prev - 1 + flatVisibleItems.length) % flatVisibleItems.length);
    } else if (e.key === 'Home') {
      e.preventDefault();
      setSelectedIndex(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      setSelectedIndex(flatVisibleItems.length - 1);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const current = flatVisibleItems[selectedIndex];
      if (current) {
        current.onSelect();
        close();
      }
    }
  };

  // Scroll active item into view
  useEffect(() => {
    if (!listRef.current) return;
    const activeEl = listRef.current.querySelector<HTMLElement>('[aria-selected="true"]');
    if (activeEl) {
      activeEl.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex]);

  return (
    <Modal isOpen={isOpen} onClose={close} size="lg" className="p-0 overflow-hidden">
      <div className="flex flex-col bg-[var(--bg-elevated)]" onKeyDown={handleKeyDown}>
        {/* Search Input Bar */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[var(--border-subtle)] bg-[var(--bg-panel)]">
          <Search className="w-4 h-4 text-[var(--text-tertiary)] shrink-0" />
          <input
            id={searchId}
            ref={inputRef}
            type="text"
            role="combobox"
            aria-label="Search commands, indicators, or actions"
            aria-expanded="true"
            aria-autocomplete="list"
            aria-controls="command-palette-results"
            placeholder="Type a command, route, or target..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            className="flex-1 bg-transparent text-sm text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] focus:outline-none"
          />
          {query ? (
            <button
              type="button"
              onClick={() => {
                setQuery('');
                inputRef.current?.focus();
              }}
              className="text-xs text-[var(--text-tertiary)] hover:text-[var(--text-primary)] px-1 rounded"
            >
              Clear
            </button>
          ) : (
            <Kbd>ESC</Kbd>
          )}
        </div>

        {/* Live region for accessibility count announcement */}
        <div className="sr-only" aria-live="polite" aria-atomic="true">
          {flatVisibleItems.length} results available
        </div>

        {/* Results List */}
        <div
          id="command-palette-results"
          ref={listRef}
          role="listbox"
          className="max-h-[380px] overflow-y-auto p-2 divide-y divide-[var(--border-subtle)]/40"
        >
          {flatVisibleItems.length === 0 ? (
            <div className="p-8 text-center space-y-2">
              <Search className="w-8 h-8 text-[var(--text-tertiary)] mx-auto opacity-50" />
              <p className="text-xs text-[var(--text-secondary)] font-medium">
                No results for &ldquo;{debouncedQuery}&rdquo;
              </p>
              <p className="text-[11px] text-[var(--text-tertiary)]">
                Try searching for a URL, scan hash, or quick command like &quot;Scan&quot; or &quot;Theme&quot;.
              </p>
            </div>
          ) : (
            groupedSections.map(sec => {
              return (
                <div key={sec.title} className="py-1.5 first:pt-0 last:pb-0">
                  {/* Overline Group Header: 11px uppercase text-tertiary */}
                  <div className="px-2.5 py-1 text-[11px] font-mono font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">
                    {sec.title}
                  </div>

                  <div className="space-y-0.5 mt-0.5">
                    {sec.items.map(item => {
                      const itemIdx = flatVisibleItems.indexOf(item);
                      const isSelected = itemIdx === selectedIndex;

                      return (
                        <div
                          key={item.id}
                          role="option"
                          aria-selected={isSelected}
                          onMouseEnter={() => setSelectedIndex(itemIdx)}
                          onClick={() => {
                            item.onSelect();
                            close();
                          }}
                          className={`flex items-center justify-between gap-3 px-3 py-2 rounded-lg text-xs cursor-pointer select-none transition-colors ${
                            isSelected
                              ? 'bg-blue-500/15 text-[var(--text-primary)] border border-blue-500/30 font-medium'
                              : 'text-[var(--text-secondary)] hover:bg-[var(--bg-panel)] border border-transparent'
                          }`}
                        >
                          <div className="flex items-center gap-2.5 min-w-0">
                            <span className="shrink-0">{item.icon}</span>
                            <div className="flex flex-col truncate">
                              <span className="truncate font-medium text-[var(--text-primary)]">
                                {item.label}
                              </span>
                              {item.sublabel && (
                                <span className="text-[11px] text-[var(--text-tertiary)] truncate">
                                  {item.sublabel}
                                </span>
                              )}
                            </div>
                          </div>

                          {isSelected && (
                            <div className="flex items-center gap-1 text-[10px] text-blue-500 font-mono shrink-0">
                              <span>Select</span>
                              <ArrowRight className="w-3 h-3" />
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Palette Footer Hints */}
        <div className="flex items-center justify-between px-3 py-2 border-t border-[var(--border-subtle)] bg-[var(--bg-inset)]/60 text-[11px] text-[var(--text-tertiary)] font-mono">
          <div className="flex items-center gap-2">
            <span>Navigate:</span>
            <Kbd>↑</Kbd>
            <Kbd>↓</Kbd>
          </div>
          <div className="flex items-center gap-2">
            <span>Select:</span>
            <Kbd>↵</Kbd>
            <span>Close:</span>
            <Kbd>ESC</Kbd>
          </div>
        </div>
      </div>
    </Modal>
  );
};
