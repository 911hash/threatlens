import React, { useRef } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Search,
  History,
  Bookmark,
  Bell,
  Sliders,
  PanelLeftClose,
  PanelLeftOpen,
  ShieldAlert,
  Layers,
  Sparkles,
  RotateCcw,
  Mail,
  Network,
} from 'lucide-react';
import { useSidebar } from '../../context/SidebarContext';
import { useThreatQuery } from '../../hooks/useThreatQuery';
import { api } from '../../api/client';
import { Badge } from '../primitives/Badge';
import { Tooltip } from '../primitives/Tooltip';

export const Sidebar: React.FC = () => {
  const { collapsed, toggle } = useSidebar();
  const location = useLocation();
  const navigate = useNavigate();
  const navContainerRef = useRef<HTMLElement>(null);

  // Poll alerts for unread badge count
  const { data: alerts, refetch: refetchAlerts } = useThreatQuery(
    'alerts-unread-count',
    () => api.getAlerts(),
    { staleMs: 30000 }
  );
  const unreadAlertsCount = alerts ? alerts.filter(a => !a.seen && !(a as any).is_read).length : 0;

  React.useEffect(() => {
    const handleAlertsUpdated = () => {
      refetchAlerts();
    };
    window.addEventListener('threatlens:alerts-updated', handleAlertsUpdated);
    return () => window.removeEventListener('threatlens:alerts-updated', handleAlertsUpdated);
  }, [refetchAlerts]);

  const navItems = [
    {
      to: '/',
      label: 'Overview',
      icon: LayoutDashboard,
      isActive: ['/', '/dashboard', '/overview'].includes(location.pathname),
    },
    {
      to: '/inbox',
      label: 'Gmail Inbox',
      icon: Mail,
      isActive: location.pathname.startsWith('/inbox'),
    },
    {
      to: '/analyze',
      label: 'Analyze',
      icon: Search,
      isActive: location.pathname.startsWith('/analyze'),
    },
    {
      to: '/scans',
      label: 'Investigations',
      icon: History,
      isActive:
        location.pathname.startsWith('/scans') ||
        location.pathname.startsWith('/history') ||
        location.pathname.startsWith('/investigations'),
    },
    {
      to: '/watchlist',
      label: 'Watchlist',
      icon: Bookmark,
      isActive: location.pathname.startsWith('/watchlist'),
    },
    {
      to: '/forensics',
      label: 'Forensics',
      icon: Network,
      isActive: location.pathname.startsWith('/forensics') || location.pathname.startsWith('/cases'),
    },
    {
      to: '/alerts',
      label: 'Alerts',
      icon: Bell,
      badge: unreadAlertsCount > 0 ? unreadAlertsCount : undefined,
      isActive: location.pathname.startsWith('/alerts'),
    },
    {
      to: '/settings',
      label: 'Settings',
      icon: Sliders,
      isActive: location.pathname.startsWith('/settings'),
    },
  ];

  const handleKeyDown = (e: React.KeyboardEvent, index: number) => {
    const items = navContainerRef.current?.querySelectorAll<HTMLAnchorElement>('a');
    if (!items || items.length === 0) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      const nextIndex = (index + 1) % items.length;
      items[nextIndex]?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const prevIndex = (index - 1 + items.length) % items.length;
      items[prevIndex]?.focus();
    }
  };

  return (
    <aside
      aria-label="Sidebar navigation"
      className={`hidden md:flex flex-col h-screen sticky top-0 z-30 select-none shrink-0 transition-all duration-200 border-r border-[var(--border-subtle)] bg-[var(--bg-panel)] ${
        collapsed ? 'w-[60px]' : 'w-[240px]'
      }`}
    >
      {/* Brand Header */}
      <div className={`flex items-center border-b border-[var(--border-subtle)] py-4 ${collapsed ? 'justify-center px-2' : 'px-4 gap-3'}`}>
        <div
          onClick={() => navigate('/')}
          className="w-8 h-8 rounded-lg bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0 cursor-pointer hover:bg-blue-600/20 transition-colors"
          title="ThreatLens Home"
        >
          <ShieldAlert className="w-4 h-4" />
        </div>

        {!collapsed && (
          <div className="flex flex-col truncate">
            <span className="font-mono font-bold text-sm tracking-wider text-[var(--text-primary)] leading-tight">
              THREAT<span className="text-blue-500">LENS</span>
            </span>
            <span className="text-[10px] text-[var(--text-tertiary)] font-sans">
              Explainable Intel
            </span>
          </div>
        )}
      </div>

      {/* Navigation Links */}
      <nav
        ref={navContainerRef}
        aria-label="Primary"
        className="flex-1 py-4 px-2 space-y-1 overflow-y-auto"
      >
        {navItems.map((item, idx) => {
          const ItemIcon = item.icon;
          const activeClass = item.isActive
            ? 'bg-blue-500/15 text-blue-500 border-blue-500/30 font-semibold shadow-sm'
            : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] border-transparent';

          const linkElement = (
            <NavLink
              to={item.to}
              onKeyDown={e => handleKeyDown(e, idx)}
              aria-current={item.isActive ? 'page' : undefined}
              className={`flex items-center rounded-lg text-xs font-medium border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                collapsed ? 'justify-center w-10 h-10 mx-auto' : 'gap-3 px-3 py-2.5'
              } ${activeClass}`}
            >
              <div className="relative shrink-0 flex items-center justify-center">
                <ItemIcon className="w-4 h-4" />
                {collapsed && item.badge && (
                  <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-red-500 ring-2 ring-[var(--bg-panel)]" />
                )}
              </div>

              {!collapsed && (
                <>
                  <span className="truncate flex-1 text-left">{item.label}</span>
                  {item.badge && (
                    <Badge variant="danger" size="xs">
                      {item.badge}
                    </Badge>
                  )}
                </>
              )}
            </NavLink>
          );

          if (collapsed) {
            return (
              <Tooltip key={item.to} content={item.label} side="right">
                {linkElement}
              </Tooltip>
            );
          }

          return <div key={item.to}>{linkElement}</div>;
        })}
      </nav>

      {/* Dev / Design System shortcut */}
      <div className="p-2 border-t border-[var(--border-subtle)]">
        {collapsed ? (
          <Tooltip content="Design System" side="right">
            <NavLink
              to="/design-system"
              aria-label="Design System catalog"
              className={({ isActive }) =>
                `flex items-center justify-center w-10 h-10 mx-auto rounded-lg text-xs border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                  isActive
                    ? 'bg-blue-500/15 text-blue-500 border-blue-500/30 font-semibold'
                    : 'text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] border-transparent'
                }`
              }
            >
              <Layers className="w-4 h-4" />
            </NavLink>
          </Tooltip>
        ) : (
          <NavLink
            to="/design-system"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                isActive
                  ? 'bg-blue-500/15 text-blue-500 border-blue-500/30 font-semibold'
                  : 'text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] border-transparent'
              }`
            }
          >
            <Layers className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">Design System</span>
          </NavLink>
        )}
      </div>

      {/* Collapse Toggle at Bottom */}
      <div className="p-2 border-t border-[var(--border-subtle)] bg-[var(--bg-inset)]/50">
        <button
          type="button"
          onClick={toggle}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={`flex items-center rounded-lg text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
            collapsed ? 'justify-center w-10 h-10 mx-auto' : 'w-full gap-3 px-3 py-2'
          }`}
        >
          {collapsed ? (
            <PanelLeftOpen className="w-4 h-4 shrink-0" />
          ) : (
            <>
              <PanelLeftClose className="w-4 h-4 shrink-0" />
              <span className="truncate">Collapse Sidebar</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
};
