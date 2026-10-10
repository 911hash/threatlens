import React from 'react';
import { Globe, Hash, FileText, Server, Mail } from 'lucide-react';
import { useDefang } from '../../design/DefangContext';
import { useDrawer } from '../../context/DrawerContext';
import { CopyButton } from '../primitives/CopyButton';
import { Badge } from '../primitives/Badge';
import { PivotPanel } from './PivotPanel';

export interface IndicatorChipProps {
  indicator?: string;
  target?: string;
  type?: 'url' | 'hash' | 'file' | 'ip' | 'email' | string;
  source?: string;
  size?: 'xs' | 'sm';
  showCopy?: boolean;
  className?: string;
  onClick?: (e: React.MouseEvent) => void;
}

export const IndicatorChip: React.FC<IndicatorChipProps> = ({
  indicator,
  target,
  type = 'url',
  source,
  size = 'sm',
  showCopy = true,
  className = '',
  onClick,
}) => {
  const { formatIndicator, copyIndicator } = useDefang();
  const drawer = useDrawer();

  const rawVal = indicator || target || '';
  const formatted = formatIndicator(rawVal);

  const typeIcon = {
    url: <Globe className="w-3 h-3 text-blue-400" />,
    hash: <Hash className="w-3 h-3 text-purple-400" />,
    file: <FileText className="w-3 h-3 text-amber-400" />,
    ip: <Server className="w-3 h-3 text-emerald-400" />,
    email: <Mail className="w-3 h-3 text-emerald-400" />,
  }[type.toLowerCase()] || <Globe className="w-3 h-3 text-blue-400" />;

  const isXs = size === 'xs';

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    const isLive = e.altKey || e.metaKey;
    copyIndicator(rawVal, { live: isLive });
  };

  const handleChipClick = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('button')) {
      return;
    }
    if (onClick) {
      onClick(e);
      return;
    }
    drawer.open(
      <PivotPanel indicator={rawVal} type={type} />,
      { title: `Indicator Pivot: ${formatted}` }
    );
  };

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={handleChipClick}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleChipClick(e as any);
        }
      }}
      className={`inline-flex items-center gap-1.5 rounded-md border border-[var(--border-subtle)] bg-[var(--bg-inset)] font-mono text-[var(--text-primary)] cursor-pointer hover:border-blue-500/40 hover:bg-[var(--bg-panel)] transition-colors select-none ${
        isXs ? 'px-1.5 py-0.5 text-[11px]' : 'px-2 py-1 text-xs'
      } ${className}`}
    >
      <span className="shrink-0 flex items-center">{typeIcon}</span>
      <span className="truncate max-w-[280px]" title={rawVal}>
        {formatted}
      </span>

      {type && (
        <Badge variant="neutral" size="xs" className="text-[9px] px-1 py-0 uppercase">
          {type}
        </Badge>
      )}

      {source && (
        <span className="text-[10px] text-[var(--text-tertiary)] font-sans">
          [{source}]
        </span>
      )}

      {showCopy && (
        <CopyButton
          value={rawVal}
          onCopy={handleCopy}
          tooltip="Copy (Alt+click for live)"
          size="xs"
        />
      )}
    </div>
  );
};

