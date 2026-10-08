import React from 'react';
import { Globe, Hash, FileText, Server } from 'lucide-react';
import { useDefang } from '../../design/DefangContext';
import { CopyButton } from '../primitives/CopyButton';
import { Badge } from '../primitives/Badge';

export interface IndicatorChipProps {
  indicator: string;
  type?: 'url' | 'hash' | 'file' | 'ip' | string;
  source?: string;
  size?: 'xs' | 'sm';
  showCopy?: boolean;
  className?: string;
}

export const IndicatorChip: React.FC<IndicatorChipProps> = ({
  indicator,
  type = 'url',
  source,
  size = 'sm',
  showCopy = true,
  className = '',
}) => {
  const { formatIndicator, copyIndicator } = useDefang();
  const formatted = formatIndicator(indicator);

  const typeIcon = {
    url: <Globe className="w-3 h-3 text-blue-400" />,
    hash: <Hash className="w-3 h-3 text-purple-400" />,
    file: <FileText className="w-3 h-3 text-amber-400" />,
    ip: <Server className="w-3 h-3 text-emerald-400" />,
  }[type.toLowerCase()] || <Globe className="w-3 h-3 text-blue-400" />;

  const isXs = size === 'xs';

  const handleCopy = (e: React.MouseEvent) => {
    const isLive = e.altKey || e.metaKey;
    copyIndicator(indicator, { live: isLive });
  };

  return (
    <div
      className={`inline-flex items-center gap-1.5 rounded-md border border-[var(--border-subtle)] bg-[var(--bg-inset)] font-mono text-[var(--text-primary)] ${
        isXs ? 'px-1.5 py-0.5 text-[11px]' : 'px-2 py-1 text-xs'
      } ${className}`}
    >
      <span className="shrink-0 flex items-center">{typeIcon}</span>
      <span className="truncate max-w-[280px]" title={indicator}>
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
          value={indicator}
          onCopy={handleCopy}
          tooltip="Copy (Alt+click for live)"
          size="xs"
        />
      )}
    </div>
  );
};
