import React from 'react';
import { useDefang } from '../../design/DefangContext';
import { CopyButton } from '../primitives/CopyButton';

export interface DefangTextProps {
  value: string;
  showCopy?: boolean;
  mono?: boolean;
  className?: string;
  truncate?: boolean;
}

export const DefangText: React.FC<DefangTextProps> = ({
  value,
  showCopy = false,
  mono = true,
  className = '',
  truncate = false,
}) => {
  const { formatIndicator, copyIndicator } = useDefang();
  const formatted = formatIndicator(value);

  const handleCopy = (e: React.MouseEvent) => {
    const isLive = e.altKey || e.metaKey;
    copyIndicator(value, { live: isLive });
  };

  return (
    <span className={`inline-flex items-center gap-1.5 ${mono ? 'font-mono' : ''} ${className}`}>
      <span className={truncate ? 'truncate' : ''} title={value}>
        {formatted}
      </span>
      {showCopy && (
        <CopyButton
          value={value}
          onCopy={handleCopy}
          tooltip="Copy (Alt+click for live)"
          size="xs"
        />
      )}
    </span>
  );
};
