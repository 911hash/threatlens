import React, { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { Tooltip } from './Tooltip';

export interface CopyButtonProps {
  value: string;
  onCopy?: (e: React.MouseEvent) => void | Promise<void>;
  size?: 'xs' | 'sm';
  tooltip?: string;
  className?: string;
}

export const CopyButton: React.FC<CopyButtonProps> = ({
  value,
  onCopy,
  size = 'xs',
  tooltip = 'Copy to clipboard',
  className = '',
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();

    if (onCopy) {
      await onCopy(e);
    } else {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(value);
      }
    }

    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isXs = size === 'xs';

  const button = (
    <button
      type="button"
      onClick={handleCopy}
      aria-label="Copy to clipboard"
      className={`inline-flex items-center justify-center rounded transition-colors text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-panel)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-blue-500 ${
        isXs ? 'w-5 h-5' : 'w-6 h-6'
      } ${className}`}
    >
      {copied ? (
        <Check className={`${isXs ? 'w-3 h-3' : 'w-3.5 h-3.5'} text-emerald-500`} />
      ) : (
        <Copy className={`${isXs ? 'w-3 h-3' : 'w-3.5 h-3.5'}`} />
      )}
    </button>
  );

  return tooltip ? (
    <Tooltip content={copied ? 'Copied' : tooltip}>
      {button}
    </Tooltip>
  ) : (
    button
  );
};
