import React from 'react';
import { Kbd } from './Kbd';

export interface KeyHintProps {
  keys: string[];
  size?: 'xs' | 'sm';
  className?: string;
}

export const KeyHint: React.FC<KeyHintProps> = ({ keys, size = 'xs', className = '' }) => {
  return (
    <div className={`inline-flex items-center gap-1 ${className}`}>
      {keys.map((k, idx) => (
        <React.Fragment key={idx}>
          <Kbd size={size}>{k}</Kbd>
          {idx < keys.length - 1 && (
            <span className="text-[10px] text-[var(--text-tertiary)]">+</span>
          )}
        </React.Fragment>
      ))}
    </div>
  );
};
