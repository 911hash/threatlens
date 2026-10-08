import React from 'react';

export interface SkipLinkProps {
  targetId?: string;
  label?: string;
  className?: string;
}

export const SkipLink: React.FC<SkipLinkProps> = ({
  targetId = 'main-content',
  label = 'Skip to main content',
  className = '',
}) => {
  return (
    <a
      href={`#${targetId}`}
      className={`sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:px-4 focus:py-2 focus:rounded-md focus:bg-blue-600 focus:text-white focus:font-semibold focus:shadow-xl focus:outline-none focus:ring-2 focus:ring-white ${className}`}
    >
      {label}
    </a>
  );
};
