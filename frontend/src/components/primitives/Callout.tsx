import React from 'react';
import { AlertTriangle, CheckCircle, Info, ShieldAlert, Sparkles, X } from 'lucide-react';

export type CalloutVariant = 'info' | 'warning' | 'danger' | 'success' | 'demo';

export interface CalloutProps {
  variant?: CalloutVariant;
  title?: React.ReactNode;
  children: React.ReactNode;
  icon?: React.ReactNode;
  onDismiss?: () => void;
  className?: string;
}

export const Callout: React.FC<CalloutProps> = ({
  variant = 'info',
  title,
  children,
  icon,
  onDismiss,
  className = '',
}) => {
  const variantConfig: Record<
    CalloutVariant,
    { icon: React.ReactNode; border: string; bg: string; text: string; titleColor: string }
  > = {
    info: {
      icon: <Info className="w-4 h-4 text-sky-500 shrink-0" />,
      border: 'border-sky-500/30',
      bg: 'bg-sky-500/5',
      text: 'text-[var(--text-secondary)]',
      titleColor: 'text-sky-500',
    },
    warning: {
      icon: <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />,
      border: 'border-amber-500/30',
      bg: 'bg-amber-500/5',
      text: 'text-[var(--text-secondary)]',
      titleColor: 'text-amber-500',
    },
    danger: {
      icon: <ShieldAlert className="w-4 h-4 text-red-500 shrink-0" />,
      border: 'border-red-500/30',
      bg: 'bg-red-500/5',
      text: 'text-[var(--text-secondary)]',
      titleColor: 'text-red-500',
    },
    success: {
      icon: <CheckCircle className="w-4 h-4 text-emerald-500 shrink-0" />,
      border: 'border-emerald-500/30',
      bg: 'bg-emerald-500/5',
      text: 'text-[var(--text-secondary)]',
      titleColor: 'text-emerald-500',
    },
    demo: {
      icon: <Sparkles className="w-4 h-4 text-purple-500 shrink-0" />,
      border: 'border-purple-500/30',
      bg: 'bg-purple-500/5',
      text: 'text-[var(--text-secondary)]',
      titleColor: 'text-purple-500',
    },
  };

  const config = variantConfig[variant];

  return (
    <div
      role="region"
      className={`relative flex items-start gap-3 p-3.5 rounded-lg border text-xs leading-relaxed ${
        config.bg
      } ${config.border} ${config.text} ${className}`}
    >
      <div className="mt-0.5">{icon || config.icon}</div>
      <div className="flex-1 flex flex-col gap-0.5">
        {title && (
          <h4 className={`font-semibold ${config.titleColor} leading-tight`}>{title}</h4>
        )}
        <div className="text-[var(--text-secondary)]">{children}</div>
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)] p-0.5 rounded -mr-1 -mt-1"
          aria-label="Dismiss callout"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  );
};
