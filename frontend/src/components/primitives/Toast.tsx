import React, { createContext, useContext, useState, useCallback } from 'react';
import { AlertTriangle, CheckCircle, Info, XCircle, X } from 'lucide-react';

export type ToastVariant = 'info' | 'success' | 'warning' | 'error';

export interface ToastItem {
  id: string;
  type: ToastVariant;
  title?: string;
  message: string;
  duration?: number;
}

export interface ToastOptions {
  variant?: ToastVariant;
  type?: ToastVariant;
  title?: string;
  message: string;
  duration?: number;
}

interface ToastContextType {
  toasts: ToastItem[];
  addToast: (toast: Omit<ToastItem, 'id'>) => string;
  toast: (options: ToastOptions) => string;
  dismissToast: (id: string) => void;
  info: (message: string, title?: string) => void;
  success: (message: string, title?: string) => void;
  warning: (message: string, title?: string) => void;
  error: (message: string, title?: string) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const addToast = useCallback(
    ({ type, title, message, duration = 4000 }: Omit<ToastItem, 'id'>) => {
      const id = Math.random().toString(36).substring(2, 9);
      const newToast: ToastItem = { id, type, title, message, duration };

      setToasts(prev => [...prev, newToast]);

      if (duration > 0) {
        setTimeout(() => {
          dismissToast(id);
        }, duration);
      }

      return id;
    },
    [dismissToast]
  );

  const toast = useCallback(
    (options: ToastOptions) => {
      const variantType = options.variant || options.type || 'info';
      return addToast({
        type: variantType,
        title: options.title,
        message: options.message,
        duration: options.duration,
      });
    },
    [addToast]
  );

  const info = useCallback((message: string, title?: string) => addToast({ type: 'info', title, message }), [addToast]);
  const success = useCallback((message: string, title?: string) => addToast({ type: 'success', title, message }), [addToast]);
  const warning = useCallback((message: string, title?: string) => addToast({ type: 'warning', title, message }), [addToast]);
  const error = useCallback((message: string, title?: string) => addToast({ type: 'error', title, message }), [addToast]);

  return (
    <ToastContext.Provider value={{ toasts, addToast, toast, dismissToast, info, success, warning, error }}>
      {children}
      {/* Toast viewport */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none px-4 sm:px-0">
        {toasts.map(t => {
          const typeConfig: Record<
            ToastVariant,
            { icon: React.ReactNode; border: string; bg: string; text: string }
          > = {
            info: {
              icon: <Info className="w-4 h-4 text-blue-500 shrink-0" />,
              border: 'border-blue-500/30',
              bg: 'bg-[var(--bg-elevated)]',
              text: 'text-[var(--text-primary)]',
            },
            success: {
              icon: <CheckCircle className="w-4 h-4 text-emerald-500 shrink-0" />,
              border: 'border-emerald-500/30',
              bg: 'bg-[var(--bg-elevated)]',
              text: 'text-[var(--text-primary)]',
            },
            warning: {
              icon: <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />,
              border: 'border-amber-500/40',
              bg: 'bg-[var(--bg-elevated)]',
              text: 'text-[var(--text-primary)]',
            },
            error: {
              icon: <XCircle className="w-4 h-4 text-red-500 shrink-0" />,
              border: 'border-red-500/40',
              bg: 'bg-[var(--bg-elevated)]',
              text: 'text-[var(--text-primary)]',
            },
          };

          const config = typeConfig[t.type];
          const isError = t.type === 'error';
          const ariaRole = isError ? 'alert' : 'status';
          const ariaLive = isError ? 'assertive' : 'polite';

          return (
            <div
              key={t.id}
              role={ariaRole}
              aria-live={ariaLive}
              aria-atomic="true"
              className={`pointer-events-auto flex items-start gap-3 p-3 rounded-lg border shadow-lg animate-in slide-in-from-bottom-2 duration-150 ${config.bg} ${config.border} ${config.text}`}
            >
              <div className="mt-0.5">{config.icon}</div>
              <div className="flex-1 flex flex-col gap-0.5 pr-2">
                {t.title && <span className="text-xs font-semibold">{t.title}</span>}
                <span className="text-xs text-[var(--text-secondary)] leading-relaxed">{t.message}</span>
              </div>
              <button
                onClick={() => dismissToast(t.id)}
                className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)] p-0.5 rounded"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
};

export function useToast(): ToastContextType {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}
