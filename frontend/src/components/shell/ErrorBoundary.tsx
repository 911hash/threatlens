import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RefreshCw, Copy, Check } from 'lucide-react';
import { Button } from '../primitives/Button';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  copied: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
    copied: false,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null, copied: false };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    if (import.meta.env.DEV) {
      console.error('Uncaught error in component tree:', error, errorInfo);
    }
    this.setState({ errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  private handleCopy = () => {
    const text = `${this.state.error?.toString()}\n\nStack:\n${this.state.errorInfo?.componentStack || ''}`;
    navigator.clipboard.writeText(text);
    this.setState({ copied: true });
    setTimeout(() => this.setState({ copied: false }), 2000);
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="min-h-[400px] flex items-center justify-center p-6 bg-[var(--bg-base)]">
          <div className="max-w-lg w-full rounded-xl border border-red-500/30 bg-[var(--bg-elevated)] p-6 shadow-2xl text-left">
            <div className="flex items-center gap-3 mb-4 text-red-500">
              <AlertOctagon className="w-6 h-6 shrink-0" />
              <h2 className="text-base font-semibold text-[var(--text-primary)]">
                Application Error Encountered
              </h2>
            </div>

            <p className="text-xs text-[var(--text-secondary)] mb-4 leading-relaxed">
              ThreatLens encountered an unexpected error while rendering this view. You can try recovering the view or reloading the page.
            </p>

            {this.state.error && (
              <div className="mb-4 p-3 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)] font-mono text-[11px] text-red-400 overflow-x-auto max-h-36">
                {this.state.error.toString()}
              </div>
            )}

            <div className="flex items-center justify-between gap-3 pt-2 border-t border-[var(--border-subtle)]">
              <Button
                variant="tertiary"
                size="xs"
                leftIcon={this.state.copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                onClick={this.handleCopy}
              >
                {this.state.copied ? 'Copied' : 'Copy details'}
              </Button>

              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  size="xs"
                  onClick={() => window.location.reload()}
                >
                  Reload Page
                </Button>
                <Button
                  variant="primary"
                  size="xs"
                  leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
                  onClick={this.handleReset}
                >
                  Try Again
                </Button>
              </div>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
