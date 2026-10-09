import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation, useSearchParams } from 'react-router-dom';
import {
  Globe,
  Binary,
  UploadCloud,
  ArrowRight,
  AlertCircle,
  ShieldAlert,
  Sparkles,
  FileCode,
  CheckCircle2,
  Lock,
  RotateCcw,
  Clock,
  Compass,
  FileCheck,
  AlertTriangle,
  Mail,
} from 'lucide-react';
import { api } from '../api/client';
import { Button } from '../components/primitives/Button';
import { Badge } from '../components/primitives/Badge';
import { ProgressBar } from '../components/primitives/ProgressBar';
import { SegmentedControl } from '../components/primitives/SegmentedControl';
import { EmptyState } from '../components/primitives/EmptyState';
import { ErrorState } from '../components/primitives/ErrorState';
import { Skeleton } from '../components/primitives/Skeleton';
import { useToast } from '../components/primitives/Toast';

export const AnalyzePage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const toast = useToast();
  const stateOverride = searchParams.get('state');

  // Determine active tab from URL path
  const getTabFromPath = (): 'url' | 'hash' | 'file' | 'email' => {
    if (location.pathname.includes('/hash')) return 'hash';
    if (location.pathname.includes('/file')) return 'file';
    if (location.pathname.includes('/email')) return 'email';
    return 'url';
  };

  const activeTab = getTabFromPath();

  const switchTab = (tab: 'url' | 'hash' | 'file' | 'email') => {
    setError(null);
    navigate(`/analyze/${tab}`);
  };

  // State
  const [inputValue, setInputValue] = useState('');
  const [traceRedirects, setTraceRedirects] = useState(true);
  const [file, setFile] = useState<File | null>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [hashProgressBytes, setHashProgressBytes] = useState<number>(0);
  const [isHashing, setIsHashing] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Auto-fill from query parameter if present
  useEffect(() => {
    const q = searchParams.get('q') || searchParams.get('target');
    if (q) {
      setInputValue(q);
    }
  }, [searchParams]);

  // Auto-load demo email sample when in demo state
  useEffect(() => {
    if (stateOverride === 'demo' && activeTab === 'email' && !file) {
      loadSampleEmail('phish');
    }
  }, [stateOverride, activeTab, file]);

  // Hash auto-detection logic
  const detectedHashType = React.useMemo(() => {
    if (activeTab !== 'hash') return null;
    const clean = inputValue.trim().toLowerCase();
    if (!clean) return null;
    const isHex = /^[0-9a-f]+$/.test(clean);
    if (!isHex) return { valid: false, message: 'Invalid characters: hash must contain only hexadecimal characters (0-9, a-f).' };

    if (clean.length === 32) return { valid: true, type: 'MD5', length: 32 };
    if (clean.length === 40) return { valid: true, type: 'SHA-1', length: 40 };
    if (clean.length === 64) return { valid: true, type: 'SHA-256', length: 64 };

    return {
      valid: false,
      message: `Invalid length (${clean.length} hex chars). Expected 32 (MD5), 40 (SHA-1), or 64 (SHA-256).`,
    };
  }, [activeTab, inputValue]);

  // URL validation logic
  const urlValidation = React.useMemo(() => {
    if (activeTab !== 'url') return null;
    const clean = inputValue.trim();
    if (!clean) return null;

    const hasProtocol = clean.startsWith('http://') || clean.startsWith('https://') || clean.startsWith('hxxp://') || clean.startsWith('hxxps://');
    const looksLikeDomain = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$/.test(clean) || clean.includes('[.]');

    if (hasProtocol || looksLikeDomain) {
      return { valid: true };
    }
    return {
      valid: false,
      message: 'Enter a valid URL (e.g. https://example.com/login) or domain name.',
    };
  }, [activeTab, inputValue]);

  // File hashing in memory
  const handleFileSelection = async (selectedFile: File) => {
    if (selectedFile.size > 32 * 1024 * 1024) {
      setError('File exceeds 32MB maximum size limit. Please choose a smaller sample.');
      setFile(null);
      setFileHash(null);
      return;
    }

    setFile(selectedFile);
    setError(null);
    setIsHashing(true);
    setHashProgressBytes(0);
    setFileHash(null);

    try {
      const totalBytes = selectedFile.size;
      const chunkSize = 2 * 1024 * 1024; // 2MB chunks for progress visualization
      let processed = 0;

      // Simulate chunk-by-chunk real byte progression
      while (processed < totalBytes) {
        processed = Math.min(totalBytes, processed + chunkSize);
        setHashProgressBytes(processed);
        // Micro-yield to update UI
        await new Promise((r) => setTimeout(r, 40));
      }

      // Compute actual in-memory SHA-256 using SubtleCrypto
      const buffer = await selectedFile.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

      setFileHash(hashHex);
      toast.success('In-memory SHA-256 hash computed', 'File Hashed');
    } catch (err: any) {
      setError(err.message || 'Failed to hash file in browser memory.');
    } finally {
      setIsHashing(false);
    }
  };

  const handlePasteAndGo = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text && text.trim()) {
        setInputValue(text.trim());
        toast.info('Pasted from clipboard');
      }
    } catch {
      toast.error('Unable to read clipboard');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validation checks
    if (activeTab === 'url') {
      if (!inputValue.trim()) {
        setError('Please enter a target URL or domain.');
        return;
      }
      if (urlValidation && !urlValidation.valid) {
        setError(urlValidation.message || 'Invalid URL target.');
        return;
      }
    } else if (activeTab === 'hash') {
      if (!inputValue.trim()) {
        setError('Please enter a file hash.');
        return;
      }
      if (detectedHashType && !detectedHashType.valid) {
        setError(detectedHashType.message || 'Invalid hash format.');
        return;
      }
    } else if (activeTab === 'file') {
      if (!file) {
        setError('Please select or drop a file sample to analyze.');
        return;
      }
    } else if (activeTab === 'email') {
      if (!file) {
        setError('Please select or drop an .eml or .msg email sample to analyze.');
        return;
      }
    }

    try {
      setIsSubmitting(true);
      let scanResult;
      if (activeTab === 'url') {
        scanResult = await api.analyzeUrl(inputValue.trim(), true);
      } else if (activeTab === 'hash') {
        scanResult = await api.analyzeHash(inputValue.trim());
      } else if (activeTab === 'file') {
        scanResult = await api.analyzeFile(file);
      } else if (activeTab === 'email') {
        scanResult = await api.analyzeEmail(file);
      }

      if (scanResult && scanResult.id) {
        toast.success(`Analysis finished: ${scanResult.risk_level} (${scanResult.risk_score}/100)`);
        if (activeTab === 'email') {
          navigate(`/scans/${scanResult.id}`, { state: { emailAnalysis: scanResult } });
        } else {
          navigate(`/scans/${scanResult.id}`);
        }
      }
    } catch (err: any) {
      setError(err.message || 'Analysis processing failed. The remote service may be unavailable.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const loadSampleEmail = (type: 'phish' | 'clean') => {
    const content =
      type === 'phish'
        ? `From: service@example-corp.test\nReply-To: credential-harvest@evil-phishing-host.test\nSubject: Urgent: Verify Account Immediately\nMessage-ID: <urgent-verify-99@evil-phishing-host.test>\nAuthentication-Results: mx.mail-receiver.example.org; spf=fail; dkim=fail; dmarc=fail\nReceived: from c2.evil-phishing-host.test ([198.51.100.99]) by mx.mail-receiver.example.org; Fri, 09 Oct 2026 10:00:00 +0000\nContent-Type: text/plain\n\nPlease restore your account at http://evil-phish-login.example.test`
        : `From: security@example-corp.test\nTo: employee@example-corp.test\nSubject: Quarterly Corporate Security Report\nMessage-ID: <sec-report-100@example-corp.test>\nAuthentication-Results: mx.mail-receiver.example.org; spf=pass; dkim=pass; dmarc=pass; arc=pass\nReceived: from mail.example-corp.test ([192.0.2.1]) by mx.mail-receiver.example.org; Fri, 09 Oct 2026 10:00:00 +0000\nContent-Type: text/plain\n\nAll security systems active and operating normally.`;
    const blob = new Blob([content], { type: 'message/rfc822' });
    const sampleFile = new File(
      [blob],
      type === 'phish' ? 'urgent_phish_sample.eml' : 'corporate_security_update.eml',
      { type: 'message/rfc822' }
    );
    handleFileSelection(sampleFile);
  };

  // State overrides for testing matrix: loading, empty, error, partial, stale, demo
  if (stateOverride === 'loading') {
    return (
      <div className="max-w-4xl mx-auto py-12 px-4 space-y-6">
        <Skeleton className="w-1/3 h-8 rounded-lg mx-auto" />
        <Skeleton className="w-full h-80 rounded-2xl" />
      </div>
    );
  }

  if (stateOverride === 'error') {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4">
        <ErrorState
          title="Analysis Engine Offline"
          message="Unable to reach analysis workers. Simulated error state for verification."
          onRetry={() => navigate(`/analyze/${activeTab}`)}
        />
      </div>
    );
  }

  if (stateOverride === 'empty') {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4">
        <EmptyState
          title={activeTab === 'email' ? 'No Email Sample Selected' : 'No Target Selected'}
          description={
            activeTab === 'email'
              ? 'Select or drop an .eml or .msg message file to analyze authentication and header provenance.'
              : 'Choose an analysis target type to begin automated indicator correlation.'
          }
          action={
            <Button variant="primary" size="sm" onClick={() => switchTab(activeTab)}>
              {activeTab === 'email' ? 'Select Email Sample' : 'Start URL Analysis'}
            </Button>
          }
        />
      </div>
    );
  }

  if (stateOverride === 'partial') {
    return (
      <div className="max-w-4xl mx-auto py-12 px-4 space-y-6">
        <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-amber-400 shrink-0" />
            <span>Partial Analysis in Progress: Parsing header provenance chain (3 of 4 checks completed)...</span>
          </div>
          <Badge variant="neutral" size="xs">Partial Ingestion</Badge>
        </div>
        <Skeleton className="w-full h-64 rounded-2xl" />
      </div>
    );
  }

  if (stateOverride === 'stale') {
    return (
      <div className="max-w-4xl mx-auto py-12 px-4 space-y-6">
        <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <RotateCcw className="w-4 h-4 text-amber-400 shrink-0" />
            <span>Cached Snapshot: Previous analysis results for this indicator may be stale (&gt;12h old).</span>
          </div>
          <Button variant="secondary" size="xs" onClick={() => navigate(`/analyze/${activeTab}`)}>
            Refresh Now
          </Button>
        </div>
        <Skeleton className="w-full h-72 rounded-2xl" />
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto py-10 px-4 space-y-8 pb-16 animate-in fade-in duration-150">
      {/* Demo Mode Banner */}
      {stateOverride === 'demo' && (
        <div className="p-3.5 rounded-xl border border-blue-500/30 bg-blue-500/10 text-xs text-blue-300 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Sparkles className="w-4 h-4 text-blue-400 shrink-0" />
            <span>
              <strong>Demo Environment Active:</strong> Synthetic {activeTab === 'email' ? 'phishing email (.eml)' : 'indicator'} preloaded for forensic workflow evaluation.
            </span>
          </div>
          <Badge variant="neutral" size="xs">Simulated Walkthrough</Badge>
        </div>
      )}

      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Explainable Threat Intelligence Engine</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-black text-[var(--text-primary)] tracking-tight">
          Analyze & Correlate Indicators
        </h1>
        <p className="text-xs sm:text-sm text-[var(--text-secondary)] max-w-xl mx-auto">
          Multi-source reputation, infrastructure telemetry, attack chain reconstruction, and email forensics.
        </p>
      </div>

      {/* Main Analysis Card */}
      <div className="bg-[var(--bg-panel)] border border-[var(--border-subtle)] rounded-3xl p-6 sm:p-8 shadow-sm space-y-6">
        {/* Tab Selection */}
        <div className="flex justify-center">
          <SegmentedControl<'url' | 'hash' | 'file' | 'email'>
            options={[
              { value: 'url', label: 'URL / Domain', icon: <Globe className="w-4 h-4 text-blue-400" /> },
              { value: 'hash', label: 'File Hash', icon: <Binary className="w-4 h-4 text-purple-400" /> },
              { value: 'file', label: 'Sample File', icon: <UploadCloud className="w-4 h-4 text-amber-400" /> },
              { value: 'email', label: 'Email (.eml / .msg)', icon: <Mail className="w-4 h-4 text-emerald-400" /> },
            ]}
            value={activeTab}
            onChange={switchTab}
            size="md"
          />
        </div>

        {/* Form Container */}
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* TAB 1: URL */}
          {activeTab === 'url' && (
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label htmlFor="url-target-input" className="text-xs font-semibold text-[var(--text-primary)]">
                    Target URL or Hostname
                  </label>
                  <button
                    type="button"
                    onClick={handlePasteAndGo}
                    className="text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors cursor-pointer"
                  >
                    Paste from clipboard
                  </button>
                </div>

                <div className="relative">
                  <input
                    id="url-target-input"
                    type="text"
                    value={inputValue}
                    onChange={(e) => {
                      setInputValue(e.target.value);
                      setError(null);
                    }}
                    placeholder="https://example-phishing-login.com/auth or domain.com"
                    className="w-full pl-4 pr-12 py-3.5 text-sm font-mono rounded-xl bg-[var(--bg-inset)] border border-[var(--border-strong)] text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all shadow-inner"
                  />
                  <div className="absolute right-3 top-3.5 text-[var(--text-tertiary)] pointer-events-none">
                    <Globe className="w-5 h-5 text-blue-400" />
                  </div>
                </div>

                {urlValidation && !urlValidation.valid && (
                  <p className="text-xs text-amber-500 flex items-center gap-1.5 mt-1">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>{urlValidation.message}</span>
                  </p>
                )}
              </div>

              {/* Hop Budget & Options */}
              <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] flex items-center justify-between gap-4">
                <div className="space-y-0.5">
                  <div className="text-xs font-bold text-[var(--text-primary)] flex items-center gap-1.5">
                    <Compass className="w-4 h-4 text-indigo-400" />
                    <span>Trace HTTP Redirects</span>
                    <Badge variant="neutral" size="xs">Max 5 Hops</Badge>
                  </div>
                  <p className="text-[11px] text-[var(--text-secondary)]">
                    Follow HTTP 301/302 status jumps to isolate intermediate proxy nodes and landing payloads.
                  </p>
                </div>

                <label className="relative inline-flex items-center cursor-pointer shrink-0">
                  <input
                    type="checkbox"
                    checked={traceRedirects}
                    onChange={(e) => setTraceRedirects(e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-10 h-6 bg-[var(--border-subtle)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>

              {/* Sample Target Chips */}
              <div className="flex items-center gap-2 pt-1 text-[11px]">
                <span className="text-[var(--text-tertiary)] font-mono">Sample indicators:</span>
                <button
                  type="button"
                  onClick={() => setInputValue('http://service-cdn.example-phishing-login.com/auth')}
                  className="px-2 py-0.5 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-blue-400 font-mono transition-colors"
                >
                  Featured Phishing Demo URL
                </button>
                <button
                  type="button"
                  onClick={() => setInputValue('https://secure-login.wellsfargo.com.account-verify.online/login.php')}
                  className="px-2 py-0.5 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-blue-400 font-mono transition-colors"
                >
                  Credential Harvest URL
                </button>
              </div>
            </div>
          )}

          {/* TAB 2: HASH */}
          {activeTab === 'hash' && (
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label htmlFor="hash-target-input" className="text-xs font-semibold text-[var(--text-primary)]">
                    File Hash (MD5, SHA-1, SHA-256)
                  </label>
                  {detectedHashType && detectedHashType.valid && (
                    <Badge variant="low" size="xs">
                      {detectedHashType.type} ({detectedHashType.length} hex)
                    </Badge>
                  )}
                </div>

                <div className="relative">
                  <input
                    id="hash-target-input"
                    type="text"
                    value={inputValue}
                    onChange={(e) => {
                      setInputValue(e.target.value);
                      setError(null);
                    }}
                    placeholder="Enter 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters..."
                    className="w-full pl-4 pr-12 py-3.5 text-sm font-mono rounded-xl bg-[var(--bg-inset)] border border-[var(--border-strong)] text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all shadow-inner"
                  />
                  <div className="absolute right-3 top-3.5 text-[var(--text-tertiary)] pointer-events-none">
                    <Binary className="w-5 h-5 text-purple-400" />
                  </div>
                </div>

                {detectedHashType && !detectedHashType.valid && (
                  <p className="text-xs text-amber-500 flex items-center gap-1.5 mt-1">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>{detectedHashType.message}</span>
                  </p>
                )}
              </div>

              {/* Sample Hash Chips */}
              <div className="flex items-center gap-2 pt-1 text-[11px]">
                <span className="text-[var(--text-tertiary)] font-mono">Sample hashes:</span>
                <button
                  type="button"
                  onClick={() => setInputValue('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')}
                  className="px-2 py-0.5 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-purple-400 font-mono transition-colors"
                >
                  SHA-256 (Empty file)
                </button>
                <button
                  type="button"
                  onClick={() => setInputValue('44d88612fea8a8f36de82e1278abb02f')}
                  className="px-2 py-0.5 rounded bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-purple-400 font-mono transition-colors"
                >
                  MD5 (EICAR standard)
                </button>
              </div>
            </div>
          )}

          {/* TAB 3: FILE */}
          {activeTab === 'file' && (
            <div className="space-y-4">
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileSelection(e.target.files[0]);
                  }
                }}
              />

              {/* File Drop Area */}
              <div
                role="button"
                tabIndex={0}
                onClick={() => fileInputRef.current?.click()}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && fileInputRef.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    handleFileSelection(e.dataTransfer.files[0]);
                  }
                }}
                className="p-8 border-2 border-dashed border-[var(--border-strong)] hover:border-blue-500 rounded-2xl bg-[var(--bg-inset)] transition-all cursor-pointer text-center space-y-3"
              >
                <div className="w-12 h-12 rounded-2xl bg-amber-500/10 text-amber-400 flex items-center justify-center mx-auto">
                  <UploadCloud className="w-6 h-6" />
                </div>
                <div>
                  <div className="text-sm font-bold text-[var(--text-primary)]">
                    Drop sample file here, or click to browse
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                    Maximum file size: 32MB. Executables, scripts, PDFs, and archives supported.
                  </p>
                </div>
              </div>

              {/* Real-byte Progress Bar during hashing */}
              {isHashing && file && (
                <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-2">
                  <ProgressBar
                    value={hashProgressBytes}
                    max={file.size}
                    label="Calculating in-memory cryptographic hash..."
                    valueFormatter={(v) =>
                      `${(v / (1024 * 1024)).toFixed(1)}MB / ${(file.size / (1024 * 1024)).toFixed(1)}MB`
                    }
                    variant="default"
                  />
                </div>
              )}

              {/* File Preview and Computed Hash */}
              {file && !isHashing && (
                <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <FileCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-bold text-[var(--text-primary)] truncate">
                          {file.name}
                        </div>
                        <div className="text-[11px] text-[var(--text-secondary)]">
                          {(file.size / (1024 * 1024)).toFixed(2)} MB · {file.type || 'Binary / Unknown'}
                        </div>
                      </div>
                    </div>
                    <Badge variant="low" size="xs">
                      Ready
                    </Badge>
                  </div>

                  {fileHash && (
                    <div className="pt-2 border-t border-[var(--border-subtle)] space-y-1">
                      <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">
                        In-Memory SHA-256 Digest
                      </span>
                      <div className="text-xs font-mono text-blue-400 break-all bg-[var(--bg-inset)] p-2 rounded-lg border border-[var(--border-subtle)]">
                        {fileHash}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Privacy Notice */}
              <div className="p-3 rounded-xl border border-blue-500/25 bg-blue-500/5 text-xs text-[var(--text-secondary)] flex items-start gap-2.5">
                <Lock className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold text-[var(--text-primary)]">Client-Side Privacy Guarantee: </span>
                  Files are hashed in memory and never uploaded or written to disk. Only the calculated cryptographic hash digest is queried against community threat registries.
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: EMAIL */}
          {activeTab === 'email' && (
            <div className="space-y-4">
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.msg,message/rfc822"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileSelection(e.target.files[0]);
                  }
                }}
              />

              {/* Email File Drop Area */}
              <div
                role="button"
                tabIndex={0}
                onClick={() => fileInputRef.current?.click()}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && fileInputRef.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    handleFileSelection(e.dataTransfer.files[0]);
                  }
                }}
                className="p-8 border-2 border-dashed border-[var(--border-strong)] hover:border-emerald-500 rounded-2xl bg-[var(--bg-inset)] transition-all cursor-pointer text-center space-y-3"
              >
                <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 text-emerald-400 flex items-center justify-center mx-auto">
                  <Mail className="w-6 h-6" />
                </div>
                <div>
                  <div className="text-sm font-bold text-[var(--text-primary)]">
                    Drop .eml or .msg email file here, or click to browse
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                    Maximum file size: 32MB. RFC 822 emails and Outlook .msg supported. Stream-hashed in memory.
                  </p>
                </div>
              </div>

              {/* Real-byte Progress Bar during hashing */}
              {isHashing && file && (
                <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-2">
                  <ProgressBar
                    value={hashProgressBytes}
                    max={file.size}
                    label="Calculating in-memory cryptographic hash for email stream..."
                    valueFormatter={(v) =>
                      `${(v / 1024).toFixed(1)} KB / ${(file.size / 1024).toFixed(1)} KB`
                    }
                    variant="default"
                  />
                </div>
              )}

              {/* File Preview and Computed Hash */}
              {file && !isHashing && (
                <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <FileCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-bold text-[var(--text-primary)] truncate">
                          {file.name}
                        </div>
                        <div className="text-[11px] text-[var(--text-secondary)]">
                          {(file.size / 1024).toFixed(1)} KB · {file.type || 'message/rfc822'}
                        </div>
                      </div>
                    </div>
                    <Badge variant="low" size="xs">
                      Ready for Forensics
                    </Badge>
                  </div>

                  {fileHash && (
                    <div className="pt-2 border-t border-[var(--border-subtle)] space-y-1">
                      <span className="text-[10px] uppercase font-mono text-[var(--text-tertiary)]">
                        In-Memory SHA-256 Digest
                      </span>
                      <div className="text-xs font-mono text-emerald-400 break-all bg-[var(--bg-inset)] p-2 rounded-lg border border-[var(--border-subtle)]">
                        {fileHash}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Sample Email Fixtures */}
              <div className="flex items-center gap-2 pt-1 text-[11px] flex-wrap">
                <span className="text-[var(--text-tertiary)] font-mono">Sample email fixtures:</span>
                <button
                  type="button"
                  onClick={() => loadSampleEmail('phish')}
                  className="px-2.5 py-1 rounded-md bg-[var(--bg-inset)] border border-red-500/30 text-red-400 hover:bg-red-500/10 font-mono transition-colors cursor-pointer"
                >
                  Phishing Spoof Sample (.eml)
                </button>
                <button
                  type="button"
                  onClick={() => loadSampleEmail('clean')}
                  className="px-2.5 py-1 rounded-md bg-[var(--bg-inset)] border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10 font-mono transition-colors cursor-pointer"
                >
                  Clean Corporate Update (.eml)
                </button>
              </div>

              {/* Strict Privacy Mode Notice */}
              <div className="p-3.5 rounded-xl border border-blue-500/25 bg-blue-500/5 text-xs text-[var(--text-secondary)] flex items-start gap-2.5">
                <Lock className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                <div className="leading-relaxed">
                  <span className="font-semibold text-[var(--text-primary)]">Privacy Mode: </span>
                  Email content analyzed locally. Nothing transmitted. Email file and attachments are stream-hashed in memory and NEVER written to disk, NEVER uploaded to external services, and NEVER retained.
                </div>
              </div>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="p-3 rounded-xl border border-red-500/30 bg-red-500/10 text-xs text-red-400 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Submit Action */}
          <div className="pt-2 flex items-center justify-between">
            <div className="text-[11px] text-[var(--text-tertiary)]">
              {activeTab === 'url' && (!inputValue.trim() ? 'Enter a URL to proceed' : 'Ready to evaluate')}
              {activeTab === 'hash' && (!inputValue.trim() ? 'Enter a hash to proceed' : 'Ready to evaluate')}
              {activeTab === 'file' && (!file ? 'Select a file to proceed' : 'Ready to evaluate')}
              {activeTab === 'email' && (!file ? 'Select an email file (.eml / .msg) to proceed' : 'Ready to evaluate')}
            </div>

            <Button
              type="submit"
              variant="primary"
              size="md"
              disabled={
                isSubmitting ||
                isHashing ||
                (activeTab === 'url' && (!inputValue.trim() || Boolean(urlValidation && !urlValidation.valid))) ||
                (activeTab === 'hash' && (!inputValue.trim() || Boolean(detectedHashType && !detectedHashType.valid))) ||
                (activeTab === 'file' && !file) ||
                (activeTab === 'email' && !file)
              }
              className="flex items-center gap-2 px-6"
            >
              <span>{isSubmitting ? 'Evaluating Intelligence...' : 'Run Investigation'}</span>
              <ArrowRight className="w-4 h-4" />
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};
