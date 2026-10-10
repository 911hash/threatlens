import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Briefcase,
  ArrowLeft,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ShieldAlert,
  Send,
  MessageSquare,
  History,
  FileText,
  ExternalLink,
  ChevronRight,
  RotateCcw,
  User,
  Shield,
  Layers,
} from 'lucide-react';
import { api } from '../api/client';
import type { Case, CaseItem, ForensicEvent } from '../types/threat';
import { Button } from '../components/primitives/Button';
import { Badge } from '../components/primitives/Badge';
import { Modal } from '../components/primitives/Modal';
import { Textarea } from '../components/primitives/Textarea';
import { SeverityChip } from '../components/primitives/SeverityChip';
import { Skeleton } from '../components/primitives/Skeleton';
import { ErrorState } from '../components/primitives/ErrorState';
import { EmptyState } from '../components/primitives/EmptyState';
import { useToast } from '../components/primitives/Toast';
import { ForensicTimeline } from '../components/domain/ForensicTimeline';
import { DefangText } from '../components/domain/DefangText';

export function CaseDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const toast = useToast();

  const [caseData, setCaseData] = useState<Case | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Active selected scan for timeline
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [timelineEvents, setTimelineEvents] = useState<ForensicEvent[]>([]);
  const [isLoadingTimeline, setIsLoadingTimeline] = useState<boolean>(false);

  // Right pane tab: 'comments' | 'audit'
  const [activeRightTab, setActiveRightTab] = useState<'comments' | 'audit'>('comments');
  const [newCommentBody, setNewCommentBody] = useState<string>('');
  const [isPostingComment, setIsPostingComment] = useState<boolean>(false);

  // Escalate / Resolve / Reopen Modals
  const [modalAction, setModalAction] = useState<'escalate' | 'resolve' | 'reopen' | null>(null);
  const [actionNote, setActionNote] = useState<string>('');
  const [isSubmittingAction, setIsSubmittingAction] = useState<boolean>(false);

  // 1. Fetch Case Detail
  const fetchCase = async () => {
    if (!id) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getCaseDetail(id);
      setCaseData(data);
      if (data.items && data.items.length > 0 && !selectedScanId) {
        setSelectedScanId(data.items[0].scan_id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load case detail.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchCase();
  }, [id]);

  // 2. Fetch Timeline when selected scan changes
  useEffect(() => {
    if (!selectedScanId) {
      setTimelineEvents([]);
      return;
    }
    let isMounted = true;
    setIsLoadingTimeline(true);

    api.getTimeline(selectedScanId)
      .then((res) => {
        if (isMounted) setTimelineEvents(res.events || []);
      })
      .catch((err) => {
        if (isMounted) {
          toast.error(err.message || 'Failed to retrieve forensic timeline.');
        }
      })
      .finally(() => {
        if (isMounted) setIsLoadingTimeline(false);
      });

    return () => {
      isMounted = false;
    };
  }, [selectedScanId]);

  // 3. Post Comment
  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id || !newCommentBody.trim()) return;

    setIsPostingComment(true);
    try {
      await api.addCaseComment(id, newCommentBody.trim());
      setNewCommentBody('');
      toast.success('Analyst note appended.');
      // Refresh case comments
      const updated = await api.getCaseDetail(id);
      setCaseData(updated);
    } catch (err: any) {
      toast.error(err.message || 'Failed to add comment.');
    } finally {
      setIsPostingComment(false);
    }
  };

  // 4. State Change Action (Escalate, Resolve, Reopen)
  const handleStateChange = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id || !modalAction) return;

    if (!actionNote.trim()) {
      toast.error('An audit note is required for case status transitions.');
      return;
    }

    setIsSubmittingAction(true);
    try {
      if (modalAction === 'escalate') {
        await api.escalateCase(id, actionNote.trim());
        toast.warning('Case status escalated.');
      } else if (modalAction === 'resolve') {
        await api.resolveCase(id, actionNote.trim());
        toast.success('Investigation resolved.');
      } else if (modalAction === 'reopen') {
        await api.reopenCase(id, actionNote.trim());
        toast.info('Case reopened.');
      }

      setModalAction(null);
      setActionNote('');
      const updated = await api.getCaseDetail(id);
      setCaseData(updated);
    } catch (err: any) {
      toast.error(err.message || 'Failed to update case status.');
    } finally {
      setIsSubmittingAction(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6 max-w-7xl mx-auto pb-16">
        <Skeleton className="h-20 w-full rounded-2xl" />
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <Skeleton className="h-96 lg:col-span-4 rounded-2xl" />
          <Skeleton className="h-96 lg:col-span-4 rounded-2xl" />
          <Skeleton className="h-96 lg:col-span-4 rounded-2xl" />
        </div>
      </div>
    );
  }

  if (error || !caseData) {
    return (
      <div className="max-w-4xl mx-auto py-12">
        <ErrorState
          title="Case Not Found"
          message={error || `Investigation case '${id}' could not be located.`}
          onRetry={fetchCase}
        />
      </div>
    );
  }

  const statusStyles = {
    open: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
    escalated: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    resolved: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  }[caseData.status.toLowerCase()] || 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30';

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      {/* Workspace Header */}
      <div className="p-5 md:p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1.5 flex-1 min-w-0">
            <button
              type="button"
              onClick={() => navigate('/forensics')}
              className="text-xs text-[var(--text-tertiary)] hover:text-blue-400 transition-colors flex items-center gap-1 cursor-pointer font-mono"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Cases</span>
            </button>

            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-lg md:text-xl font-bold text-[var(--text-primary)] truncate">
                {caseData.title}
              </h1>
              <span className={`text-[10px] font-mono uppercase px-2.5 py-0.5 rounded-md border font-semibold ${statusStyles}`}>
                {caseData.status}
              </span>
            </div>

            {caseData.description && (
              <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                {caseData.description}
              </p>
            )}

            <div className="flex items-center gap-3 text-[11px] font-mono text-[var(--text-tertiary)] flex-wrap pt-0.5">
              <span>Case ID: {caseData.id}</span>
              <span>·</span>
              <span>
                Created {new Date(caseData.created_at).toLocaleDateString()} at{' '}
                {new Date(caseData.created_at).toLocaleTimeString()}
              </span>
              {caseData.resolved_at && (
                <>
                  <span>·</span>
                  <span className="text-emerald-400">
                    Resolved {new Date(caseData.resolved_at).toLocaleDateString()}
                  </span>
                </>
              )}
            </div>
          </div>

          {/* Action Buttons: Escalate / Resolve */}
          <div className="flex items-center gap-2 shrink-0 self-start sm:self-center">
            {caseData.status !== 'resolved' ? (
              <>
                {caseData.status !== 'escalated' && (
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      setModalAction('escalate');
                      setActionNote('');
                    }}
                    className="flex items-center gap-1.5 text-amber-400 border-amber-500/30 hover:bg-amber-500/10"
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Escalate</span>
                  </Button>
                )}
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => {
                    setModalAction('resolve');
                    setActionNote('');
                  }}
                  className="flex items-center gap-1.5"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Resolve Case</span>
                </Button>
              </>
            ) : (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setModalAction('reopen');
                  setActionNote('');
                }}
                className="flex items-center gap-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reopen Case</span>
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* ───────────────────────────────────────────────────────────── */}
      {/* THREE-PANE LAYOUT at 1280px, STACKED at 320px */}
      {/* ───────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* PANE 1: FORENSIC TIMELINE (Left at 1280px) */}
        <div className="lg:col-span-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] p-4 md:p-5 space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)]">
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-400" />
              <h3 className="text-xs font-bold text-[var(--text-primary)] uppercase tracking-wider">
                Forensic Timeline
              </h3>
            </div>
            {selectedScanId && (
              <Badge variant="outline" size="xs" className="font-mono text-[9px]">
                {timelineEvents.length} Events
              </Badge>
            )}
          </div>

          {selectedScanId ? (
            <ForensicTimeline
              events={timelineEvents}
              isLoading={isLoadingTimeline}
            />
          ) : (
            <div className="p-8 text-center text-xs text-[var(--text-tertiary)] space-y-2">
              <Clock className="w-8 h-8 mx-auto text-[var(--text-tertiary)]" />
              <p>No artifact selected.</p>
              <p className="text-[11px]">Select an evidence item from the center panel to reconstruct its forensic timeline.</p>
            </div>
          )}
        </div>

        {/* PANE 2: CASE ITEMS LIST (Center at 1280px) */}
        <div className="lg:col-span-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] p-4 md:p-5 space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)]">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-purple-400" />
              <h3 className="text-xs font-bold text-[var(--text-primary)] uppercase tracking-wider">
                Evidence Artifacts
              </h3>
            </div>
            <Badge variant="neutral" size="xs">
              {caseData.items?.length || 0}
            </Badge>
          </div>

          {!caseData.items || caseData.items.length === 0 ? (
            <div className="p-8 text-center text-xs text-[var(--text-tertiary)] space-y-2">
              <FileText className="w-8 h-8 mx-auto text-[var(--text-tertiary)]" />
              <p>No artifacts linked to this case yet.</p>
              <p className="text-[11px]">Use "Add to Case" on any scan report or Gmail inbox email to attach evidence.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {caseData.items.map((item: CaseItem) => {
                const isSelected = selectedScanId === item.scan_id;
                return (
                  <div
                    key={item.id}
                    onClick={() => setSelectedScanId(item.scan_id)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer space-y-2 ${
                      isSelected
                        ? 'border-blue-500/60 bg-blue-500/10 shadow-xs ring-1 ring-blue-500/30'
                        : 'border-[var(--border-subtle)] bg-[var(--bg-inset)] hover:border-[var(--border-default)]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs font-semibold text-[var(--text-primary)] truncate">
                        {item.scan?.target || item.scan_id}
                      </span>
                      {item.scan?.risk_level && (
                        <SeverityChip
                          severity={item.scan.risk_level}
                          score={item.scan.risk_score}
                          size="xs"
                        />
                      )}
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-[var(--text-tertiary)] font-mono">
                      <span>Added by {item.added_by}</span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/scan/${item.scan_id}`);
                        }}
                        className="text-blue-400 hover:underline flex items-center gap-1 cursor-pointer"
                      >
                        <span>Report</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* PANE 3: COMMENTS & IMMUTABLE AUDIT TRAIL (Right at 1280px) */}
        <div className="lg:col-span-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] p-4 md:p-5 space-y-4">
          {/* Tab Selector */}
          <div className="flex rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-0.5">
            <button
              type="button"
              onClick={() => setActiveRightTab('comments')}
              className={`flex-1 py-1.5 px-3 rounded-md font-medium text-xs transition-colors cursor-pointer flex items-center justify-center gap-1.5 ${
                activeRightTab === 'comments'
                  ? 'bg-[var(--bg-panel)] text-[var(--text-primary)] shadow-xs'
                  : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <span>Comments ({caseData.comments?.length || 0})</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveRightTab('audit')}
              className={`flex-1 py-1.5 px-3 rounded-md font-medium text-xs transition-colors cursor-pointer flex items-center justify-center gap-1.5 ${
                activeRightTab === 'audit'
                  ? 'bg-[var(--bg-panel)] text-[var(--text-primary)] shadow-xs'
                  : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
              }`}
            >
              <History className="w-3.5 h-3.5" />
              <span>Audit Log ({caseData.audit?.length || 0})</span>
            </button>
          </div>

          {/* Tab Content 1: Comments */}
          {activeRightTab === 'comments' && (
            <div className="space-y-4 animate-in fade-in duration-100">
              {/* Comment Thread */}
              <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
                {!caseData.comments || caseData.comments.length === 0 ? (
                  <p className="text-xs text-[var(--text-tertiary)] text-center py-6">
                    No analyst comments yet. Add observations below.
                  </p>
                ) : (
                  caseData.comments.map((cmt) => (
                    <div
                      key={cmt.id}
                      className="p-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-1.5 text-xs"
                    >
                      <div className="flex items-center justify-between text-[11px] font-mono text-[var(--text-tertiary)]">
                        <span className="font-semibold text-blue-400 flex items-center gap-1">
                          <User className="w-3 h-3" />
                          <span>{cmt.author}</span>
                        </span>
                        <span>{new Date(cmt.created_at).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-xs text-[var(--text-primary)] leading-relaxed whitespace-pre-wrap font-sans">
                        {cmt.body}
                      </p>
                    </div>
                  ))
                )}
              </div>

              {/* Add Comment Input */}
              <form onSubmit={handleAddComment} className="space-y-2 pt-2 border-t border-[var(--border-subtle)]">
                <Textarea
                  value={newCommentBody}
                  onChange={(e) => setNewCommentBody(e.target.value)}
                  placeholder="Record an investigation note or IOC finding..."
                  rows={3}
                  className="text-xs"
                />
                <div className="flex justify-end">
                  <Button
                    type="submit"
                    variant="primary"
                    size="sm"
                    disabled={isPostingComment || !newCommentBody.trim()}
                    className="flex items-center gap-1.5"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Post Comment</span>
                  </Button>
                </div>
              </form>
            </div>
          )}

          {/* Tab Content 2: Immutable Audit Trail */}
          {activeRightTab === 'audit' && (
            <div className="space-y-3 max-h-96 overflow-y-auto pr-1 animate-in fade-in duration-100">
              {!caseData.audit || caseData.audit.length === 0 ? (
                <p className="text-xs text-[var(--text-tertiary)] text-center py-6">
                  No audit entries recorded yet.
                </p>
              ) : (
                caseData.audit.map((aud) => (
                  <div
                    key={aud.id}
                    className="p-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-1 text-xs"
                  >
                    <div className="flex items-center justify-between text-[10px] font-mono">
                      <span className="font-semibold uppercase text-blue-400">
                        {aud.action.replace('_', ' ')}
                      </span>
                      <span className="text-[var(--text-tertiary)]">
                        {new Date(aud.timestamp).toLocaleString()}
                      </span>
                    </div>
                    {aud.note && (
                      <p className="text-xs text-[var(--text-secondary)] font-sans">
                        {aud.note}
                      </p>
                    )}
                    <div className="text-[10px] text-[var(--text-tertiary)] font-mono">
                      Actor: {aud.actor}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>

      {/* State Transition Modal (Escalate / Resolve / Reopen) */}
      <Modal
        isOpen={modalAction !== null}
        onClose={() => setModalAction(null)}
        title={
          modalAction === 'escalate'
            ? 'Escalate Investigation Case'
            : modalAction === 'resolve'
            ? 'Resolve Investigation Case'
            : 'Reopen Investigation Case'
        }
        description="All status transitions require a mandatory explanation note for the immutable audit trail."
        size="md"
      >
        <form onSubmit={handleStateChange} className="space-y-4 py-1 text-xs">
          <div className="space-y-1.5">
            <label htmlFor="action-note" className="font-semibold text-[var(--text-secondary)]">
              Audit Justification / Resolution Note <span className="text-red-400">*</span>
            </label>
            <Textarea
              id="action-note"
              value={actionNote}
              onChange={(e) => setActionNote(e.target.value)}
              placeholder={
                modalAction === 'escalate'
                  ? 'Explain why this incident requires Tier-2/3 escalation...'
                  : modalAction === 'resolve'
                  ? 'Detail root cause, containment actions, and remediation taken...'
                  : 'Explain the reason for reopening this case...'
              }
              rows={4}
              required
            />
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-[var(--border-subtle)]">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => setModalAction(null)}
              disabled={isSubmittingAction}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant={modalAction === 'escalate' ? 'secondary' : 'primary'}
              size="sm"
              disabled={isSubmittingAction || !actionNote.trim()}
              className={modalAction === 'escalate' ? 'text-amber-400 border-amber-500/30' : ''}
            >
              {isSubmittingAction
                ? 'Recording...'
                : modalAction === 'escalate'
                ? 'Confirm Escalation'
                : modalAction === 'resolve'
                ? 'Confirm Resolution'
                : 'Confirm Reopen'}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
