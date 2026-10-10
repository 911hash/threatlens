import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Briefcase, Plus, Check, Loader2 } from 'lucide-react';
import { api } from '../../api/client';
import type { Case } from '../../types/threat';
import { Modal } from '../primitives/Modal';
import { Button } from '../primitives/Button';
import { Input } from '../primitives/Input';
import { Textarea } from '../primitives/Textarea';
import { Badge } from '../primitives/Badge';
import { useToast } from '../primitives/Toast';

export interface AddToCaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  scanId: string;
  scanTarget?: string;
}

export const AddToCaseModal: React.FC<AddToCaseModalProps> = ({
  isOpen,
  onClose,
  scanId,
  scanTarget,
}) => {
  const navigate = useNavigate();
  const toast = useToast();

  const [cases, setCases] = useState<Case[]>([]);
  const [loadingCases, setLoadingCases] = useState<boolean>(true);
  const [selectedCaseId, setSelectedCaseId] = useState<string>('');
  const [mode, setMode] = useState<'existing' | 'new'>('existing');

  // New Case Fields
  const [newTitle, setNewTitle] = useState<string>('');
  const [newDesc, setNewDesc] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);

  useEffect(() => {
    if (!isOpen) return;
    let isMounted = true;
    setLoadingCases(true);

    api.getCases()
      .then((data) => {
        if (!isMounted) return;
        setCases(data);
        const openCases = data.filter((c) => c.status !== 'resolved');
        if (openCases.length > 0) {
          setSelectedCaseId(openCases[0].id);
          setMode('existing');
        } else {
          setMode('new');
        }
      })
      .catch(() => {
        if (isMounted) setMode('new');
      })
      .finally(() => {
        if (isMounted) setLoadingCases(false);
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);

    try {
      let targetCaseId = selectedCaseId;

      if (mode === 'new') {
        if (!newTitle.trim()) {
          toast.error('Case title is required.');
          setSubmitting(false);
          return;
        }
        const created = await api.createCase({
          title: newTitle.trim(),
          description: newDesc.trim() || `Created for investigation of ${scanTarget || scanId}`,
        });
        targetCaseId = created.id;
      }

      if (!targetCaseId) {
        toast.error('Please select or create an investigation case.');
        setSubmitting(false);
        return;
      }

      await api.addCaseItem(targetCaseId, scanId);
      toast.success('Investigation artifact added to case.');
      onClose();
      navigate(`/cases/${targetCaseId}`);
    } catch (err: any) {
      toast.error(err.message || 'Failed to link scan to case.');
    } finally {
      setSubmitting(false);
    }
  };

  const openCases = cases.filter((c) => c.status !== 'resolved');

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Add Artifact to Investigation Case"
      description={`Link scan ${scanId.slice(0, 14)} to an incident investigation workspace.`}
      size="md"
    >
      <form onSubmit={handleSubmit} className="space-y-4 py-1 text-xs">
        {/* Toggle Mode */}
        {openCases.length > 0 && (
          <div className="flex rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-0.5">
            <button
              type="button"
              onClick={() => setMode('existing')}
              className={`flex-1 py-1.5 px-3 rounded-md font-medium text-xs transition-colors cursor-pointer ${
                mode === 'existing'
                  ? 'bg-[var(--bg-panel)] text-[var(--text-primary)] shadow-xs'
                  : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
              }`}
            >
              Select Existing Case ({openCases.length})
            </button>
            <button
              type="button"
              onClick={() => setMode('new')}
              className={`flex-1 py-1.5 px-3 rounded-md font-medium text-xs transition-colors cursor-pointer ${
                mode === 'new'
                  ? 'bg-[var(--bg-panel)] text-[var(--text-primary)] shadow-xs'
                  : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
              }`}
            >
              + Create New Case
            </button>
          </div>
        )}

        {mode === 'existing' ? (
          <div className="space-y-2">
            <label className="font-semibold text-[var(--text-secondary)]">Choose Open Case</label>
            <div className="divide-y divide-[var(--border-subtle)] border border-[var(--border-subtle)] rounded-xl max-h-56 overflow-y-auto bg-[var(--bg-panel)]">
              {openCases.map((c) => {
                const isSelected = selectedCaseId === c.id;
                return (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => setSelectedCaseId(c.id)}
                    className={`w-full flex items-center justify-between p-3 text-left transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-blue-500/10 border-l-2 border-l-blue-500'
                        : 'hover:bg-[var(--bg-inset)]'
                    }`}
                  >
                    <div className="space-y-0.5 min-w-0 pr-2">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-[var(--text-primary)] truncate text-xs">
                          {c.title}
                        </span>
                        <Badge
                          variant={c.status === 'escalated' ? 'error' : 'neutral'}
                          size="xs"
                          className="uppercase font-mono text-[9px]"
                        >
                          {c.status}
                        </Badge>
                      </div>
                      <div className="text-[11px] text-[var(--text-tertiary)] font-mono">
                        {c.item_count || 0} artifacts · Updated {new Date(c.updated_at).toLocaleDateString()}
                      </div>
                    </div>
                    {isSelected && <Check className="w-4 h-4 text-blue-400 shrink-0" />}
                  </button>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="space-y-1">
              <label htmlFor="case-title" className="font-semibold text-[var(--text-secondary)]">
                Case Title <span className="text-red-400">*</span>
              </label>
              <Input
                id="case-title"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                placeholder="e.g. Executive Phishing Outbreak — Q4"
                required
              />
            </div>
            <div className="space-y-1">
              <label htmlFor="case-desc" className="font-semibold text-[var(--text-secondary)]">
                Incident Description
              </label>
              <Textarea
                id="case-desc"
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                placeholder="Optional hypothesis, scope of affected mailboxes, and response notes..."
                rows={3}
              />
            </div>
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-2 border-t border-[var(--border-subtle)]">
          <Button type="button" variant="secondary" size="sm" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" size="sm" disabled={submitting}>
            {submitting ? (
              <span className="flex items-center gap-1.5">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Linking Artifact...</span>
              </span>
            ) : (
              <span>Add to Case</span>
            )}
          </Button>
        </div>
      </form>
    </Modal>
  );
};
