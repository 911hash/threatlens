import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Briefcase,
  Network,
  Plus,
  Search,
  Filter,
  Clock,
  ArrowRight,
  Shield,
  Layers,
  ChevronRight,
  RefreshCw,
  FolderOpen,
  FileText,
  AlertCircle,
  CheckCircle2,
} from 'lucide-react';
import { api } from '../api/client';
import type { Case, GraphEdge, GraphNode } from '../types/threat';
import { Button } from '../components/primitives/Button';
import { Input } from '../components/primitives/Input';
import { Textarea } from '../components/primitives/Textarea';
import { Badge } from '../components/primitives/Badge';
import { Modal } from '../components/primitives/Modal';
import { EmptyState } from '../components/primitives/EmptyState';
import { ErrorState } from '../components/primitives/ErrorState';
import { Skeleton } from '../components/primitives/Skeleton';
import { useToast } from '../components/primitives/Toast';
import { ArtifactGraph } from '../components/domain/ArtifactGraph';

export function ForensicsPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const toast = useToast();

  const queryNodeId = searchParams.get('node_id');
  const querySearch = searchParams.get('query');
  const queryTab = searchParams.get('tab');

  const [activeTab, setActiveTab] = useState<'cases' | 'graph'>(
    queryNodeId || querySearch || queryTab === 'graph' ? 'graph' : 'cases'
  );

  // Cases State
  const [cases, setCases] = useState<Case[]>([]);
  const [isLoadingCases, setIsLoadingCases] = useState<boolean>(true);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // New Case Modal State
  const [isNewCaseOpen, setIsNewCaseOpen] = useState<boolean>(false);
  const [newTitle, setNewTitle] = useState<string>('');
  const [newDesc, setNewDesc] = useState<string>('');
  const [isSubmittingCase, setIsSubmittingCase] = useState<boolean>(false);

  // Graph Explorer State
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([]);
  const [selectedGraphNodeId, setSelectedGraphNodeId] = useState<string | undefined>(
    queryNodeId || undefined
  );
  const [isLoadingGraph, setIsLoadingGraph] = useState<boolean>(false);
  const [graphSearchInput, setGraphSearchInput] = useState<string>(querySearch || '');

  // 1. Fetch Cases
  const fetchCases = async () => {
    setIsLoadingCases(true);
    setCaseError(null);
    try {
      const data = await api.getCases();
      setCases(data);
    } catch (err: any) {
      setCaseError(err.message || 'Failed to retrieve cases.');
    } finally {
      setIsLoadingCases(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  // 2. Fetch Graph Data for Node
  const loadGraphNode = async (nodeId: string) => {
    setIsLoadingGraph(true);
    try {
      const res = await api.getNodeNeighbors(nodeId, 1);
      setGraphNodes(res.nodes);
      setGraphEdges(res.edges);
      setSelectedGraphNodeId(nodeId);
    } catch (err: any) {
      toast.error(err.message || 'Failed to load graph node.');
    } finally {
      setIsLoadingGraph(false);
    }
  };

  // 3. Fetch Recent Graph Nodes on Mount / Tab Switch
  const loadRecentGraph = async () => {
    setIsLoadingGraph(true);
    try {
      const res = await api.getRecentGraphNodes(20);
      setGraphNodes(res.nodes);
      setGraphEdges(res.edges);
      if (res.nodes && res.nodes.length > 0) {
        // Select first IP node or Domain node by default, or fallback to first node
        const defaultNode =
          res.nodes.find((n) => n.node_type === 'IP') ||
          res.nodes.find((n) => n.node_type === 'Domain') ||
          res.nodes[0];
        setSelectedGraphNodeId(defaultNode.id);
      }
    } catch (err: any) {
      toast.error(err.message || 'Failed to load recent graph nodes.');
    } finally {
      setIsLoadingGraph(false);
    }
  };

  useEffect(() => {
    if (queryTab === 'graph' && activeTab !== 'graph') {
      setActiveTab('graph');
    } else if (queryTab === 'cases' && activeTab !== 'cases') {
      setActiveTab('cases');
    }
  }, [queryTab]);

  useEffect(() => {
    if (queryNodeId) {
      setActiveTab('graph');
      loadGraphNode(queryNodeId);
    } else if (querySearch) {
      setActiveTab('graph');
      handleGraphLookup(querySearch);
    } else if (activeTab === 'graph' && graphNodes.length === 0) {
      loadRecentGraph();
    }
  }, [queryNodeId, querySearch, activeTab]);

  const handleGraphLookup = async (val: string) => {
    if (!val.trim()) return;
    setIsLoadingGraph(true);
    try {
      const node = await api.lookupGraphNode(val.trim());
      await loadGraphNode(node.id);
    } catch {
      toast.error(`Indicator '${val}' not found in artifact graph.`);
      setIsLoadingGraph(false);
    }
  };

  // 3. Create Case
  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      toast.error('Case title is required.');
      return;
    }
    setIsSubmittingCase(true);
    try {
      const created = await api.createCase({
        title: newTitle.trim(),
        description: newDesc.trim(),
      });
      toast.success('Investigation case initialized.');
      setIsNewCaseOpen(false);
      setNewTitle('');
      setNewDesc('');
      navigate(`/cases/${created.id}`);
    } catch (err: any) {
      toast.error(err.message || 'Failed to create case.');
    } finally {
      setIsSubmittingCase(false);
    }
  };

  // Filter cases
  const filteredCases = useMemo(() => {
    return cases.filter((c) => {
      const matchesStatus =
        statusFilter === 'all' ? true : c.status.toLowerCase() === statusFilter.toLowerCase();
      const matchesQuery =
        !searchQuery.trim() ||
        c.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.id.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesStatus && matchesQuery;
    });
  }, [cases, statusFilter, searchQuery]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      {/* Workspace Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 md:p-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] shadow-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Briefcase className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-lg md:text-xl font-bold text-[var(--text-primary)]">
                Forensic Platform & Case Management
              </h1>
              <p className="text-xs text-[var(--text-secondary)]">
                Correlate observable artifacts, inspect timelines, and audit incident investigation lifecycles.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* View Segmented Toggle */}
          <div className="flex rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-0.5">
            <button
              type="button"
              onClick={() => setActiveTab('cases')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                activeTab === 'cases'
                  ? 'bg-[var(--bg-panel)] text-[var(--text-primary)] shadow-xs'
                  : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
              }`}
            >
              <Briefcase className="w-3.5 h-3.5" />
              <span>Cases</span>
              <Badge variant="neutral" size="xs" className="ml-1 px-1 py-0 text-[10px]">
                {cases.length}
              </Badge>
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveTab('graph');
                if (graphNodes.length === 0) {
                  loadRecentGraph();
                }
              }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                activeTab === 'graph'
                  ? 'bg-[var(--bg-panel)] text-[var(--text-primary)] shadow-xs'
                  : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>Artifact Graph</span>
            </button>
          </div>

          <Button
            variant="primary"
            size="sm"
            onClick={() => setIsNewCaseOpen(true)}
            className="flex items-center gap-1.5"
          >
            <Plus className="w-4 h-4" />
            <span>New Case</span>
          </Button>
        </div>
      </div>

      {/* ───────────────────────────────────────────────────────────── */}
      {/* TAB A: INVESTIGATION CASES WORKSPACE */}
      {/* ───────────────────────────────────────────────────────────── */}
      {activeTab === 'cases' && (
        <div className="space-y-4 animate-in fade-in duration-150">
          {/* Controls Filter Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            {/* Status Filter Chips */}
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
              {[
                { key: 'all', label: 'All Cases' },
                { key: 'open', label: 'Open' },
                { key: 'escalated', label: 'Escalated' },
                { key: 'resolved', label: 'Resolved' },
              ].map(({ key, label }) => {
                const isSelected = statusFilter === key;
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setStatusFilter(key)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                      isSelected
                        ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30 font-semibold'
                        : 'border border-[var(--border-subtle)] bg-[var(--bg-panel)] text-[var(--text-secondary)] hover:bg-[var(--bg-inset)]'
                    }`}
                  >
                    {label}
                  </button>
                );
              })}
            </div>

            {/* Search Input */}
            <div className="relative w-full sm:w-72">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-tertiary)]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search cases by title or ID..."
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none focus:border-blue-500/60"
              />
            </div>
          </div>

          {/* Cases List */}
          {isLoadingCases ? (
            <div className="border border-[var(--border-subtle)] rounded-2xl bg-[var(--bg-panel)] divide-y divide-[var(--border-subtle)] p-2 space-y-3">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="p-4 flex items-center justify-between gap-4">
                  <div className="space-y-2 flex-1">
                    <Skeleton className="h-4 w-48" />
                    <Skeleton className="h-3 w-80" />
                  </div>
                  <Skeleton className="h-6 w-20 rounded-full" />
                </div>
              ))}
            </div>
          ) : caseError ? (
            <ErrorState
              title="Failed to Load Investigation Cases"
              message={caseError}
              onRetry={fetchCases}
            />
          ) : filteredCases.length === 0 ? (
            <div className="p-8 border border-[var(--border-subtle)] rounded-2xl bg-[var(--bg-panel)]">
              <EmptyState
                title="No cases yet"
                description="Add an email to a case to start tracking an investigation."
                icon={<Briefcase className="w-10 h-10 text-[var(--text-tertiary)]" />}
                action={
                  <Button variant="primary" size="sm" onClick={() => setIsNewCaseOpen(true)}>
                    <Plus className="w-4 h-4 mr-1.5" />
                    <span>Create First Case</span>
                  </Button>
                }
              />
            </div>
          ) : (
            <div className="border border-[var(--border-subtle)] rounded-2xl bg-[var(--bg-panel)] divide-y divide-[var(--border-subtle)] overflow-hidden shadow-xs">
              {filteredCases.map((c) => {
                const statusStyles = {
                  open: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
                  escalated: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
                  resolved: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
                }[c.status.toLowerCase()] || 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30';

                return (
                  <div
                    key={c.id}
                    role="button"
                    tabIndex={0}
                    onClick={() => navigate(`/cases/${c.id}`)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        navigate(`/cases/${c.id}`);
                      }
                    }}
                    className="p-4 md:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-[var(--bg-inset)] transition-colors cursor-pointer group outline-none focus:bg-[var(--bg-inset)]"
                  >
                    <div className="space-y-1.5 min-w-0 flex-1">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="font-semibold text-sm md:text-base text-[var(--text-primary)] group-hover:text-blue-400 transition-colors">
                          {c.title}
                        </span>
                        <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded-md border font-semibold ${statusStyles}`}>
                          {c.status}
                        </span>
                      </div>

                      {c.description && (
                        <p className="text-xs text-[var(--text-secondary)] line-clamp-1">
                          {c.description}
                        </p>
                      )}

                      <div className="flex items-center gap-4 text-[11px] font-mono text-[var(--text-tertiary)]">
                        <span className="flex items-center gap-1">
                          <FolderOpen className="w-3 h-3" />
                          <span>{c.item_count || 0} artifact{c.item_count === 1 ? '' : 's'} linked</span>
                        </span>
                        <span>·</span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          <span>Updated {new Date(c.updated_at).toLocaleString()}</span>
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0 sm:self-center">
                      <span className="text-xs text-blue-400 font-medium opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1">
                        <span>Open Workspace</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ───────────────────────────────────────────────────────────── */}
      {/* TAB B: ARTIFACT GRAPH EXPLORER */}
      {/* ───────────────────────────────────────────────────────────── */}
      {activeTab === 'graph' && (
        <div className="space-y-4 animate-in fade-in duration-150">
          {/* Graph Search & Node Filter */}
          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex-1 max-w-lg relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-tertiary)]" />
              <input
                type="text"
                value={graphSearchInput}
                onChange={(e) => setGraphSearchInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    handleGraphLookup(graphSearchInput);
                  }
                }}
                placeholder="Search indicator in graph (e.g. IP, domain, hash, email)..."
                className="w-full pl-9 pr-24 py-1.5 text-xs rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-none focus:border-blue-500/60 font-mono"
              />
              <button
                type="button"
                onClick={() => handleGraphLookup(graphSearchInput)}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 px-2.5 py-1 text-[11px] rounded bg-blue-500/20 text-blue-400 font-medium hover:bg-blue-500/30 transition-colors cursor-pointer"
              >
                Search
              </button>
            </div>

            <div className="text-xs font-mono text-[var(--text-tertiary)] flex items-center gap-2">
              <span>{graphNodes.length} nodes loaded</span>
              <span>·</span>
              <span>{graphEdges.length} edges mapped</span>
            </div>
          </div>

          {/* Graph Visualization Component */}
          <ArtifactGraph
            nodes={graphNodes}
            edges={graphEdges}
            selectedNodeId={selectedGraphNodeId}
            onPivot={(nid) => loadGraphNode(nid)}
            isLoading={isLoadingGraph}
          />
        </div>
      )}

      {/* Modal: New Investigation Case */}
      <Modal
        isOpen={isNewCaseOpen}
        onClose={() => setIsNewCaseOpen(false)}
        title="Create New Investigation Case"
        description="Initialize an investigation workspace with an immutable audit log."
        size="md"
      >
        <form onSubmit={handleCreateCase} className="space-y-4 py-1 text-xs">
          <div className="space-y-1">
            <label htmlFor="modal-case-title" className="font-semibold text-[var(--text-secondary)]">
              Case Title <span className="text-red-400">*</span>
            </label>
            <Input
              id="modal-case-title"
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="e.g. Credential Phishing Wave Targeting Finance"
              required
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="modal-case-desc" className="font-semibold text-[var(--text-secondary)]">
              Description & Objectives
            </label>
            <Textarea
              id="modal-case-desc"
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="Incident context, initial indicators, and analyst tracking notes..."
              rows={4}
            />
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-[var(--border-subtle)]">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => setIsNewCaseOpen(false)}
              disabled={isSubmittingCase}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" size="sm" disabled={isSubmittingCase}>
              {isSubmittingCase ? 'Creating...' : 'Create Case Workspace'}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
