import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Network,
  ArrowRight,
  ExternalLink,
  Shield,
  Layers,
  Sparkles,
  RefreshCw,
  Search,
} from 'lucide-react';
import { api } from '../../api/client';
import type { GraphNode, GraphPivot } from '../../types/threat';
import { useDefang } from '../../design/DefangContext';
import { useDrawer } from '../../context/DrawerContext';
import { Badge } from '../primitives/Badge';
import { Button } from '../primitives/Button';
import { Skeleton } from '../primitives/Skeleton';
import { NODE_COLORS } from './ArtifactGraph';

export interface PivotPanelProps {
  nodeId?: string;
  indicator?: string;
  type?: string;
}

export const PivotPanel: React.FC<PivotPanelProps> = ({
  nodeId,
  indicator,
  type,
}) => {
  const navigate = useNavigate();
  const { formatIndicator } = useDefang();
  const drawer = useDrawer();

  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [pivot, setPivot] = useState<GraphPivot | null>(null);
  const [activeNodeId, setActiveNodeId] = useState<string | undefined>(nodeId);

  useEffect(() => {
    let isMounted = true;
    const fetchPivotData = async () => {
      setLoading(true);
      setError(null);

      try {
        let targetId = activeNodeId;

        // If no nodeId, lookup by indicator
        if (!targetId && indicator) {
          try {
            const lookup = await api.lookupGraphNode(indicator, type);
            targetId = lookup.id;
            if (isMounted) setActiveNodeId(targetId);
          } catch {
            // Not yet indexed into graph
            if (isMounted) {
              setLoading(false);
              setPivot(null);
            }
            return;
          }
        }

        if (targetId) {
          const res = await api.getNodePivot(targetId);
          if (isMounted) setPivot(res);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || 'Failed to load pivot graph relationships.');
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    fetchPivotData();
    return () => {
      isMounted = false;
    };
  }, [activeNodeId, indicator, type]);

  const handleOpenInForensics = () => {
    drawer.close();
    if (pivot?.node?.id) {
      navigate(`/forensics?node_id=${encodeURIComponent(pivot.node.id)}`);
    } else if (indicator) {
      navigate(`/forensics?query=${encodeURIComponent(indicator)}`);
    } else {
      navigate('/forensics');
    }
  };

  const displayVal = pivot?.node?.display_value || pivot?.node?.value || indicator || 'Unknown Indicator';
  const defangedVal = formatIndicator(displayVal);
  const nodeType = pivot?.node?.node_type || type || 'Indicator';
  const colors = NODE_COLORS[nodeType] || { fill: '#3b82f6', text: '#93c5fd', bg: 'rgba(59, 130, 246, 0.15)' };

  if (loading) {
    return (
      <div className="space-y-4 p-1">
        <div className="flex items-center gap-3">
          <Skeleton className="w-10 h-10 rounded-xl" />
          <div className="space-y-1.5 flex-1">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-5 w-full" />
          </div>
        </div>
        <Skeleton className="h-24 w-full rounded-xl" />
        <Skeleton className="h-32 w-full rounded-xl" />
      </div>
    );
  }

  if (error || !pivot) {
    return (
      <div className="space-y-4 p-1 text-xs">
        <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
          <div className="flex items-center justify-between">
            <Badge variant="outline" size="xs" className="uppercase font-mono">
              {nodeType}
            </Badge>
            <span className="text-[10px] text-[var(--text-tertiary)] font-mono">Local Telemetry</span>
          </div>
          <div className="font-mono text-sm text-[var(--text-primary)] break-all font-semibold">
            {defangedVal}
          </div>
        </div>

        <div className="p-4 rounded-xl border border-blue-500/20 bg-blue-500/5 text-[var(--text-secondary)] space-y-2">
          <div className="flex items-center gap-2 text-blue-400 font-semibold">
            <Network className="w-4 h-4" />
            <span>Forensic Mesh Observation</span>
          </div>
          <p className="leading-relaxed">
            This indicator has not yet been linked to an indexed investigation scan in the artifact graph.
          </p>
        </div>

        <Button
          variant="primary"
          size="sm"
          onClick={handleOpenInForensics}
          className="w-full flex items-center justify-center gap-2"
        >
          <Network className="w-4 h-4" />
          <span>Open in Forensics Workspace</span>
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-5 p-1 text-xs">
      {/* Target Indicator Card */}
      <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: colors.fill }} />
            <Badge variant="neutral" size="xs" className="uppercase font-mono font-bold">
              {nodeType}
            </Badge>
          </div>
          <span className="text-[10px] font-mono text-[var(--text-tertiary)]">
            {pivot.total_connections} connection{pivot.total_connections === 1 ? '' : 's'}
          </span>
        </div>
        <div className="font-mono text-sm text-[var(--text-primary)] break-all font-bold">
          {defangedVal}
        </div>
      </div>

      {/* Connected Entities Grouped by Type */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-tertiary)] font-semibold">
            Connected Graph Observables
          </span>
          <span className="text-[10px] font-mono text-[var(--text-tertiary)]">
            {Object.keys(pivot.grouped).length} entity types
          </span>
        </div>

        {Object.entries(pivot.grouped).length === 0 ? (
          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] text-center text-[var(--text-secondary)]">
            No 1-hop connected neighbors found.
          </div>
        ) : (
          <div className="space-y-3">
            {Object.entries(pivot.grouped).map(([gType, gNodes]) => {
              const gColors = NODE_COLORS[gType] || { fill: '#71717a', text: '#d4d4d8' };
              return (
                <div
                  key={gType}
                  className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] overflow-hidden"
                >
                  <div className="flex items-center justify-between px-3 py-2 bg-[var(--bg-inset)] border-b border-[var(--border-subtle)]">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: gColors.fill }} />
                      <span className="font-mono text-xs font-semibold text-[var(--text-primary)]">
                        {gType}
                      </span>
                    </div>
                    <Badge variant="outline" size="xs">
                      {gNodes.length}
                    </Badge>
                  </div>

                  <div className="divide-y divide-[var(--border-subtle)] max-h-48 overflow-y-auto">
                    {gNodes.map((n) => (
                      <button
                        key={n.id}
                        type="button"
                        onClick={() => setActiveNodeId(n.id)}
                        className="w-full flex items-center justify-between px-3 py-2 text-left hover:bg-[var(--bg-inset)] transition-colors cursor-pointer group"
                      >
                        <span className="font-mono text-xs text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] truncate max-w-[240px]">
                          {formatIndicator(n.display_value || n.value)}
                        </span>
                        <span className="text-[10px] text-blue-400 font-mono flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                          <span>Pivot</span>
                          <ArrowRight className="w-3 h-3" />
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Action Button */}
      <Button
        variant="primary"
        size="sm"
        onClick={handleOpenInForensics}
        className="w-full flex items-center justify-center gap-2 shadow-sm"
      >
        <Network className="w-4 h-4" />
        <span>Open in Forensics Workspace</span>
      </Button>
    </div>
  );
};
