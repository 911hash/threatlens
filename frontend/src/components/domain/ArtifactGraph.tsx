import React, { useState, useRef, useEffect, useMemo } from 'react';
import {
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Maximize2,
  Minimize2,
  Layers,
  ArrowRight,
  Shield,
  Search,
  List,
  Compass,
} from 'lucide-react';
import type { GraphEdge, GraphNode, GraphNodeType } from '../../types/threat';
import { Badge } from '../primitives/Badge';
import { IconButton } from '../primitives/IconButton';
import { Tooltip } from '../primitives/Tooltip';

export interface ArtifactGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedNodeId?: string;
  onPivot: (nodeId: string) => void;
  isLoading?: boolean;
  className?: string;
}

export const NODE_COLORS: Record<string, { fill: string; stroke: string; text: string; bg: string }> = {
  IP: { fill: '#3b82f6', stroke: '#1d4ed8', text: '#93c5fd', bg: 'rgba(59, 130, 246, 0.15)' },
  Domain: { fill: '#10b981', stroke: '#047857', text: '#6ee7b7', bg: 'rgba(16, 185, 129, 0.15)' },
  AttachmentHash: { fill: '#f59e0b', stroke: '#b45309', text: '#fcd34d', bg: 'rgba(245, 158, 11, 0.15)' },
  URL: { fill: '#8b5cf6', stroke: '#6d28d9', text: '#c4b5fd', bg: 'rgba(139, 92, 246, 0.15)' },
  Email: { fill: '#64748b', stroke: '#334155', text: '#cbd5e1', bg: 'rgba(100, 116, 139, 0.15)' },
  ASN: { fill: '#f97316', stroke: '#c2410c', text: '#fdba74', bg: 'rgba(249, 115, 22, 0.15)' },
  Sender: { fill: '#06b6d4', stroke: '#0e7490', text: '#67e8f9', bg: 'rgba(6, 182, 212, 0.15)' },
  Recipient: { fill: '#06b6d4', stroke: '#0e7490', text: '#67e8f9', bg: 'rgba(6, 182, 212, 0.15)' },
};

const DEFAULT_COLOR = { fill: '#71717a', stroke: '#3f3f46', text: '#d4d4d8', bg: 'rgba(113, 113, 122, 0.15)' };

export const ArtifactGraph: React.FC<ArtifactGraphProps> = ({
  nodes,
  edges,
  selectedNodeId,
  onPivot,
  isLoading = false,
  className = '',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState<number>(1.0);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isMobileList, setIsMobileList] = useState<boolean>(false);
  const [activeHoverNode, setActiveHoverNode] = useState<string | null>(null);

  // Responsive check for small viewports (e.g. 320px)
  useEffect(() => {
    const checkWidth = () => {
      if (containerRef.current) {
        setIsMobileList(containerRef.current.clientWidth < 420);
      } else if (window.innerWidth < 420) {
        setIsMobileList(true);
      }
    };
    checkWidth();
    window.addEventListener('resize', checkWidth);
    return () => window.removeEventListener('resize', checkWidth);
  }, []);

  // Determine center root node (prefer IP, Domain, or first node)
  const rootNode = useMemo(() => {
    if (!nodes || nodes.length === 0) return null;
    if (selectedNodeId) {
      const match = nodes.find((n) => n.id === selectedNodeId);
      if (match) return match;
    }
    // Fallback: prefer IP or Domain over generic nodes
    return (
      nodes.find((n) => n.node_type === 'IP') ||
      nodes.find((n) => n.node_type === 'Domain') ||
      nodes[0]
    );
  }, [nodes, selectedNodeId]);

  const TYPE_ORDER: Record<string, number> = {
    Domain: 1,
    URL: 2,
    IP: 3,
    ASN: 4,
    Sender: 5,
    Recipient: 6,
    AttachmentHash: 7,
    Email: 8,
  };

  // Compute radial positions: Option A (cluster by type) + Option D (wider ring)
  const { positions, layoutEdges } = useMemo(() => {
    const pos: Record<string, { x: number; y: number; node: GraphNode; isCenter: boolean }> = {};
    if (!rootNode) return { positions: pos, layoutEdges: [] };

    const cx = 400;
    const cy = 400;
    pos[rootNode.id] = { x: cx, y: cy, node: rootNode, isCenter: true };

    // Group nodes by node_type in distinct angular sectors
    const satelliteNodes = nodes
      .filter((n) => n.id !== rootNode.id)
      .sort((a, b) => {
        const orderA = TYPE_ORDER[a.node_type] ?? 99;
        const orderB = TYPE_ORDER[b.node_type] ?? 99;
        if (orderA !== orderB) return orderA - orderB;
        return (a.display_value || a.value).localeCompare(b.display_value || b.value);
      });

    const N = satelliteNodes.length;
    const radius = 280;

    satelliteNodes.forEach((node, idx) => {
      const angle = (2 * Math.PI * idx) / Math.max(1, N) - Math.PI / 2;
      const x = cx + radius * Math.cos(angle);
      const y = cy + radius * Math.sin(angle);
      pos[node.id] = { x, y, node, isCenter: false };
    });

    const lEdges = edges
      .map((edge) => {
        const p1 = pos[edge.from_node_id];
        const p2 = pos[edge.to_node_id];
        if (!p1 || !p2) return null;
        return {
          edge,
          x1: p1.x,
          y1: p1.y,
          x2: p2.x,
          y2: p2.y,
          mx: (p1.x + p2.x) / 2,
          my: (p1.y + p2.y) / 2,
        };
      })
      .filter(Boolean) as Array<{
      edge: GraphEdge;
      x1: number;
      y1: number;
      x2: number;
      y2: number;
      mx: number;
      my: number;
    }>;

    return { positions: pos, layoutEdges: lEdges };
  }, [nodes, edges, rootNode]);

  // Pan interaction
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setZoom((prev) => Math.min(Math.max(0.5, prev + delta), 2.5));
  };

  const resetView = () => {
    setZoom(1.0);
    setPan({ x: 0, y: 0 });
  };

  if (isLoading) {
    return (
      <div className={`p-8 text-center flex flex-col items-center justify-center min-h-[360px] border border-[var(--border-subtle)] rounded-2xl bg-[var(--bg-panel)] ${className}`}>
        <div className="w-10 h-10 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-3" />
        <span className="text-xs text-[var(--text-secondary)] font-mono">
          Correlating artifact graph observable mesh...
        </span>
      </div>
    );
  }

  if (!nodes || nodes.length === 0) {
    return (
      <div className={`p-8 text-center flex flex-col items-center justify-center min-h-[300px] border border-[var(--border-subtle)] rounded-2xl bg-[var(--bg-panel)] ${className}`}>
        <Compass className="w-8 h-8 text-[var(--text-tertiary)] mb-2" />
        <p className="text-xs text-[var(--text-secondary)]">No observable graph nodes available for this target.</p>
      </div>
    );
  }

  // 320px viewport fallback: Accessible List View
  if (isMobileList) {
    return (
      <div
        ref={containerRef}
        className={`border border-[var(--border-subtle)] rounded-2xl bg-[var(--bg-panel)] p-4 space-y-4 ${className}`}
      >
        <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)]">
          <div className="flex items-center gap-2">
            <List className="w-4 h-4 text-blue-400" />
            <h4 className="text-xs font-semibold text-[var(--text-primary)]">Observable Mesh (List View)</h4>
          </div>
          <Badge variant="outline" size="xs">
            {nodes.length} Nodes
          </Badge>
        </div>

        {rootNode && (
          <div className="p-3 rounded-xl border border-blue-500/30 bg-blue-500/10 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase text-blue-400 font-bold">Center Pivot</span>
              <Badge variant="neutral" size="xs">
                {rootNode.node_type}
              </Badge>
            </div>
            <div className="font-mono text-xs text-[var(--text-primary)] break-all font-semibold">
              {rootNode.display_value || rootNode.value}
            </div>
          </div>
        )}

        <div className="space-y-2">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-tertiary)]">
            Connected Entities ({nodes.length - (rootNode ? 1 : 0)})
          </span>
          <div className="divide-y divide-[var(--border-subtle)] border border-[var(--border-subtle)] rounded-xl overflow-hidden bg-[var(--bg-inset)]">
            {nodes
              .filter((n) => n.id !== rootNode?.id)
              .map((node) => {
                const conf = NODE_COLORS[node.node_type] || DEFAULT_COLOR;
                return (
                  <button
                    key={node.id}
                    type="button"
                    onClick={() => onPivot(node.id)}
                    className="w-full flex items-center justify-between p-2.5 text-left hover:bg-[var(--bg-panel)] transition-colors cursor-pointer group"
                  >
                    <div className="space-y-0.5 min-w-0 pr-2">
                      <div className="flex items-center gap-1.5">
                        <span
                          className="w-2 h-2 rounded-full shrink-0"
                          style={{ backgroundColor: conf.fill }}
                        />
                        <span className="text-[10px] font-mono font-medium uppercase text-[var(--text-secondary)]">
                          {node.node_type}
                        </span>
                      </div>
                      <div className="text-xs font-mono text-[var(--text-primary)] truncate">
                        {node.display_value || node.value}
                      </div>
                    </div>
                    <span className="text-[10px] text-blue-400 font-mono flex items-center gap-0.5 group-hover:translate-x-0.5 transition-transform shrink-0">
                      <span>Pivot</span>
                      <ArrowRight className="w-3 h-3" />
                    </span>
                  </button>
                );
              })}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={`relative border border-[var(--border-subtle)] rounded-2xl bg-[var(--bg-panel)] overflow-hidden select-none ${className}`}
    >
      {/* Floating Toolbar */}
      <div className="absolute top-3 right-3 z-10 flex items-center gap-1 p-1 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)]/90 backdrop-blur-md shadow-sm">
        <IconButton
          icon={<ZoomIn className="w-3.5 h-3.5" />}
          aria-label="Zoom in"
          size="sm"
          variant="ghost"
          onClick={() => setZoom((prev) => Math.min(prev + 0.2, 2.5))}
        />
        <IconButton
          icon={<ZoomOut className="w-3.5 h-3.5" />}
          aria-label="Zoom out"
          size="sm"
          variant="ghost"
          onClick={() => setZoom((prev) => Math.max(prev - 0.2, 0.5))}
        />
        <IconButton
          icon={<RotateCcw className="w-3.5 h-3.5" />}
          aria-label="Reset zoom and pan"
          size="sm"
          variant="ghost"
          onClick={resetView}
        />
      </div>

      {/* Type Legend */}
      <div className="absolute bottom-3 left-3 z-10 hidden sm:flex items-center gap-3 p-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)]/90 backdrop-blur-md text-[10px] font-mono text-[var(--text-secondary)]">
        {Object.entries(NODE_COLORS)
          .slice(0, 6)
          .map(([type, colors]) => (
            <div key={type} className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: colors.fill }} />
              <span>{type}</span>
            </div>
          ))}
      </div>

      {/* SVG Radial Graph */}
      <div
        className="w-full h-[520px] cursor-grab active:cursor-grabbing flex items-center justify-center overflow-hidden"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
      >
        <svg
          viewBox="0 0 800 800"
          className="w-full h-full max-w-[800px] max-h-[800px] transition-transform duration-75"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: 'center center',
          }}
        >
          <defs>
            {/* Radial background grid */}
            <pattern id="graph-grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <circle cx="20" cy="20" r="0.8" fill="var(--border-subtle)" opacity="0.6" />
            </pattern>
          </defs>

          <rect width="800" height="800" fill="url(#graph-grid)" opacity="0.4" />

          {/* Guide Circles */}
          <circle cx="400" cy="400" r="280" fill="none" stroke="var(--border-subtle)" strokeDasharray="4 4" strokeWidth="1" />
          <circle cx="400" cy="400" r="140" fill="none" stroke="var(--border-subtle)" strokeDasharray="2 2" strokeWidth="0.5" opacity="0.5" />

          {/* Edges */}
          <g className="edges">
            {layoutEdges.map(({ edge, x1, y1, x2, y2, mx, my }) => {
              const isHovered =
                activeHoverNode && (edge.from_node_id === activeHoverNode || edge.to_node_id === activeHoverNode);
              return (
                <g key={edge.id} className="transition-opacity duration-150">
                  <line
                    x1={x1}
                    y1={y1}
                    x2={x2}
                    y2={y2}
                    stroke={isHovered ? '#60a5fa' : 'var(--border-default)'}
                    strokeWidth={isHovered ? 2.5 : 1.2}
                    opacity={isHovered ? 1 : 0.6}
                  />
                  {/* Edge label pill */}
                  <g transform={`translate(${mx}, ${my})`}>
                    <rect
                      x="-30"
                      y="-7"
                      width="60"
                      height="14"
                      rx="4"
                      fill="var(--bg-panel)"
                      stroke="var(--border-subtle)"
                      strokeWidth="0.8"
                    />
                    <text
                      textAnchor="middle"
                      dominantBaseline="middle"
                      className="text-[7.5px] font-mono font-semibold fill-[var(--text-tertiary)] select-none uppercase"
                    >
                      {edge.edge_type.replace('_', ' ').slice(0, 9)}
                    </text>
                  </g>
                </g>
              );
            })}
          </g>

          {/* Nodes */}
          <g className="nodes">
            {Object.values(positions).map(({ x, y, node, isCenter }) => {
              const colors = NODE_COLORS[node.node_type] || DEFAULT_COLOR;
              const isSelected = node.id === rootNode?.id;
              const isHovered = activeHoverNode === node.id;
              const rawLabel = node.display_value || node.value;
              const maxLen = isCenter ? 20 : 16;
              const displayLabel = rawLabel.length > maxLen ? rawLabel.slice(0, maxLen - 1) + '…' : rawLabel;

              return (
                <g
                  key={node.id}
                  transform={`translate(${x}, ${y})`}
                  tabIndex={0}
                  role="button"
                  aria-label={`${node.node_type}: ${rawLabel}. Press Enter to pivot.`}
                  className="cursor-pointer outline-none focus:ring-2 focus:ring-blue-400"
                  onClick={(e) => {
                    e.stopPropagation();
                    onPivot(node.id);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onPivot(node.id);
                    }
                  }}
                  onMouseEnter={() => setActiveHoverNode(node.id)}
                  onMouseLeave={() => setActiveHoverNode(null)}
                >
                  <title>{`${node.node_type}: ${rawLabel}`}</title>
                  {/* Glow pulse on center / hovered node */}
                  {(isCenter || isHovered) && (
                    <circle
                      r={isCenter ? 32 : 18}
                      fill={colors.fill}
                      opacity={0.15}
                      className="animate-pulse"
                    />
                  )}

                  {/* Main Circle (Option D: 30% shrink on satellites) */}
                  <circle
                    r={isCenter ? 24 : 13}
                    fill={colors.fill}
                    stroke={isSelected ? '#ffffff' : colors.stroke}
                    strokeWidth={isSelected ? 2.5 : 1.5}
                    className="transition-transform duration-150 hover:scale-115 shadow-lg"
                  />

                  {/* Type abbreviation in circle */}
                  <text
                    textAnchor="middle"
                    dominantBaseline="middle"
                    className={`font-mono font-bold fill-white select-none pointer-events-none ${
                      isCenter ? 'text-[9px]' : 'text-[7px]'
                    }`}
                  >
                    {node.node_type.slice(0, 3).toUpperCase()}
                  </text>

                  {/* Node label box */}
                  <g transform={`translate(0, ${isCenter ? 32 : 19})`}>
                    <rect
                      x={isCenter ? -55 : -42}
                      y="-1"
                      width={isCenter ? 110 : 84}
                      height={isCenter ? 18 : 15}
                      rx="4"
                      fill="var(--bg-inset)"
                      stroke="var(--border-subtle)"
                      strokeWidth="0.8"
                      opacity="0.95"
                    />
                    <text
                      textAnchor="middle"
                      dominantBaseline="middle"
                      y={isCenter ? 8 : 6.5}
                      className={`font-mono fill-[var(--text-primary)] select-none pointer-events-none font-medium truncate ${
                        isCenter ? 'text-[9px]' : 'text-[7.5px]'
                      }`}
                    >
                      {displayLabel}
                    </text>
                  </g>
                </g>
              );
            })}
          </g>
        </svg>
      </div>
    </div>
  );
};
