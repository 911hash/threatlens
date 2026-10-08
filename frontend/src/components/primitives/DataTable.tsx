import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { ChevronDown, ChevronUp, ChevronsUpDown, Columns, Eye, EyeOff } from 'lucide-react';
import { useTheme } from '../../design/ThemeContext';
import { Checkbox } from './Checkbox';
import { Skeleton } from './Skeleton';
import { EmptyState } from './EmptyState';

export interface ColumnDef<T> {
  id: string;
  header: React.ReactNode;
  cell: (row: T, index: number) => React.ReactNode;
  width?: number; // initial width in px
  minWidth?: number;
  maxWidth?: number;
  sortable?: boolean;
  enableResizing?: boolean;
  enableHiding?: boolean;
}

export type SortDirection = 'asc' | 'desc' | null;

export interface SortState {
  columnId: string;
  direction: SortDirection;
}

export interface DataTableProps<T> {
  data: T[];
  columns: ColumnDef<T>[];
  rowKey: (row: T) => string;
  selectable?: boolean;
  selectedRowKeys?: string[];
  onSelectedRowKeysChange?: (keys: string[]) => void;
  onRowClick?: (row: T, index: number) => void;
  sortState?: SortState;
  onSortChange?: (sort: SortState) => void;
  isLoading?: boolean;
  emptyState?: React.ReactNode;
  density?: 'compact' | 'comfortable';
  maxHeight?: string | number;
  className?: string;
}

export function DataTable<T>({
  data,
  columns,
  rowKey,
  selectable = false,
  selectedRowKeys = [],
  onSelectedRowKeysChange,
  onRowClick,
  sortState,
  onSortChange,
  isLoading = false,
  emptyState,
  density: propDensity,
  maxHeight = '600px',
  className = '',
}: DataTableProps<T>) {
  const { density: contextDensity } = useTheme();
  const activeDensity = propDensity || contextDensity;

  // Density row heights: compact = 36px, comfortable = 44px
  const rowHeight = activeDensity === 'compact' ? 36 : 44;

  // Column widths state
  const [columnWidths, setColumnWidths] = useState<Record<string, number>>(() => {
    const initial: Record<string, number> = {};
    columns.forEach(col => {
      initial[col.id] = col.width || 150;
    });
    return initial;
  });

  // Column visibility state
  const [visibleColumns, setVisibleColumns] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    columns.forEach(col => {
      initial[col.id] = true;
    });
    return initial;
  });

  const [showVisibilityMenu, setShowVisibilityMenu] = useState(false);
  const [focusedRowIndex, setFocusedRowIndex] = useState<number>(-1);

  // Virtualization state (active when > 200 rows)
  const isVirtualized = data.length > 200;
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(500);

  // Handle scroll for virtualization
  const handleScroll = useCallback(() => {
    if (containerRef.current) {
      setScrollTop(containerRef.current.scrollTop);
    }
  }, []);

  useEffect(() => {
    if (containerRef.current) {
      setContainerHeight(containerRef.current.clientHeight);
    }
  }, [maxHeight]);

  // Virtual window calculation
  const totalRows = data.length;
  const totalHeight = totalRows * rowHeight;
  const bufferCount = 10;

  const { startIndex, endIndex } = useMemo(() => {
    if (!isVirtualized) {
      return { startIndex: 0, endIndex: totalRows };
    }
    const start = Math.max(0, Math.floor(scrollTop / rowHeight) - bufferCount);
    const visibleCount = Math.ceil(containerHeight / rowHeight);
    const end = Math.min(totalRows, start + visibleCount + bufferCount * 2);
    return { startIndex: start, endIndex: end };
  }, [isVirtualized, scrollTop, rowHeight, bufferCount, containerHeight, totalRows]);

  const visibleData = useMemo(() => {
    if (!isVirtualized) return data;
    return data.slice(startIndex, endIndex);
  }, [isVirtualized, data, startIndex, endIndex]);

  const activeColumns = useMemo(
    () => columns.filter(col => visibleColumns[col.id] !== false),
    [columns, visibleColumns]
  );

  // Resizing state & handlers
  const resizingRef = useRef<{
    colId: string;
    startX: number;
    startWidth: number;
    minWidth: number;
    maxWidth: number;
  } | null>(null);

  const handleResizeStart = (e: React.MouseEvent, col: ColumnDef<T>) => {
    e.preventDefault();
    e.stopPropagation();
    const currentWidth = columnWidths[col.id] || col.width || 150;
    resizingRef.current = {
      colId: col.id,
      startX: e.clientX,
      startWidth: currentWidth,
      minWidth: col.minWidth || 60,
      maxWidth: col.maxWidth || 800,
    };

    const handleMouseMove = (moveEvent: MouseEvent) => {
      if (!resizingRef.current) return;
      const deltaX = moveEvent.clientX - resizingRef.current.startX;
      const newWidth = Math.max(
        resizingRef.current.minWidth,
        Math.min(resizingRef.current.maxWidth, resizingRef.current.startWidth + deltaX)
      );
      setColumnWidths(prev => ({
        ...prev,
        [resizingRef.current!.colId]: newWidth,
      }));
    };

    const handleMouseUp = () => {
      resizingRef.current = null;
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
  };

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (data.length === 0) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setFocusedRowIndex(prev => {
        const next = Math.min(data.length - 1, prev + 1);
        // Scroll into view if needed
        if (containerRef.current) {
          const targetTop = next * rowHeight;
          if (targetTop > containerRef.current.scrollTop + containerHeight - rowHeight) {
            containerRef.current.scrollTop = targetTop - containerHeight + rowHeight * 2;
          }
        }
        return next;
      });
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setFocusedRowIndex(prev => {
        const next = Math.max(0, prev - 1);
        if (containerRef.current) {
          const targetTop = next * rowHeight;
          if (targetTop < containerRef.current.scrollTop) {
            containerRef.current.scrollTop = targetTop;
          }
        }
        return next;
      });
    } else if (e.key === ' ' || e.key === 'Enter') {
      if (focusedRowIndex >= 0 && focusedRowIndex < data.length) {
        e.preventDefault();
        const row = data[focusedRowIndex];
        const key = rowKey(row);

        if (e.key === ' ' && selectable && onSelectedRowKeysChange) {
          const isSelected = selectedRowKeys.includes(key);
          if (isSelected) {
            onSelectedRowKeysChange(selectedRowKeys.filter(k => k !== key));
          } else {
            onSelectedRowKeysChange([...selectedRowKeys, key]);
          }
        } else if (onRowClick) {
          onRowClick(row, focusedRowIndex);
        } else if (selectable && onSelectedRowKeysChange) {
          const isSelected = selectedRowKeys.includes(key);
          if (isSelected) {
            onSelectedRowKeysChange(selectedRowKeys.filter(k => k !== key));
          } else {
            onSelectedRowKeysChange([...selectedRowKeys, key]);
          }
        }
      }
    } else if (e.key === 'Home') {
      e.preventDefault();
      setFocusedRowIndex(0);
      if (containerRef.current) containerRef.current.scrollTop = 0;
    } else if (e.key === 'End') {
      e.preventDefault();
      setFocusedRowIndex(data.length - 1);
      if (containerRef.current) containerRef.current.scrollTop = totalHeight;
    }
  };

  // Select all logic
  const isAllSelected = data.length > 0 && selectedRowKeys.length === data.length;
  const isPartiallySelected = selectedRowKeys.length > 0 && selectedRowKeys.length < data.length;

  const handleSelectAll = (checked: boolean) => {
    if (!onSelectedRowKeysChange) return;
    if (checked) {
      onSelectedRowKeysChange(data.map(row => rowKey(row)));
    } else {
      onSelectedRowKeysChange([]);
    }
  };

  const handleSelectRow = (key: string, checked: boolean) => {
    if (!onSelectedRowKeysChange) return;
    if (checked) {
      onSelectedRowKeysChange([...selectedRowKeys, key]);
    } else {
      onSelectedRowKeysChange(selectedRowKeys.filter(k => k !== key));
    }
  };

  const handleSort = (colId: string) => {
    if (!onSortChange) return;
    if (sortState?.columnId === colId) {
      if (sortState.direction === 'asc') {
        onSortChange({ columnId: colId, direction: 'desc' });
      } else if (sortState.direction === 'desc') {
        onSortChange({ columnId: colId, direction: null });
      } else {
        onSortChange({ columnId: colId, direction: 'asc' });
      }
    } else {
      onSortChange({ columnId: colId, direction: 'asc' });
    }
  };

  return (
    <div
      className={`relative w-full flex flex-col rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-panel)] overflow-hidden ${className}`}
      onKeyDown={handleKeyDown}
      tabIndex={0}
      role="region"
      aria-label="Data table"
    >
      {/* Table toolbar / Column visibility toggle */}
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[var(--border-subtle)] bg-[var(--bg-inset)]/60 text-xs">
        <div className="flex items-center gap-2">
          {selectable && (
            <span className="text-[11px] text-[var(--text-secondary)] font-mono tabular-nums">
              {selectedRowKeys.length} selected
            </span>
          )}
          {isVirtualized && (
            <span className="text-[10px] text-blue-500 font-mono px-1.5 py-0.5 rounded bg-blue-500/10">
              Virtualized ({data.length} rows)
            </span>
          )}
        </div>

        {/* Column visibility menu toggle */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setShowVisibilityMenu(!showVisibilityMenu)}
            className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-[11px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] border border-[var(--border-subtle)]"
          >
            <Columns className="w-3 h-3" />
            <span>Columns</span>
          </button>

          {showVisibilityMenu && (
            <div className="absolute right-0 top-full mt-1 w-48 rounded-md border border-[var(--border-strong)] bg-[var(--bg-elevated)] p-2 shadow-xl z-50 animate-in fade-in zoom-in-95">
              <div className="text-[11px] font-semibold text-[var(--text-primary)] pb-1 mb-1 border-b border-[var(--border-subtle)]">
                Toggle Columns
              </div>
              <div className="flex flex-col gap-1 max-h-48 overflow-y-auto">
                {columns.map(col => {
                  if (col.enableHiding === false) return null;
                  const isVisible = visibleColumns[col.id] !== false;

                  return (
                    <label
                      key={col.id}
                      className="flex items-center justify-between text-xs px-1.5 py-1 rounded hover:bg-[var(--bg-panel)] cursor-pointer select-none"
                    >
                      <span className="truncate text-[var(--text-secondary)]">
                        {typeof col.header === 'string' ? col.header : col.id}
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          setVisibleColumns(prev => ({
                            ...prev,
                            [col.id]: !isVisible,
                          }))
                        }
                        className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)]"
                      >
                        {isVisible ? <Eye className="w-3.5 h-3.5 text-blue-500" /> : <EyeOff className="w-3.5 h-3.5" />}
                      </button>
                    </label>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Main Table Container */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        style={{ maxHeight }}
        className="w-full overflow-auto relative focus:outline-none"
      >
        <table className="w-full border-collapse text-left text-xs">
          {/* Sticky Header */}
          <thead className="sticky top-0 z-20 bg-[var(--bg-panel)] shadow-xs select-none">
            <tr className="border-b border-[var(--border-strong)]">
              {selectable && (
                <th
                  style={{ width: 40 }}
                  className="sticky left-0 z-30 bg-[var(--bg-panel)] px-3 py-2 text-center"
                >
                  <Checkbox
                    checked={isAllSelected}
                    indeterminate={isPartiallySelected}
                    onChange={e => handleSelectAll(e.target.checked)}
                    aria-label="Select all rows"
                  />
                </th>
              )}

              {activeColumns.map((col, idx) => {
                const width = columnWidths[col.id] || col.width || 150;
                const isFirstCol = idx === 0 && !selectable;
                const isSorted = sortState?.columnId === col.id;

                return (
                  <th
                    key={col.id}
                    style={{ width, minWidth: col.minWidth || 60 }}
                    className={`relative px-3 py-2 text-xs font-semibold text-[var(--text-secondary)] tracking-wider uppercase border-b border-[var(--border-strong)] ${
                      isFirstCol ? 'sticky left-0 z-30 bg-[var(--bg-panel)] shadow-r' : ''
                    }`}
                  >
                    <div
                      className={`flex items-center justify-between gap-1.5 ${
                        col.sortable ? 'cursor-pointer hover:text-[var(--text-primary)]' : ''
                      }`}
                      onClick={() => col.sortable && handleSort(col.id)}
                    >
                      <span className="truncate">{col.header}</span>
                      {col.sortable && (
                        <span className="shrink-0 text-[var(--text-tertiary)]">
                          {isSorted && sortState.direction === 'asc' ? (
                            <ChevronUp className="w-3.5 h-3.5 text-blue-500" />
                          ) : isSorted && sortState.direction === 'desc' ? (
                            <ChevronDown className="w-3.5 h-3.5 text-blue-500" />
                          ) : (
                            <ChevronsUpDown className="w-3 h-3 opacity-40 hover:opacity-100" />
                          )}
                        </span>
                      )}
                    </div>

                    {/* Resizer handle */}
                    {col.enableResizing !== false && (
                      <div
                        onMouseDown={e => handleResizeStart(e, col)}
                        className="absolute right-0 top-0 bottom-0 w-1.5 cursor-col-resize hover:bg-blue-500/50 transition-colors z-40 select-none"
                      />
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>

          {/* Table Body */}
          <tbody className="divide-y divide-[var(--border-subtle)]">
            {isLoading ? (
              // Loading Skeleton Rows
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={`skeleton-${i}`} style={{ height: rowHeight }}>
                  {selectable && (
                    <td className="px-3 py-1.5 text-center">
                      <Skeleton variant="rectangular" width={16} height={16} />
                    </td>
                  )}
                  {activeColumns.map((col, cIdx) => (
                    <td key={`skel-col-${cIdx}`} className="px-3 py-1.5">
                      <Skeleton variant="text" width={cIdx === 0 ? '70%' : '50%'} />
                    </td>
                  ))}
                </tr>
              ))
            ) : data.length === 0 ? (
              // Empty State
              <tr>
                <td
                  colSpan={activeColumns.length + (selectable ? 1 : 0)}
                  className="py-12 px-4 text-center"
                >
                  {emptyState || <EmptyState title="No records found" description="No data matches the selected criteria." />}
                </td>
              </tr>
            ) : (
              <>
                {/* Virtualized top spacer */}
                {isVirtualized && startIndex > 0 && (
                  <tr style={{ height: startIndex * rowHeight }}>
                    <td colSpan={activeColumns.length + (selectable ? 1 : 0)} />
                  </tr>
                )}

                {/* Rendered row window */}
                {visibleData.map((row, relativeIdx) => {
                  const absoluteIdx = isVirtualized ? startIndex + relativeIdx : relativeIdx;
                  const key = rowKey(row);
                  const isSelected = selectedRowKeys.includes(key);
                  const isFocused = focusedRowIndex === absoluteIdx;

                  return (
                    <tr
                      key={key}
                      style={{ height: rowHeight }}
                      onClick={() => onRowClick?.(row, absoluteIdx)}
                      className={`transition-colors select-none group cursor-pointer ${
                        isSelected
                          ? 'bg-blue-500/10 hover:bg-blue-500/15'
                          : isFocused
                          ? 'bg-[var(--bg-elevated)] ring-1 ring-inset ring-blue-500'
                          : 'hover:bg-[var(--bg-elevated)]/60'
                      }`}
                    >
                      {selectable && (
                        <td
                          style={{ width: 40 }}
                          onClick={e => e.stopPropagation()}
                          className="sticky left-0 z-10 bg-[var(--bg-panel)] group-hover:bg-[var(--bg-elevated)] px-3 py-1.5 text-center"
                        >
                          <Checkbox
                            checked={isSelected}
                            onChange={e => handleSelectRow(key, e.target.checked)}
                            aria-label={`Select row ${absoluteIdx + 1}`}
                          />
                        </td>
                      )}

                      {activeColumns.map((col, cIdx) => {
                        const width = columnWidths[col.id] || col.width || 150;
                        const isFirstCol = cIdx === 0 && !selectable;

                        return (
                          <td
                            key={col.id}
                            style={{ width }}
                            className={`px-3 py-1 text-xs text-[var(--text-primary)] truncate ${
                              isFirstCol
                                ? 'sticky left-0 z-10 bg-[var(--bg-panel)] group-hover:bg-[var(--bg-elevated)] shadow-r font-medium'
                                : ''
                            }`}
                          >
                            {col.cell(row, absoluteIdx)}
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}

                {/* Virtualized bottom spacer */}
                {isVirtualized && endIndex < totalRows && (
                  <tr style={{ height: (totalRows - endIndex) * rowHeight }}>
                    <td colSpan={activeColumns.length + (selectable ? 1 : 0)} />
                  </tr>
                )}
              </>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
