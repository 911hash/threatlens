import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { IconButton } from './IconButton';

export interface PaginationProps {
  page: number;
  pageSize: number;
  totalItems: number;
  onPageChange: (newPage: number) => void;
  onPageSizeChange?: (newPageSize: number) => void;
  pageSizeOptions?: number[];
  className?: string;
}

export const Pagination: React.FC<PaginationProps> = ({
  page,
  pageSize,
  totalItems,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [10, 20, 50, 100],
  className = '',
}) => {
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const startItem = totalItems === 0 ? 0 : (page - 1) * pageSize + 1;
  const endItem = Math.min(page * pageSize, totalItems);

  return (
    <div
      className={`flex flex-wrap items-center justify-between gap-3 text-xs text-[var(--text-secondary)] py-2 ${className}`}
    >
      <div className="flex items-center gap-2">
        <span>
          Showing <span className="font-medium text-[var(--text-primary)]">{startItem}</span> to{' '}
          <span className="font-medium text-[var(--text-primary)]">{endItem}</span> of{' '}
          <span className="font-medium text-[var(--text-primary)]">{totalItems}</span>
        </span>

        {onPageSizeChange && (
          <div className="flex items-center gap-1.5 ml-3">
            <span>Per page:</span>
            <select
              value={pageSize}
              onChange={e => onPageSizeChange(Number(e.target.value))}
              className="h-6 rounded border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-1.5 text-xs text-[var(--text-primary)] focus:outline-none focus:border-blue-500"
            >
              {pageSizeOptions.map(sz => (
                <option key={sz} value={sz}>
                  {sz}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div className="flex items-center gap-1.5">
        <IconButton
          icon={<ChevronLeft className="w-3.5 h-3.5" />}
          aria-label="Previous page"
          size="xs"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
        />
        <span className="px-2 font-mono tabular-nums text-xs">
          Page {page} / {totalPages}
        </span>
        <IconButton
          icon={<ChevronRight className="w-3.5 h-3.5" />}
          aria-label="Next page"
          size="xs"
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
        />
      </div>
    </div>
  );
};
