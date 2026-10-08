import React, { useState, useRef, useEffect, useId } from 'react';
import { Check, ChevronDown, Search, X } from 'lucide-react';

export interface ComboboxOption {
  value: string;
  label: string;
  description?: string;
  icon?: React.ReactNode;
}

export interface ComboboxProps {
  options: ComboboxOption[];
  value: string[];
  onChange: (value: string[]) => void;
  placeholder?: string;
  label?: string;
  searchPlaceholder?: string;
  multiple?: boolean;
  disabled?: boolean;
  error?: string | boolean;
  className?: string;
}

export const Combobox: React.FC<ComboboxProps> = ({
  options,
  value,
  onChange,
  placeholder = 'Select options...',
  label,
  searchPlaceholder = 'Filter...',
  multiple = true,
  disabled = false,
  error,
  className = '',
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [highlightedIndex, setHighlightedIndex] = useState(0);

  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const id = useId();

  const filteredOptions = options.filter(opt =>
    opt.label.toLowerCase().includes(search.toLowerCase()) ||
    (opt.description && opt.description.toLowerCase().includes(search.toLowerCase()))
  );

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const toggleOption = (optValue: string) => {
    if (multiple) {
      if (value.includes(optValue)) {
        onChange(value.filter(v => v !== optValue));
      } else {
        onChange([...value, optValue]);
      }
    } else {
      onChange([optValue]);
      setIsOpen(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (disabled) return;

    if (!isOpen) {
      if (e.key === 'Enter' || e.key === 'ArrowDown' || e.key === ' ') {
        e.preventDefault();
        setIsOpen(true);
        setTimeout(() => inputRef.current?.focus(), 50);
      }
      return;
    }

    if (e.key === 'Escape') {
      e.preventDefault();
      setIsOpen(false);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHighlightedIndex(prev => (prev + 1) % (filteredOptions.length || 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHighlightedIndex(prev => (prev - 1 + filteredOptions.length) % (filteredOptions.length || 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const current = filteredOptions[highlightedIndex];
      if (current) {
        toggleOption(current.value);
      }
    }
  };

  const selectedLabels = options
    .filter(opt => value.includes(opt.value))
    .map(opt => opt.label);

  return (
    <div className={`w-full flex flex-col gap-1 ${className}`} ref={containerRef}>
      {label && (
        <label htmlFor={id} className="text-xs font-medium text-[var(--text-secondary)] select-none">
          {label}
        </label>
      )}

      <div className="relative w-full">
        <button
          id={id}
          type="button"
          disabled={disabled}
          onClick={() => {
            if (!disabled) {
              setIsOpen(!isOpen);
              setTimeout(() => inputRef.current?.focus(), 50);
            }
          }}
          onKeyDown={handleKeyDown}
          className={`w-full h-8 px-2.5 rounded border text-xs flex items-center justify-between text-left transition-colors bg-[var(--bg-inset)] hover:bg-[var(--bg-panel)] focus-visible:outline-none focus-visible:ring-1 ${
            error
              ? 'border-red-500 focus-visible:ring-red-500'
              : 'border-[var(--border-subtle)] focus-visible:border-blue-500 focus-visible:ring-blue-500'
          } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
        >
          <div className="flex items-center gap-1.5 truncate">
            {selectedLabels.length === 0 ? (
              <span className="text-[var(--text-tertiary)]">{placeholder}</span>
            ) : multiple ? (
              <div className="flex items-center gap-1 truncate">
                <span className="font-medium text-[var(--text-primary)]">
                  {selectedLabels.length} selected
                </span>
                <span className="text-[var(--text-tertiary)] truncate">
                  ({selectedLabels.slice(0, 2).join(', ')}{selectedLabels.length > 2 ? '...' : ''})
                </span>
              </div>
            ) : (
              <span className="font-medium text-[var(--text-primary)]">{selectedLabels[0]}</span>
            )}
          </div>
          <ChevronDown className="w-3.5 h-3.5 text-[var(--text-tertiary)] shrink-0 ml-1.5" />
        </button>

        {isOpen && (
          <div className="absolute left-0 top-full mt-1 w-full min-w-[200px] rounded-md border border-[var(--border-strong)] bg-[var(--bg-elevated)] shadow-lg z-50 py-1.5 animate-in fade-in-50">
            <div className="px-2 pb-1.5 border-b border-[var(--border-subtle)]">
              <div className="relative flex items-center">
                <Search className="w-3 h-3 absolute left-2 text-[var(--text-tertiary)] pointer-events-none" />
                <input
                  ref={inputRef}
                  value={search}
                  onChange={e => {
                    setSearch(e.target.value);
                    setHighlightedIndex(0);
                  }}
                  onKeyDown={handleKeyDown}
                  placeholder={searchPlaceholder}
                  className="w-full h-7 pl-6 pr-6 rounded bg-[var(--bg-inset)] text-xs text-[var(--text-primary)] placeholder:text-[var(--text-tertiary)] border border-[var(--border-subtle)] focus:outline-none focus:border-blue-500"
                />
                {search && (
                  <button
                    onClick={() => setSearch('')}
                    className="absolute right-2 text-[var(--text-tertiary)] hover:text-[var(--text-primary)]"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
            </div>

            <div className="max-h-48 overflow-y-auto py-1">
              {filteredOptions.length === 0 ? (
                <div className="px-3 py-2 text-xs text-[var(--text-tertiary)] text-center">
                  No options found
                </div>
              ) : (
                filteredOptions.map((opt, idx) => {
                  const isSelected = value.includes(opt.value);
                  const isHighlighted = idx === highlightedIndex;

                  return (
                    <div
                      key={opt.value}
                      onClick={() => toggleOption(opt.value)}
                      onMouseEnter={() => setHighlightedIndex(idx)}
                      className={`px-2.5 py-1.5 text-xs flex items-center justify-between cursor-pointer select-none transition-colors ${
                        isHighlighted ? 'bg-[var(--bg-panel)]' : ''
                      } ${isSelected ? 'text-blue-500 font-medium' : 'text-[var(--text-primary)]'}`}
                    >
                      <div className="flex items-center gap-2 truncate">
                        {opt.icon && <span className="shrink-0">{opt.icon}</span>}
                        <span className="truncate">{opt.label}</span>
                        {opt.description && (
                          <span className="text-[10px] text-[var(--text-tertiary)] truncate">
                            {opt.description}
                          </span>
                        )}
                      </div>
                      {isSelected && <Check className="w-3.5 h-3.5 text-blue-500 shrink-0" />}
                    </div>
                  );
                })
              )}
            </div>

            {multiple && (
              <div className="px-2 pt-1 border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px]">
                <button
                  type="button"
                  onClick={() => onChange(options.map(o => o.value))}
                  className="text-blue-500 hover:underline"
                >
                  Select all
                </button>
                <button
                  type="button"
                  onClick={() => onChange([])}
                  className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)]"
                >
                  Clear all
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
