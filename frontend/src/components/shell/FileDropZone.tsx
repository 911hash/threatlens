import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, X } from 'lucide-react';
import { Button } from '../primitives/Button';

export interface FileDropZoneProps {
  onFileSelect: (file: File) => void;
  accept?: string;
  maxSizeBytes?: number;
  disabled?: boolean;
  className?: string;
}

export const FileDropZone: React.FC<FileDropZoneProps> = ({
  onFileSelect,
  accept,
  maxSizeBytes = 32 * 1024 * 1024, // 32MB default
  disabled = false,
  className = '',
}) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (!disabled) setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const validateAndProcessFile = (file: File) => {
    setError(null);
    if (maxSizeBytes && file.size > maxSizeBytes) {
      setError(`File exceeds maximum size (${(maxSizeBytes / (1024 * 1024)).toFixed(0)}MB)`);
      return;
    }
    setSelectedFile(file);
    onFileSelect(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (disabled) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndProcessFile(e.dataTransfer.files[0]);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndProcessFile(e.target.files[0]);
    }
  };

  const clearFile = (e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedFile(null);
    setError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={() => !disabled && fileInputRef.current?.click()}
      className={`relative flex flex-col items-center justify-center p-6 rounded-xl border-2 border-dashed transition-all cursor-pointer text-center select-none ${
        disabled
          ? 'opacity-50 cursor-not-allowed bg-[var(--bg-inset)] border-[var(--border-subtle)]'
          : isDragOver
          ? 'border-blue-500 bg-blue-500/10'
          : selectedFile
          ? 'border-emerald-500/40 bg-emerald-500/5'
          : 'border-[var(--border-strong)] hover:border-blue-500/60 bg-[var(--bg-inset)]/50 hover:bg-[var(--bg-panel)]'
      } ${className}`}
    >
      <input
        ref={fileInputRef}
        type="file"
        accept={accept}
        disabled={disabled}
        onChange={handleInputChange}
        className="sr-only"
      />

      {selectedFile ? (
        <div className="flex flex-col items-center gap-2">
          <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-500">
            <FileText className="w-6 h-6 stroke-[1.5]" />
          </div>
          <div className="flex flex-col">
            <span className="text-xs font-semibold text-[var(--text-primary)] max-w-xs truncate">
              {selectedFile.name}
            </span>
            <span className="text-[11px] font-mono text-[var(--text-tertiary)]">
              {formatFileSize(selectedFile.size)}
            </span>
          </div>
          <Button
            variant="tertiary"
            size="xs"
            leftIcon={<X className="w-3 h-3" />}
            onClick={clearFile}
            className="mt-1"
          >
            Remove file
          </Button>
        </div>
      ) : (
        <div className="flex flex-col items-center gap-2">
          <div className="w-12 h-12 rounded-full bg-[var(--bg-panel)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--text-tertiary)]">
            <UploadCloud className="w-6 h-6 stroke-[1.5]" />
          </div>
          <div>
            <p className="text-xs font-medium text-[var(--text-primary)]">
              Drag & drop suspicious file, or <span className="text-blue-500 underline">browse</span>
            </p>
            <p className="text-[11px] text-[var(--text-tertiary)] mt-0.5">
              Files are hashed locally; contents never leave your browser without consent (Max 32MB)
            </p>
          </div>
        </div>
      )}

      {error && (
        <div className="mt-3 text-xs text-red-500 font-medium">
          {error}
        </div>
      )}
    </div>
  );
};
