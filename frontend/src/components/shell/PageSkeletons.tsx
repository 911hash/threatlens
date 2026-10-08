import React from 'react';
import { Skeleton } from '../primitives/Skeleton';

export const DashboardSkeleton: React.FC = () => (
  <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 space-y-8 animate-in fade-in duration-150">
    <div className="space-y-3">
      <Skeleton className="h-8 w-64 rounded-lg" />
      <Skeleton className="h-4 w-96 rounded" />
    </div>
    <Skeleton className="h-16 w-full rounded-2xl" />
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <Skeleton className="h-28 rounded-2xl" />
      <Skeleton className="h-28 rounded-2xl" />
      <Skeleton className="h-28 rounded-2xl" />
      <Skeleton className="h-28 rounded-2xl" />
    </div>
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <Skeleton className="lg:col-span-2 h-72 rounded-2xl" />
      <Skeleton className="h-72 rounded-2xl" />
    </div>
  </div>
);

export const AnalyzeSkeleton: React.FC = () => (
  <div className="max-w-4xl mx-auto py-8 px-4 space-y-6 animate-in fade-in duration-150">
    <div className="space-y-2">
      <Skeleton className="h-8 w-56 rounded-lg" />
      <Skeleton className="h-4 w-80 rounded" />
    </div>
    <Skeleton className="h-12 w-full max-w-md rounded-xl" />
    <Skeleton className="h-64 w-full rounded-2xl" />
  </div>
);

export const InvestigationsSkeleton: React.FC = () => (
  <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 space-y-6 animate-in fade-in duration-150">
    <div className="flex justify-between items-center">
      <Skeleton className="h-8 w-64 rounded-lg" />
      <Skeleton className="h-8 w-32 rounded-lg" />
    </div>
    <Skeleton className="h-16 w-full rounded-2xl" />
    <div className="p-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-3">
      <Skeleton className="h-10 w-full rounded-lg" />
      <Skeleton className="h-12 w-full rounded-lg" />
      <Skeleton className="h-12 w-full rounded-lg" />
      <Skeleton className="h-12 w-full rounded-lg" />
      <Skeleton className="h-12 w-full rounded-lg" />
      <Skeleton className="h-12 w-full rounded-lg" />
    </div>
  </div>
);

export const ReportSkeleton: React.FC = () => (
  <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 space-y-6 animate-in fade-in duration-150">
    <div className="flex justify-between items-center">
      <Skeleton className="h-8 w-72 rounded-lg" />
      <Skeleton className="h-8 w-40 rounded-lg" />
    </div>
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      <Skeleton className="h-48 rounded-2xl" />
      <Skeleton className="h-48 rounded-2xl" />
      <Skeleton className="h-48 rounded-2xl" />
    </div>
    <Skeleton className="h-80 w-full rounded-2xl" />
  </div>
);

export const CompareSkeleton: React.FC = () => (
  <div className="max-w-6xl mx-auto py-8 px-4 space-y-6 animate-in fade-in duration-150">
    <div className="flex justify-between items-center">
      <Skeleton className="h-8 w-64 rounded-lg" />
      <Skeleton className="h-8 w-48 rounded-lg" />
    </div>
    <Skeleton className="h-32 w-full rounded-2xl" />
    <Skeleton className="h-64 w-full rounded-2xl" />
  </div>
);

export const WatchlistSkeleton: React.FC = () => (
  <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 space-y-6 animate-in fade-in duration-150">
    <div className="flex justify-between items-center">
      <Skeleton className="h-8 w-56 rounded-lg" />
      <Skeleton className="h-8 w-32 rounded-lg" />
    </div>
    <Skeleton className="h-12 w-full rounded-2xl" />
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      <Skeleton className="h-44 rounded-2xl" />
      <Skeleton className="h-44 rounded-2xl" />
      <Skeleton className="h-44 rounded-2xl" />
      <Skeleton className="h-44 rounded-2xl" />
      <Skeleton className="h-44 rounded-2xl" />
      <Skeleton className="h-44 rounded-2xl" />
    </div>
  </div>
);

export const AlertsSkeleton: React.FC = () => (
  <div className="max-w-5xl mx-auto py-8 px-4 space-y-6 animate-in fade-in duration-150">
    <div className="flex justify-between items-center">
      <Skeleton className="h-8 w-48 rounded-lg" />
      <Skeleton className="h-8 w-36 rounded-lg" />
    </div>
    <Skeleton className="h-12 w-full rounded-2xl" />
    <div className="space-y-3">
      <Skeleton className="h-20 w-full rounded-xl" />
      <Skeleton className="h-20 w-full rounded-xl" />
      <Skeleton className="h-20 w-full rounded-xl" />
      <Skeleton className="h-20 w-full rounded-xl" />
    </div>
  </div>
);

export const SettingsSkeleton: React.FC = () => (
  <div className="max-w-5xl mx-auto py-8 px-4 space-y-6 animate-in fade-in duration-150">
    <Skeleton className="h-8 w-48 rounded-lg" />
    <Skeleton className="h-44 w-full rounded-2xl" />
    <Skeleton className="h-44 w-full rounded-2xl" />
    <Skeleton className="h-44 w-full rounded-2xl" />
  </div>
);
