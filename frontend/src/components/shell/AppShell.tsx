import React, { Suspense } from 'react';
import { Routes, Route } from 'react-router-dom';
import { useDrawer } from '../../context/DrawerContext';
import { useCommandPalette } from '../../context/CommandPaletteContext';
import { useKeyboardShortcut } from '../../hooks/useKeyboardShortcut';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { DetailDrawer } from './DetailDrawer';
import { CommandPalette } from './CommandPalette';
import { SkipLink } from './SkipLink';
import { ErrorBoundary } from './ErrorBoundary';
import {
  DashboardSkeleton,
  AnalyzeSkeleton,
  InvestigationsSkeleton,
  ReportSkeleton,
  CompareSkeleton,
  WatchlistSkeleton,
  AlertsSkeleton,
  SettingsSkeleton,
} from './PageSkeletons';

// Route-Level Code Splitting (React.lazy)
const DashboardPage = React.lazy(() => import('../../pages/DashboardPage').then(m => ({ default: m.DashboardPage })));
const AnalyzePage = React.lazy(() => import('../../pages/AnalyzePage').then(m => ({ default: m.AnalyzePage })));
const InvestigationsPage = React.lazy(() => import('../../pages/HistoryPage').then(m => ({ default: m.InvestigationsPage })));
const ResultPage = React.lazy(() => import('../../pages/ResultPage').then(m => ({ default: m.ResultPage })));
const ComparePage = React.lazy(() => import('../../pages/ComparePage').then(m => ({ default: m.ComparePage })));
const WatchlistPage = React.lazy(() => import('../../pages/WatchlistPage').then(m => ({ default: m.WatchlistPage })));
const AlertsPage = React.lazy(() => import('../../pages/AlertsPage').then(m => ({ default: m.AlertsPage })));
const SettingsPage = React.lazy(() => import('../../pages/SettingsPage').then(m => ({ default: m.SettingsPage })));
const DesignSystemPage = React.lazy(() => import('../../pages/DesignSystemPage').then(m => ({ default: m.DesignSystemPage })));
const NotFoundPage = React.lazy(() => import('../../pages/NotFoundPage').then(m => ({ default: m.NotFoundPage })));

export const AppShell: React.FC = () => {
  const drawer = useDrawer();
  const palette = useCommandPalette();

  // Global Keyboard Shortcuts
  // 1. Cmd/Ctrl+K -> toggle command palette
  useKeyboardShortcut('mod+k', () => {
    palette.toggle();
  });

  // 2. '/' -> open command palette when not inside input
  useKeyboardShortcut('/', () => {
    palette.open();
  });

  // 3. Escape -> close drawer, then palette
  useKeyboardShortcut(
    'Escape',
    () => {
      if (drawer.isOpen) {
        drawer.close();
      } else if (palette.isOpen) {
        palette.close();
      }
    },
    { enabled: drawer.isOpen || palette.isOpen }
  );

  return (
    <>
      <SkipLink targetId="main-content" />
      <CommandPalette />
      <DetailDrawer />

      <div className="flex min-h-screen max-w-full bg-[var(--bg-base)] text-[var(--text-primary)] font-sans transition-colors overflow-x-hidden">
        {/* Responsive / Collapsible Sidebar */}
        <Sidebar />

        {/* Content Area with Sticky TopBar */}
        <div className="flex-1 min-w-0 flex flex-col h-screen overflow-hidden">
          <TopBar />

          {/* Independent Scroll Main Container */}
          <main
            id="main-content"
            tabIndex={-1}
            className="flex-1 min-w-0 overflow-y-auto overflow-x-hidden focus:outline-none"
          >
            <ErrorBoundary>
              <Routes>
                {/* Overview / Dashboard aliases */}
                <Route
                  path="/"
                  element={
                    <Suspense fallback={<DashboardSkeleton />}>
                      <DashboardPage />
                    </Suspense>
                  }
                />
                <Route
                  path="/dashboard"
                  element={
                    <Suspense fallback={<DashboardSkeleton />}>
                      <DashboardPage />
                    </Suspense>
                  }
                />
                <Route
                  path="/overview"
                  element={
                    <Suspense fallback={<DashboardSkeleton />}>
                      <DashboardPage />
                    </Suspense>
                  }
                />

                {/* Investigations / Scans / History aliases */}
                <Route
                  path="/scans"
                  element={
                    <Suspense fallback={<InvestigationsSkeleton />}>
                      <InvestigationsPage />
                    </Suspense>
                  }
                />
                <Route
                  path="/history"
                  element={
                    <Suspense fallback={<InvestigationsSkeleton />}>
                      <InvestigationsPage />
                    </Suspense>
                  }
                />
                <Route
                  path="/investigations"
                  element={
                    <Suspense fallback={<InvestigationsSkeleton />}>
                      <InvestigationsPage />
                    </Suspense>
                  }
                />

                {/* Analyze with tab segment aliases */}
                <Route
                  path="/analyze"
                  element={
                    <Suspense fallback={<AnalyzeSkeleton />}>
                      <AnalyzePage />
                    </Suspense>
                  }
                />
                <Route
                  path="/analyze/url"
                  element={
                    <Suspense fallback={<AnalyzeSkeleton />}>
                      <AnalyzePage />
                    </Suspense>
                  }
                />
                <Route
                  path="/analyze/hash"
                  element={
                    <Suspense fallback={<AnalyzeSkeleton />}>
                      <AnalyzePage />
                    </Suspense>
                  }
                />
                <Route
                  path="/analyze/file"
                  element={
                    <Suspense fallback={<AnalyzeSkeleton />}>
                      <AnalyzePage />
                    </Suspense>
                  }
                />

                {/* Scans & Comparisons */}
                <Route
                  path="/scan/:id"
                  element={
                    <Suspense fallback={<ReportSkeleton />}>
                      <ResultPage />
                    </Suspense>
                  }
                />
                <Route
                  path="/scans/:id"
                  element={
                    <Suspense fallback={<ReportSkeleton />}>
                      <ResultPage />
                    </Suspense>
                  }
                />
                <Route
                  path="/compare/:id1/:id2"
                  element={
                    <Suspense fallback={<CompareSkeleton />}>
                      <ComparePage />
                    </Suspense>
                  }
                />
                <Route
                  path="/compare"
                  element={
                    <Suspense fallback={<CompareSkeleton />}>
                      <ComparePage />
                    </Suspense>
                  }
                />

                {/* Watchlist */}
                <Route
                  path="/watchlist"
                  element={
                    <Suspense fallback={<WatchlistSkeleton />}>
                      <WatchlistPage />
                    </Suspense>
                  }
                />

                {/* New Routes */}
                <Route
                  path="/alerts"
                  element={
                    <Suspense fallback={<AlertsSkeleton />}>
                      <AlertsPage />
                    </Suspense>
                  }
                />
                <Route
                  path="/settings"
                  element={
                    <Suspense fallback={<SettingsSkeleton />}>
                      <SettingsPage />
                    </Suspense>
                  }
                />

                {/* Development Catalog */}
                <Route
                  path="/design-system"
                  element={
                    <Suspense fallback={<DashboardSkeleton />}>
                      <DesignSystemPage />
                    </Suspense>
                  }
                />

                {/* 404 Catch-All */}
                <Route
                  path="*"
                  element={
                    <Suspense fallback={<DashboardSkeleton />}>
                      <NotFoundPage />
                    </Suspense>
                  }
                />
              </Routes>
            </ErrorBoundary>
          </main>
        </div>
      </div>
    </>
  );
};
