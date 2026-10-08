import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { ThemeProvider } from './design/ThemeContext';
import { DefangProvider } from './design/DefangContext';
import { SidebarProvider } from './context/SidebarContext';
import { DrawerProvider } from './context/DrawerContext';
import { CommandPaletteProvider } from './context/CommandPaletteContext';
import { ToastProvider } from './components/primitives/Toast';
import { CopyWarningBridge } from './components/shell/CopyWarningBridge';
import { ErrorBoundary } from './components/shell/ErrorBoundary';
import { AppShell } from './components/shell/AppShell';

export default function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <DefangProvider>
          <SidebarProvider>
            <DrawerProvider>
              <CommandPaletteProvider>
                <ToastProvider>
                  <CopyWarningBridge />
                  <BrowserRouter>
                    <AppShell />
                  </BrowserRouter>
                </ToastProvider>
              </CommandPaletteProvider>
            </DrawerProvider>
          </SidebarProvider>
        </DefangProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}
