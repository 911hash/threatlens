import React, { createContext, useContext, useEffect, useMemo } from 'react';
import type { ThemeMode, DensityMode } from './tokens';
import { useLocalStorage } from '../hooks/useLocalStorage';
import { usePrefersReducedMotion } from '../hooks/usePrefersReducedMotion';

interface ThemeContextType {
  theme: ThemeMode;
  setTheme: (theme: ThemeMode) => void;
  toggleTheme: () => void;
  density: DensityMode;
  setDensity: (density: DensityMode) => void;
  toggleDensity: () => void;
  reducedMotion: boolean;
  setReducedMotion: (reduced: boolean) => void;
  toggleReducedMotion: () => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setTheme] = useLocalStorage<ThemeMode>('threatlens_theme_pref', 'dark');
  const [density, setDensity] = useLocalStorage<DensityMode>('threatlens_density_pref', 'compact');
  const [reducedMotionPref, setReducedMotionPref] = useLocalStorage<boolean>('threatlens_motion_pref', false);
  const osReducedMotion = usePrefersReducedMotion();

  // URL query parameter theme override
  useEffect(() => {
    try {
      const urlTheme = new URLSearchParams(window.location.search).get('theme');
      if (urlTheme === 'light' || urlTheme === 'dark') {
        setTheme(urlTheme as ThemeMode);
      }
    } catch {
      // Ignore URL parse errors
    }
  }, []);

  const isReducedMotion = reducedMotionPref || osReducedMotion;

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
    if (theme === 'dark') {
      root.classList.add('dark');
      root.classList.remove('light');
    } else {
      root.classList.add('light');
      root.classList.remove('dark');
    }
  }, [theme]);

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute('data-density', density);
  }, [density]);

  useEffect(() => {
    const root = document.documentElement;
    if (isReducedMotion) {
      root.classList.add('reduced-motion');
    } else {
      root.classList.remove('reduced-motion');
    }
  }, [isReducedMotion]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  const toggleDensity = () => {
    setDensity(prev => (prev === 'compact' ? 'comfortable' : 'compact'));
  };

  const toggleReducedMotion = () => {
    setReducedMotionPref(prev => !prev);
  };

  const setReducedMotion = (val: boolean) => {
    setReducedMotionPref(val);
  };

  const value = useMemo(
    () => ({
      theme,
      setTheme,
      toggleTheme,
      density,
      setDensity,
      toggleDensity,
      reducedMotion: isReducedMotion,
      setReducedMotion,
      toggleReducedMotion,
    }),
    [theme, density, isReducedMotion]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
};

export function useTheme(): ThemeContextType {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
}
