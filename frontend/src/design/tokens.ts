export type ThemeMode = 'dark' | 'light';
export type DensityMode = 'compact' | 'comfortable';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'unknown';

export interface SeverityToken {
  level: SeverityLevel;
  label: string;
  text: string;
  bg: string;
  border: string;
  solid: string;
  badgeClass: string;
}

export interface SurfaceTokens {
  base: string;
  panel: string;
  elevated: string;
  inset: string;
  visual: string;
}

export interface BorderTokens {
  subtle: string;
  strong: string;
}

export interface TextTokens {
  primary: string;
  secondary: string;
  tertiary: string;
}

export interface AccentTokens {
  primary: string;
  hover: string;
  active: string;
  subtle: string;
  border: string;
}

export const SURFACES: Record<ThemeMode, SurfaceTokens> = {
  dark: {
    base: '#0A0B0D',
    panel: '#121417',
    elevated: '#1A1D21',
    inset: '#08090A',
    visual: '#0E1013',
  },
  light: {
    base: '#FFFFFF',
    panel: '#F6F8FA',
    elevated: '#FFFFFF',
    inset: '#EAEEF2',
    visual: '#FFFFFF',
  },
};

export const BORDERS: Record<ThemeMode, BorderTokens> = {
  dark: {
    subtle: '#1F2328',
    strong: '#2E343B',
  },
  light: {
    subtle: '#D0D7DE',
    strong: '#AFB8C1',
  },
};

export const TEXT_TOKENS: Record<ThemeMode, TextTokens> = {
  dark: {
    primary: '#E6E8EB',
    secondary: '#9BA1A8',
    tertiary: '#6B7280',
  },
  light: {
    primary: '#1F2328',
    secondary: '#57606A',
    tertiary: '#6E7781',
  },
};

export const ACCENT_TOKENS: Record<ThemeMode, AccentTokens> = {
  dark: {
    primary: '#3B82F6',
    hover: '#2563EB',
    active: '#1D4ED8',
    subtle: 'rgba(59, 130, 246, 0.15)',
    border: 'rgba(59, 130, 246, 0.40)',
  },
  light: {
    primary: '#0969DA',
    hover: '#0550AE',
    active: '#033D8B',
    subtle: 'rgba(9, 105, 218, 0.10)',
    border: 'rgba(9, 105, 218, 0.35)',
  },
};

export const SEVERITY_TOKENS: Record<ThemeMode, Record<SeverityLevel, SeverityToken>> = {
  dark: {
    critical: {
      level: 'critical',
      label: 'Critical',
      text: '#E5484D',
      bg: 'rgba(229, 72, 77, 0.14)',
      border: 'rgba(229, 72, 77, 0.35)',
      solid: '#E5484D',
      badgeClass: 'text-red-400 bg-red-950/40 border-red-800/60',
    },
    high: {
      level: 'high',
      label: 'High',
      text: '#F76B15',
      bg: 'rgba(247, 107, 21, 0.14)',
      border: 'rgba(247, 107, 21, 0.35)',
      solid: '#F76B15',
      badgeClass: 'text-orange-400 bg-orange-950/40 border-orange-800/60',
    },
    medium: {
      level: 'medium',
      label: 'Medium',
      text: '#F5A524',
      bg: 'rgba(245, 165, 36, 0.14)',
      border: 'rgba(245, 165, 36, 0.35)',
      solid: '#F5A524',
      badgeClass: 'text-amber-400 bg-amber-950/40 border-amber-800/60',
    },
    low: {
      level: 'low',
      label: 'Low',
      text: '#3E9BFF',
      bg: 'rgba(62, 155, 255, 0.14)',
      border: 'rgba(62, 155, 255, 0.35)',
      solid: '#3E9BFF',
      badgeClass: 'text-sky-400 bg-sky-950/40 border-sky-800/60',
    },
    clean: {
      level: 'clean',
      label: 'Clean',
      text: '#30A46C',
      bg: 'rgba(48, 164, 108, 0.14)',
      border: 'rgba(48, 164, 108, 0.35)',
      solid: '#30A46C',
      badgeClass: 'text-emerald-400 bg-emerald-950/40 border-emerald-800/60',
    },
    unknown: {
      level: 'unknown',
      label: 'Unknown',
      text: '#9BA1A8',
      bg: 'rgba(155, 161, 168, 0.14)',
      border: 'rgba(155, 161, 168, 0.35)',
      solid: '#6B7280',
      badgeClass: 'text-gray-400 bg-gray-900/40 border-gray-700/60',
    },
  },
  light: {
    critical: {
      level: 'critical',
      label: 'Critical',
      text: '#D32F2F',
      bg: 'rgba(211, 47, 47, 0.10)',
      border: 'rgba(211, 47, 47, 0.30)',
      solid: '#D32F2F',
      badgeClass: 'text-red-700 bg-red-50 border-red-200',
    },
    high: {
      level: 'high',
      label: 'High',
      text: '#C2410C',
      bg: 'rgba(194, 65, 12, 0.10)',
      border: 'rgba(194, 65, 12, 0.30)',
      solid: '#C2410C',
      badgeClass: 'text-orange-700 bg-orange-50 border-orange-200',
    },
    medium: {
      level: 'medium',
      label: 'Medium',
      text: '#B45309', // High contrast accessible amber/brown on white
      bg: 'rgba(180, 83, 9, 0.10)',
      border: 'rgba(180, 83, 9, 0.30)',
      solid: '#B45309',
      badgeClass: 'text-amber-800 bg-amber-50 border-amber-200',
    },
    low: {
      level: 'low',
      label: 'Low',
      text: '#0969DA',
      bg: 'rgba(9, 105, 218, 0.10)',
      border: 'rgba(9, 105, 218, 0.30)',
      solid: '#0969DA',
      badgeClass: 'text-blue-700 bg-blue-50 border-blue-200',
    },
    clean: {
      level: 'clean',
      label: 'Clean',
      text: '#166534',
      bg: 'rgba(22, 101, 52, 0.10)',
      border: 'rgba(22, 101, 52, 0.30)',
      solid: '#166534',
      badgeClass: 'text-emerald-800 bg-emerald-50 border-emerald-200',
    },
    unknown: {
      level: 'unknown',
      label: 'Unknown',
      text: '#4B5563',
      bg: 'rgba(75, 85, 99, 0.10)',
      border: 'rgba(75, 85, 99, 0.30)',
      solid: '#4B5563',
      badgeClass: 'text-gray-700 bg-gray-100 border-gray-300',
    },
  },
};

/**
 * Resolves a severity token based strictly on severity level and current theme.
 * Normalized to handle aliases (safe -> clean, info -> low, etc.).
 * No component should EVER branch on theme directly to pick colors.
 */
export function getSeverityToken(
  severity: SeverityLevel | string | undefined | null,
  theme: ThemeMode = 'dark'
): SeverityToken {
  const norm = (severity || 'unknown').toLowerCase().trim();
  let level: SeverityLevel = 'unknown';

  if (norm === 'critical') level = 'critical';
  else if (norm === 'high') level = 'high';
  else if (norm === 'medium' || norm === 'med' || norm === 'warn' || norm === 'warning') level = 'medium';
  else if (norm === 'low' || norm === 'info' || norm === 'informational') level = 'low';
  else if (norm === 'clean' || norm === 'safe') level = 'clean';
  else level = 'unknown';

  return SEVERITY_TOKENS[theme][level];
}

export const DENSITY_TOKENS: Record<DensityMode, {
  rowHeight: number;
  rowHeightClass: string;
  cellPaddingY: string;
  cellPaddingX: string;
  fontSize: string;
  compactClass: string;
}> = {
  compact: {
    rowHeight: 36,
    rowHeightClass: 'h-9',
    cellPaddingY: 'py-1.5',
    cellPaddingX: 'px-3',
    fontSize: 'text-xs',
    compactClass: 'leading-5',
  },
  comfortable: {
    rowHeight: 44,
    rowHeightClass: 'h-11',
    cellPaddingY: 'py-2.5',
    cellPaddingX: 'px-4',
    fontSize: 'text-sm',
    compactClass: 'leading-6',
  },
};

export const RADIUS = {
  none: '0px',
  sm: '0.25rem',  // 4px
  md: '0.375rem', // 6px
  lg: '0.5rem',   // 8px
  xl: '0.75rem',  // 12px
  full: '9999px',
} as const;

export const FOCUS_RING = {
  ringColorDark: 'rgb(59 130 246 / 0.8)',
  ringColorLight: 'rgb(9 105 218 / 0.7)',
  outlineOffset: '2px',
} as const;

export const TYPOGRAPHY = {
  fontSans: 'Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  fontMono: '"JetBrains Mono", "SF Mono", Menlo, Monaco, Consolas, "Liberation Mono", monospace',
} as const;
