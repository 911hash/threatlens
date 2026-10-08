/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        // Semantic design system variables
        surface: {
          base: 'var(--bg-base)',
          panel: 'var(--bg-panel)',
          elevated: 'var(--bg-elevated)',
          inset: 'var(--bg-inset)',
          visual: 'var(--bg-visual)',
        },
        border: {
          subtle: 'var(--border-subtle)',
          strong: 'var(--border-strong)',
        },
        txt: {
          primary: 'var(--text-primary)',
          secondary: 'var(--text-secondary)',
          tertiary: 'var(--text-tertiary)',
        },
        accent: {
          primary: 'var(--accent-primary)',
          hover: 'var(--accent-hover)',
          active: 'var(--accent-active)',
          subtle: 'var(--accent-subtle)',
          border: 'var(--accent-border)',
        },
        // Legacy palette support so existing views don't crash
        threat: {
          bg: 'var(--bg-base)',
          card: 'var(--bg-panel)',
          cardHover: 'var(--bg-elevated)',
          border: 'var(--border-subtle)',
          borderLight: 'var(--border-strong)',
          safe: '#10b981',
          safeBg: 'rgba(16, 185, 129, 0.1)',
          low: '#06b6d4',
          lowBg: 'rgba(6, 182, 212, 0.1)',
          medium: '#f59e0b',
          mediumBg: 'rgba(245, 158, 11, 0.1)',
          high: '#f97316',
          highBg: 'rgba(249, 115, 22, 0.1)',
          critical: '#ef4444',
          criticalBg: 'rgba(239, 68, 68, 0.12)',
          unknown: '#94a3b8',
          unknownBg: 'rgba(148, 163, 184, 0.1)',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'dash': 'dash 2s linear infinite',
      },
      keyframes: {
        dash: {
          to: {
            'stroke-dashoffset': '-20',
          },
        },
      },
    },
  },
  plugins: [],
}
