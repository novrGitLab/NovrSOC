// Ported 1:1 from the real app's dark-mode design tokens.
// Source: frontend/src/app/globals.css (NovrSOC main repo, verified 2026-10-27).
// Do not invent new colors here — add to this file only by copying a real token.

export const tokens = {
  brand: {
    blue: '#2B3BCC',
    red: '#CC2B2B',
    redHover: '#B02424',
    purple: '#520385',
    purpleHover: '#420270',
    orange: '#FF5500',
    orangeHover: '#E54D00',
    white: '#FFFFFF',
    grey50: '#F8F9FC',
    grey100: '#EEF0F6',
    grey300: '#C4C9D8',
    grey500: '#7A8099',
    grey800: '#1C1F2E',
    grey900: '#0D0F1A',
    success: '#16A34A',
    warning: '#F59E0B',
  },
  // Dark theme surface tokens (`.dark` block in globals.css) — the video uses this theme.
  surface: {
    surface: '#0D0F1A',
    card: '#14172a',
    cardMuted: '#1a1e33',
    border: 'rgba(255, 255, 255, 0.1)',
    foreground: '#FFFFFF',
    foregroundMuted: '#7A8099',
  },
  // Data-viz tokens (`--vz-*`), dark mode values.
  vz: {
    sevCritical: '#ff8466',
    sevHigh: '#e05a3a',
    sevMedium: '#bb472f',
    sevLow: '#8c3a2a',
    sevInfo: '#5d6279',
    prog1: '#6a3aa6',
    prog2: '#8853c6',
    prog3: '#a97ae2',
    prog4: '#cdaaf7',
    neutral: '#3a3f58',
    grid: 'rgba(255, 255, 255, 0.06)',
    axis: 'rgba(255, 255, 255, 0.16)',
    good: '#16A34A',
    warning: '#fab219',
    serious: '#ec835a',
    critical: '#d03b3b',
    cat1: '#3987e5',
    cat3: '#199e70',
  },
} as const;

export const fonts = {
  heading: 'Space Grotesk',
  sans: 'Inter',
  data: 'JetBrains Mono',
} as const;
