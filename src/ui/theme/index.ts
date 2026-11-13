/**
 * Ghost-Tag UI Theme Definitions
 */

export const theme = {
  colors: {
    background: '#0D1117',
    surface: '#161B22',
    surfaceHighlight: '#21262D',
    border: '#30363D',
    primary: '#00E676',
    primaryDark: '#00B0FF',
    accent: '#7C4DFF',
    textPrimary: '#F0F6FC',
    textSecondary: '#8B949E',
    textMuted: '#484F58',
    danger: '#FF5252',
    warning: '#FFD600',
    success: '#00E676',
  },
  spacing: {
    xs: 4,
    sm: 8,
    md: 16,
    lg: 24,
    xl: 32,
    xxl: 48,
  },
  borderRadius: {
    sm: 6,
    md: 12,
    lg: 16,
    pill: 9999,
  },
};

export type Theme = typeof theme;
