/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        canvas: '#0C0D0F',
        surface: '#131519',
        elevated: '#1A1D23',
        inset: '#232730',
        radar: {
          DEFAULT: '#F59E0B',
          core: '#F59E0B',
          glow: '#FBBF24',
          border: '#78350F',
          muted: '#92400E',
          dim: 'rgba(245, 158, 11, 0.12)',
        },
      },
      borderColor: {
        subpixel: 'rgba(255, 255, 255, 0.08)',
        'subpixel-hover': 'rgba(255, 255, 255, 0.16)',
        'radar-border': '#78350F',
      },
      boxShadow: {
        'radar-glow': '0 0 12px rgba(245, 158, 11, 0.35)',
        'radar-glow-sm': '0 0 6px rgba(245, 158, 11, 0.25)',
        'subtle-inset': 'inset 0 1px 2px rgba(0, 0, 0, 0.6)',
        'tactile': '0 1px 2px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.05)',
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', '"Liberation Mono"', '"Courier New"', 'monospace'],
        sans: ['-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'Helvetica', 'Arial', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'radar-sweep': 'radarSweep 4s linear infinite',
        'progress-30s': 'countdown 30s linear forwards',
      },
      keyframes: {
        radarSweep: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        countdown: {
          '0%': { width: '100%' },
          '100%': { width: '0%' },
        },
      },
    },
  },
  plugins: [],
};
