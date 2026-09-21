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
        canvas: '#0A0B0D',
        sidebar: '#0F1014',
        surface: {
          DEFAULT: '#14161A',
          hover: '#1B1E24',
          active: '#22252E',
          muted: '#181A20',
        },
        border: {
          subtle: 'rgba(255, 255, 255, 0.07)',
          hover: 'rgba(255, 255, 255, 0.14)',
          active: 'rgba(255, 255, 255, 0.25)',
        },
        brand: {
          DEFAULT: '#EDEDED',
          dark: '#0A0B0D',
          blue: '#4F46E5',
          emerald: '#10B981',
        },
      },
      borderColor: {
        subtle: 'rgba(255, 255, 255, 0.07)',
        hover: 'rgba(255, 255, 255, 0.14)',
      },
      boxShadow: {
        subtle: '0 1px 2px rgba(0, 0, 0, 0.3)',
        card: '0 1px 3px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.04)',
        modal: '0 25px 50px -12px rgba(0, 0, 0, 0.8), 0 0 0 1px rgba(255, 255, 255, 0.08)',
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Text"', '"Segoe UI"', 'Roboto', 'Helvetica', 'Arial', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', '"Liberation Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
};
