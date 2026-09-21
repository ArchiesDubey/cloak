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
        canvas: '#000000',
        sidebar: '#08080A',
        surface: {
          DEFAULT: '#0D0E11',
          hover: '#141519',
          active: '#1A1C22',
          muted: '#101114',
        },
        border: {
          subtle: '#222328',
          track: '#2D2D2D',
          ring: '#303030',
          hover: 'rgba(255, 255, 255, 0.16)',
        },
        burnrate: {
          ample: '#00FF88',     // Vibrant mint green (Active / Healthy)
          watch: '#F2FF00',     // Electric chartreuse (Pending / Waiting)
          critical: '#FF3F00',  // High-vis pure red (Danger / Error)
        },
        text: {
          primary: '#FFFFFF',
          secondary: '#808080',
          tertiary: '#6E6E73',
        },
      },
      borderColor: {
        subtle: '#222328',
        track: '#2D2D2D',
        ring: '#303030',
      },
      boxShadow: {
        subtle: '0 1px 2px rgba(0, 0, 0, 0.6)',
        card: '0 1px 3px rgba(0, 0, 0, 0.6), 0 0 0 1px #222328',
        modal: '0 25px 50px -12px rgba(0, 0, 0, 0.95), 0 0 0 1px #2D2D2D',
        'glow-ample': '0 0 14px rgba(0, 255, 136, 0.25)',
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Text"', '"SF Pro Display"', '"Helvetica Neue"', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', '"Liberation Mono"', 'monospace'],
      },
      transitionTimingFunction: {
        spring: 'cubic-bezier(0.16, 1, 0.3, 1)', // NotchMotion spring response: 0.42, damping: 0.78
        unfold: 'cubic-bezier(0.16, 1, 0.3, 1)',
        glide: 'cubic-bezier(0.19, 1, 0.22, 1)',
      },
      animation: {
        'status-spin': 'statusSpin 1.4s linear infinite', // NotchMotion 1.4s period
        'fade-in': 'fadeIn 0.24s cubic-bezier(0.16, 1, 0.3, 1) forwards',
      },
      keyframes: {
        statusSpin: {
          '0%': { transform: 'rotate(-90deg)' },
          '100%': { transform: 'rotate(270deg)' },
        },
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(3px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
};
