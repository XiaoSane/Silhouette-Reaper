/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        reaper: {
          base: '#0a0a0f',
          elevated: '#11121c',
          card: 'rgba(18, 20, 32, 0.65)',
          border: 'rgba(251, 191, 36, 0.18)',
          'border-subtle': 'rgba(255, 255, 255, 0.07)',
          amber: '#f59e0b',
          'amber-light': '#fbbf24',
          'amber-glow': 'rgba(251, 191, 36, 0.15)',
          data: '#86efac',
          muted: '#71717a',
          dim: '#3f3f46',
          text: '#f4f4f5',
        },
        forensic: {
          dark: '#0a0a0f',
          surface: '#11121c',
          elevated: '#181926',
          border: 'rgba(251, 191, 36, 0.2)',
          hover: 'rgba(251, 191, 36, 0.08)',
          text: '#f4f4f5',
          muted: '#a1a1aa',
          accent: '#f59e0b',
          high: '#ef4444',
          medium: '#f59e0b',
          low: '#10b981',
          info: '#38bdf8',
          verified: '#10b981',
          mismatch: '#ef4444',
        },
      },
      fontFamily: {
        display: ['"Bebas Neue"', 'Oswald', 'sans-serif'],
        heading: ['Oswald', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      keyframes: {
        fadeInSlideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        amberPulse: {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.6', transform: 'scale(0.95)' },
        },
        ringPulse: {
          '0%, 100%': {
            boxShadow: '0 0 0 0 rgba(245, 158, 11, 0.4), 0 0 20px rgba(245, 158, 11, 0.3)',
          },
          '50%': {
            boxShadow: '0 0 0 10px rgba(245, 158, 11, 0), 0 0 35px rgba(245, 158, 11, 0.5)',
          },
        },
        spinSlow: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
      },
      animation: {
        'page-in': 'fadeInSlideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards',
        'amber-pulse': 'amberPulse 2.5s infinite ease-in-out',
        'ring-pulse': 'ringPulse 2.2s ease-in-out infinite',
        'spin-slow': 'spinSlow 25s linear infinite',
      },
    },
  },
  plugins: [],
};
