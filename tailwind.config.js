/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Dark SOC theme palette
        soc: {
          bg: '#0a0e1a',
          surface: '#111827',
          card: '#1a2332',
          border: '#2a3a4e',
          hover: '#243447',
          muted: '#8b9bb4',
          text: '#e2e8f0',
        },
        severity: {
          low: '#3b82f6',
          medium: '#f59e0b',
          high: '#f97316',
          critical: '#ef4444',
        },
        accent: {
          blue: '#3b82f6',
          cyan: '#06b6d4',
          green: '#10b981',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'fade-in': 'fadeIn 0.3s ease-in-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
