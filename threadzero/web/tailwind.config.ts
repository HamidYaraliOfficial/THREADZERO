import type { Config } from 'tailwindcss';

const v = (n: string) => `rgb(var(--${n}) / <alpha-value>)`;
const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}', './views/**/*.{ts,tsx}', './lib/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: v('bg'), layer: v('layer'), layer2: v('layer2'), stroke: v('stroke'), fg: v('fg'), muted: v('muted'),
        accent: v('accent'), 'accent-fg': v('accent-fg'), danger: v('danger'), warn: v('warn'), ok: v('ok'), info: v('info'),
      },
      borderRadius: { win: '8px', winlg: '12px' },
      boxShadow: { win: '0 2px 4px rgb(0 0 0 / .08), 0 0 0 1px rgb(var(--stroke) / .6)', pop: '0 8px 32px rgb(0 0 0 / .28), 0 0 0 1px rgb(var(--stroke) / .8)' },
      fontFamily: {
        sans: ['"Segoe UI Variable Text"', '"Segoe UI Variable"', '"Segoe UI"', 'Vazirmatn', 'Tahoma', '"Microsoft YaHei UI"', '"Microsoft YaHei"', '"PingFang SC"', 'system-ui', 'sans-serif'],
        mono: ['"Cascadia Code"', '"Cascadia Mono"', 'Consolas', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
};
export default config;
