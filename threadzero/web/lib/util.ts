import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export const cn = (...i: ClassValue[]) => twMerge(clsx(i));
export const sevRank: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
export const sevColor: Record<string, string> = {
  Critical: 'bg-danger text-accent-fg', High: 'bg-danger/70 text-accent-fg', Medium: 'bg-warn/80 text-black', Low: 'bg-info/70 text-accent-fg', Info: 'bg-muted/50 text-fg',
};
export const download = (name: string, content: BlobPart, type = 'text/plain') => {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
};
export const fmtDuration = (sec: number | null | undefined) => {
  if (sec == null) return '—';
  let s = Math.max(0, Math.round(sec)); const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600; const m = Math.floor(s / 60); s -= m * 60;
  return [d ? `${d}d` : '', d || h ? `${h}h` : '', d || h || m ? `${m}m` : '', `${s}s`].filter(Boolean).join(' ');
};
/** Minimal line diff (LCS) for DSL candidates. */
export function lineDiff(a: string, b: string): { t: ' ' | '+' | '-'; s: string }[] {
  const x = a.split('\n'), y = b.split('\n');
  const n = x.length, m = y.length;
  const L: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = x[i] === y[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const out: { t: ' ' | '+' | '-'; s: string }[] = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) { out.push({ t: ' ', s: x[i] }); i++; j++; }
    else if (L[i + 1][j] >= L[i][j + 1]) out.push({ t: '-', s: x[i++] }); else out.push({ t: '+', s: y[j++] });
  }
  while (i < n) out.push({ t: '-', s: x[i++] }); while (j < m) out.push({ t: '+', s: y[j++] });
  return out;
}
