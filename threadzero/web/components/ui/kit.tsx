'use client';
import { cva, type VariantProps } from 'class-variance-authority';
import { Loader2 } from 'lucide-react';
import React, { useEffect, useRef, useState } from 'react';
import { cn, sevColor } from '@/lib/util';
import { useApp } from '@/lib/store';

// ---- Button (shadcn-style, Fluent look) ----
const button = cva('inline-flex items-center justify-center gap-2 rounded-win px-3 h-8 text-sm font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none select-none whitespace-nowrap', {
  variants: {
    variant: {
      primary: 'bg-accent text-accent-fg hover:bg-accent/90 active:bg-accent/80',
      secondary: 'bg-layer2 border border-stroke hover:bg-stroke/40 text-fg',
      ghost: 'hover:bg-stroke/40 text-fg', danger: 'bg-danger text-accent-fg hover:bg-danger/90',
    },
    size: { sm: 'h-7 px-2 text-xs', md: 'h-8', icon: 'h-8 w-8 px-0' },
  },
  defaultVariants: { variant: 'secondary', size: 'md' },
});
export function Button({ className, variant, size, loading, children, ...p }: React.ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof button> & { loading?: boolean }) {
  return <button className={cn(button({ variant, size }), className)} {...p}>{loading && <Loader2 className="h-4 w-4 animate-spin" />}{children}</button>;
}

export const Card = ({ className, children, ...p }: React.HTMLAttributes<HTMLDivElement>) => <div className={cn('win-card', className)} {...p}>{children}</div>;
export const CardHeader = ({ title, actions, icon }: { title: React.ReactNode; actions?: React.ReactNode; icon?: React.ReactNode }) => (
  <div className="flex items-center justify-between gap-2 px-4 py-2.5 border-b border-stroke"><div className="flex items-center gap-2 font-semibold">{icon}{title}</div><div className="flex items-center gap-2">{actions}</div></div>
);

export function Badge({ children, tone = 'muted', className }: { children: React.ReactNode; tone?: 'ok' | 'warn' | 'danger' | 'info' | 'muted' | 'accent'; className?: string }) {
  const tones = { ok: 'bg-ok/15 text-ok', warn: 'bg-warn/20 text-warn', danger: 'bg-danger/15 text-danger', info: 'bg-info/15 text-info', muted: 'bg-stroke/60 text-muted', accent: 'bg-accent/15 text-accent' };
  return <span className={cn('inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium', tones[tone], className)}>{children}</span>;
}
export function SevBadge({ sev }: { sev: string }) {
  const { t } = useApp();
  return <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold', sevColor[sev] ?? 'bg-stroke')}>{t(`sev.${sev}`)}</span>;
}
export const diagTone = (s: string) => (s === 'error' ? 'danger' : s === 'warning' ? 'warn' : s === 'finding' ? 'accent' : s === 'optimization' ? 'info' : 'muted') as any;

export function Tabs({ tabs, value, onChange, className }: { tabs: { id: string; label: React.ReactNode }[]; value: string; onChange: (v: string) => void; className?: string }) {
  return (
    <div role="tablist" className={cn('flex gap-1 border-b border-stroke overflow-x-auto', className)}>
      {tabs.map((x) => (
        <button key={x.id} role="tab" aria-selected={value === x.id} onClick={() => onChange(x.id)}
          className={cn('px-3 py-2 text-sm whitespace-nowrap border-b-2 -mb-px transition-colors', value === x.id ? 'border-accent text-fg font-semibold' : 'border-transparent text-muted hover:text-fg')}>{x.label}</button>
      ))}
    </div>
  );
}

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(({ className, ...p }, r) => <input ref={r} className={cn('win-input', className)} {...p} />);
Input.displayName = 'Input';
export const Select = ({ className, children, ...p }: React.SelectHTMLAttributes<HTMLSelectElement>) => <select className={cn('win-input pe-8', className)} {...p}>{children}</select>;
export const Textarea = ({ className, ...p }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) => <textarea className={cn('win-input font-mono text-xs', className)} {...p} />;

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (b: boolean) => void; label?: React.ReactNode }) {
  return (
    <label className="inline-flex items-center gap-2 cursor-pointer select-none">
      <button type="button" role="switch" aria-checked={checked} onClick={() => onChange(!checked)}
        className={cn('relative h-5 w-10 rounded-full border transition-colors', checked ? 'bg-accent border-accent' : 'bg-layer2 border-muted/60')}>
        <span className={cn('absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all', checked ? 'bg-accent-fg start-[22px]' : 'bg-muted start-0.5')} />
      </button>{label}
    </label>
  );
}
export const Field = ({ label, children, className }: { label: React.ReactNode; children: React.ReactNode; className?: string }) => (
  <label className={cn('flex flex-col gap-1 text-xs text-muted', className)}><span>{label}</span><div className="text-fg text-sm">{children}</div></label>
);

export function Stat({ label, value, tone }: { label: string; value: React.ReactNode; tone?: string }) {
  return <Card className="p-4"><div className="text-xs text-muted">{label}</div><div className={cn('text-2xl font-semibold mt-1', tone)}>{value}</div></Card>;
}

export function Table({ head, rows, empty, onRow, className }: { head: React.ReactNode[]; rows: React.ReactNode[][]; empty?: string; onRow?: (i: number) => void; className?: string }) {
  return (
    <div className={cn('overflow-auto', className)}>
      <table className="w-full text-sm border-collapse">
        <thead><tr className="text-muted text-xs">{head.map((h, i) => <th key={i} className="text-start font-medium px-3 py-2 border-b border-stroke sticky top-0 bg-layer">{h}</th>)}</tr></thead>
        <tbody>
          {rows.map((r, i) => <tr key={i} onClick={() => onRow?.(i)} className={cn('border-b border-stroke/60 hover:bg-stroke/25', onRow && 'cursor-pointer')}>{r.map((c, j) => <td key={j} className="px-3 py-2 align-top">{c}</td>)}</tr>)}
          {!rows.length && <tr><td colSpan={head.length} className="px-3 py-8 text-center text-muted">{empty ?? '—'}</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
export const Empty = ({ children }: { children?: React.ReactNode }) => { const { t } = useApp(); return <div className="text-center text-muted py-12">{children ?? t('noData')}</div>; };
export const Spinner = () => <Loader2 className="h-4 w-4 animate-spin text-accent" />;
export const Kbd = ({ children }: { children: React.ReactNode }) => <kbd className="ltr rounded border border-stroke bg-layer2 px-1.5 py-0.5 text-[11px] font-mono">{children}</kbd>;
export const Mono = ({ children, className }: { children: React.ReactNode; className?: string }) => <code className={cn('ltr font-mono text-xs break-all', className)}>{children}</code>;

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 mb-4 fluent-in">
      <div><h1 className="text-2xl font-semibold">{title}</h1>{subtitle && <p className="text-muted mt-0.5">{subtitle}</p>}</div>
      <div className="flex flex-wrap items-center gap-2">{actions}</div>
    </div>
  );
}

/** Resizable two-pane split (multi-panel docking building block). Handles RTL by mirroring the drag axis. */
export function SplitPane({ a, b, dir = 'h', initial = 0.55, min = 0.2, className }: { a: React.ReactNode; b: React.ReactNode; dir?: 'h' | 'v'; initial?: number; min?: number; className?: string }) {
  const { dir: pageDir } = useApp();
  const [ratio, setRatio] = useState(initial);
  const [active, setActive] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!active) return;
    const move = (e: PointerEvent) => {
      const r = box.current!.getBoundingClientRect();
      let v = dir === 'h' ? (e.clientX - r.left) / r.width : (e.clientY - r.top) / r.height;
      if (dir === 'h' && pageDir === 'rtl') v = 1 - v;
      setRatio(Math.min(1 - min, Math.max(min, v)));
    };
    const up = () => setActive(false);
    window.addEventListener('pointermove', move); window.addEventListener('pointerup', up);
    return () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up); };
  }, [active, dir, min, pageDir]);
  const size = `${ratio * 100}%`;
  return (
    <div ref={box} className={cn('flex min-h-0 min-w-0', dir === 'h' ? 'flex-row' : 'flex-col', className)}>
      <div className="min-h-0 min-w-0 overflow-hidden" style={{ [dir === 'h' ? 'width' : 'height']: size } as any}>{a}</div>
      <div data-active={active} onPointerDown={(e) => { e.preventDefault(); setActive(true); }}
        className={cn('split-handle shrink-0 transition-colors', dir === 'h' ? 'w-1 cursor-col-resize mx-0.5 rounded' : 'h-1 cursor-row-resize my-0.5 rounded')} role="separator" />
      <div className="min-h-0 min-w-0 flex-1 overflow-hidden">{b}</div>
    </div>
  );
}

export function Modal({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: React.ReactNode; children: React.ReactNode; wide?: boolean }) {
  useEffect(() => { if (!open) return; const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose(); window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] bg-black/40" onMouseDown={onClose}>
      <div className={cn('acrylic win-card shadow-pop w-[92vw] max-h-[78vh] overflow-auto fluent-in', wide ? 'max-w-4xl' : 'max-w-xl')} onMouseDown={(e) => e.stopPropagation()} role="dialog" aria-modal>
        <div className="flex items-center justify-between px-4 py-3 border-b border-stroke"><h2 className="font-semibold">{title}</h2><Button variant="ghost" size="icon" onClick={onClose}>✕</Button></div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

export function BarChart({ data, height = 120 }: { data: { label: string; value: number; color?: string }[]; height?: number }) {
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <div className="flex items-end gap-3 ltr" style={{ height }}>
      {data.map((d) => (
        <div key={d.label} className="flex flex-col items-center gap-1 flex-1 min-w-[28px]">
          <span className="text-xs text-muted">{d.value}</span>
          <div className="w-full rounded-t bg-accent" style={{ height: `${(d.value / max) * (height - 34)}px`, background: d.color, minHeight: d.value ? 3 : 1 }} />
          <span className="text-[10px] text-muted truncate max-w-full">{d.label}</span>
        </div>
      ))}
    </div>
  );
}
export function Json({ value, max = 4000 }: { value: any; max?: number }) {
  const s = typeof value === 'string' ? value : JSON.stringify(value, null, 1);
  return <pre className="text-xs font-mono bg-layer2 border border-stroke rounded-win p-3 overflow-auto max-h-[60vh] whitespace-pre-wrap break-words">{s.length > max ? s.slice(0, max) + '\n…' : s}</pre>;
}
