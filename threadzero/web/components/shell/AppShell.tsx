'use client';
import { Command, Languages, Menu, Palette, Play, Search, ShieldCheck } from 'lucide-react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import React, { useEffect, useMemo, useState } from 'react';
import { LANGS } from '@/lib/i18n';
import { ThemeId, useApp } from '@/lib/store';
import { cn } from '@/lib/util';
import { VIEWS } from '@/views/ids';
import { Badge, Button, Kbd, Modal, Select, Spinner } from '../ui/kit';

const GROUPS = ['design', 'analyze', 'runtime', 'ship', 'manage'] as const;
const THEMES: ThemeId[] = ['system', 'light', 'dark', 'amoled', 'red', 'blue'];

export function AppShell({ children }: { children: React.ReactNode }) {
  const app = useApp();
  const { t, lang, setLang, theme, setTheme, analysis, analyzing, compiling, compile, backendUp, toasts, paletteOpen, setPalette, examples, loadExample, patchSource } = app;
  const path = usePathname();
  const router = useRouter();
  const [collapsed, setCollapsed] = useState(false);
  const [help, setHelp] = useState(false);
  const [q, setQ] = useState('');

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette(true); }
      else if (mod && e.key === 'Enter') { e.preventDefault(); compile(); }
      else if (e.altKey && /^[1-9]$/.test(e.key)) { router.push(`/${VIEWS[+e.key - 1].id}/`); }
      else if (e.key === '?' && !(e.target as HTMLElement).closest('input,textarea,.cm-editor')) setHelp(true);
    };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [compile, router, setPalette]);

  const commands = useMemo(() => [
    ...VIEWS.map((v) => ({ id: `go-${v.id}`, label: t(`nav.${v.id}`), hint: 'Go to', run: () => router.push(`/${v.id}/`) })),
    { id: 'compile', label: t('compile'), hint: 'Ctrl+Enter', run: () => compile() },
    ...THEMES.map((x) => ({ id: `theme-${x}`, label: `${t('theme')}: ${t(x)}`, hint: '', run: () => setTheme(x) })),
    ...LANGS.map((l) => ({ id: `lang-${l.id}`, label: `${t('language')}: ${l.label}`, hint: '', run: () => setLang(l.id) })),
    ...examples.map((e) => ({ id: `ex-${e.name}`, label: `${t('example')}: ${e.name}`, hint: '', run: () => loadExample(e.name) })),
  ], [t, router, compile, setTheme, setLang, examples, loadExample]);
  const shown = commands.filter((c) => c.label.toLowerCase().includes(q.toLowerCase())).slice(0, 12);

  const errs = analysis?.errorCount ?? 0;
  const sev = analysis?.metrics?.findingsBySeverity ?? {};
  return (
    <div className="h-screen flex flex-col overflow-hidden">
      {/* title bar */}
      <header className="mica flex items-center gap-3 h-11 px-3 border-b border-stroke shrink-0">
        <Button variant="ghost" size="icon" onClick={() => setCollapsed(!collapsed)} aria-label="menu"><Menu className="h-4 w-4" /></Button>
        <div className="flex items-center gap-2 font-semibold"><ShieldCheck className="h-5 w-5 text-accent" /><span>{t('appName')}</span><span className="text-muted font-normal hidden md:inline">· {t('appTagline')}</span></div>
        <button onClick={() => setPalette(true)} className="mx-auto hidden sm:flex items-center gap-2 h-8 w-[min(420px,40vw)] rounded-win bg-layer2 border border-stroke px-3 text-muted hover:border-accent/60">
          <Search className="h-4 w-4" /><span className="flex-1 text-start">{t('search')}</span><Kbd>Ctrl K</Kbd>
        </button>
        <div className="flex items-center gap-2 ms-auto sm:ms-0">
          <Button variant="primary" onClick={() => compile()} loading={compiling}><Play className="h-3.5 w-3.5" />{t('compile')}</Button>
          <label className="hidden md:flex items-center gap-1"><Languages className="h-4 w-4 text-muted" />
            <Select className="h-8 w-28 py-0" value={lang} onChange={(e) => setLang(e.target.value as any)} aria-label={t('language')}>{LANGS.map((l) => <option key={l.id} value={l.id}>{l.label}</option>)}</Select></label>
          <label className="hidden md:flex items-center gap-1"><Palette className="h-4 w-4 text-muted" />
            <Select className="h-8 w-36 py-0" value={theme} onChange={(e) => setTheme(e.target.value as any)} aria-label={t('theme')}>{THEMES.map((x) => <option key={x} value={x}>{t(x)}</option>)}</Select></label>
        </div>
      </header>

      <div className="flex flex-1 min-h-0">
        {/* navigation view */}
        <nav className={cn('mica shrink-0 border-e border-stroke overflow-y-auto py-2 transition-[width]', collapsed ? 'w-12' : 'w-60')} aria-label="Navigation">
          {GROUPS.map((g) => (
            <div key={g} className="mb-2">
              {!collapsed && <div className="px-4 pt-2 pb-1 text-[11px] uppercase tracking-wide text-muted">{t(`nav.group.${g}`)}</div>}
              {VIEWS.filter((v) => v.group === g).map((v) => {
                const active = path?.replace(/\/$/, '') === `/${v.id}` || (v.id === 'studio' && (path === '/' || path === ''));
                const Icon = v.icon;
                return (
                  <Link key={v.id} href={`/${v.id}/`} title={t(`nav.${v.id}`)}
                    className={cn('relative mx-1.5 my-0.5 flex items-center gap-3 rounded-win h-9 px-2.5 hover:bg-stroke/40 transition-colors', active && 'bg-stroke/50 font-semibold',
                      active && 'before:absolute before:start-0 before:top-2.5 before:h-4 before:w-[3px] before:rounded-full before:bg-accent')}>
                    <Icon className={cn('h-[18px] w-[18px] shrink-0', active ? 'text-accent' : 'text-muted')} />{!collapsed && <span className="truncate">{t(`nav.${v.id}`)}</span>}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
        <main className="flex-1 min-w-0 overflow-auto p-5">
          {!backendUp && <div className="mb-4 rounded-win border border-danger/50 bg-danger/10 text-danger px-4 py-3">{t('backendDown')}</div>}
          {children}
        </main>
      </div>

      {/* status bar */}
      <footer className="mica h-7 shrink-0 border-t border-stroke flex items-center gap-3 px-3 text-xs text-muted">
        <span className="flex items-center gap-1.5">{analyzing || compiling ? <><Spinner />{compiling ? t('compiling') : t('analyzing')}</> : <><span className={cn('h-2 w-2 rounded-full', errs ? 'bg-danger' : 'bg-ok')} />{errs ? `${errs} ${t('errors')}` : t('ready')}</>}</span>
        {analysis && <><span>{analysis.project.name} v{analysis.project.version}</span>
          {['Critical', 'High', 'Medium', 'Low'].map((s) => sev[s] ? <Badge key={s} tone={s === 'Critical' || s === 'High' ? 'danger' : s === 'Medium' ? 'warn' : 'info'}>{t(`sev.${s}`)} {sev[s]}</Badge> : null)}</>}
        <span className="ms-auto ltr">{app.health?.core ?? ''}</span>
        <button className="hover:text-fg flex items-center gap-1" onClick={() => setHelp(true)}><Command className="h-3 w-3" />{t('shortcuts')}</button>
      </footer>

      <Modal open={paletteOpen} onClose={() => setPalette(false)} title={t('commandPalette')}>
        <input autoFocus className="win-input mb-3" placeholder={t('search')} value={q} onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && shown[0]) { shown[0].run(); setPalette(false); setQ(''); } }} />
        <ul>{shown.map((c) => <li key={c.id}><button className="w-full flex justify-between items-center px-3 py-2 rounded hover:bg-stroke/40 text-start" onClick={() => { c.run(); setPalette(false); setQ(''); }}><span>{c.label}</span><span className="text-xs text-muted">{c.hint}</span></button></li>)}</ul>
      </Modal>
      <Modal open={help} onClose={() => setHelp(false)} title={t('shortcuts')}>
        <ul className="space-y-2">{[['Ctrl K', t('commandPalette')], ['Ctrl Enter', t('compile')], ['Alt 1…9', t('nav.group.design')], ['?', t('shortcuts')], ['Esc', t('close')]].map(([k, d]) => <li key={k} className="flex justify-between"><Kbd>{k}</Kbd><span>{d}</span></li>)}</ul>
      </Modal>
      <div className="fixed bottom-10 end-4 z-50 flex flex-col gap-2">
        {toasts.map((x) => <div key={x.id} className={cn('acrylic win-card shadow-pop px-4 py-2 fluent-in max-w-sm', x.kind === 'err' && 'border-danger/60 text-danger', x.kind === 'ok' && 'border-ok/60')}>{x.msg}</div>)}
      </div>
    </div>
  );
}
