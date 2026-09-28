'use client';
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { api } from './api';
import { dirOf, Lang, translate } from './i18n';

export type ThemeId = 'system' | 'light' | 'dark' | 'amoled' | 'red' | 'blue';
export type A = any;
type Toast = { id: number; msg: string; kind: 'ok' | 'err' | 'info' };

interface Ctx {
  lang: Lang; setLang: (l: Lang) => void; t: (k: string, v?: Record<string, string | number>) => string; dir: 'ltr' | 'rtl';
  theme: ThemeId; setTheme: (t: ThemeId) => void;
  source: string; setSource: (s: string) => void; project: string;
  analysis: A | null; analyzing: boolean; error: string | null; reanalyze: () => Promise<A | null>;
  compileRes: A | null; compiling: boolean; compile: () => Promise<A | null>;
  examples: { name: string; title: string }[]; loadExample: (n: string) => Promise<void>;
  toast: (m: string, k?: Toast['kind']) => void; toasts: Toast[];
  backendUp: boolean; health: A | null;
  patchSource: (fn: (s: string) => string) => void;
  paletteOpen: boolean; setPalette: (b: boolean) => void;
}
const C = createContext<Ctx>(null as any);
export const useApp = () => useContext(C);

const ls = {
  get: (k: string, d: string) => (typeof window === 'undefined' ? d : window.localStorage.getItem(k) ?? d),
  set: (k: string, v: string) => { try { window.localStorage.setItem(k, v); } catch { /* ignore */ } },
};

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangS] = useState<Lang>('en');
  const [theme, setThemeS] = useState<ThemeId>('system');
  const [source, setSourceS] = useState('');
  const [analysis, setAnalysis] = useState<A | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [compileRes, setCompileRes] = useState<A | null>(null);
  const [compiling, setCompiling] = useState(false);
  const [examples, setExamples] = useState<{ name: string; title: string }[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [health, setHealth] = useState<A | null>(null);
  const [paletteOpen, setPalette] = useState(false);
  const seq = useRef(0);
  const hydrated = useRef(false);

  // hydrate from localStorage
  useEffect(() => {
    setLangS(ls.get('tz.lang', 'en') as Lang); setThemeS(ls.get('tz.theme', 'system') as ThemeId);
    const saved = ls.get('tz.source', '');
    hydrated.current = true;
    api('/api/health').then(setHealth).catch(() => setHealth({ ok: false }));
    api('/api/examples').then(setExamples).catch(() => {});
    if (saved) setSourceS(saved);
    else api('/api/examples/secure_api').then((e) => setSourceS(e.source)).catch(() => {});
  }, []);

  // apply theme + language + direction to <html>
  useEffect(() => {
    const apply = () => {
      const resolved = theme === 'system' ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme;
      document.documentElement.dataset.theme = resolved;
    };
    apply();
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  }, [theme]);
  useEffect(() => { document.documentElement.lang = lang; document.documentElement.dir = dirOf(lang); }, [lang]);

  const setLang = (l: Lang) => { setLangS(l); ls.set('tz.lang', l); };
  const setTheme = (x: ThemeId) => { setThemeS(x); ls.set('tz.theme', x); };
  const setSource = useCallback((s: string) => { setSourceS(s); ls.set('tz.source', s); }, []);
  const patchSource = useCallback((fn: (s: string) => string) => setSourceS((s) => { const n = fn(s); ls.set('tz.source', n); return n; }), []);

  const toast = useCallback((msg: string, kind: Toast['kind'] = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((x) => [...x, { id, msg, kind }]);
    setTimeout(() => setToasts((x) => x.filter((y) => y.id !== id)), 4200);
  }, []);

  const reanalyze = useCallback(async () => {
    if (!source.trim()) return null;
    const my = ++seq.current;
    setAnalyzing(true);
    try {
      const a = await api('/api/analyze', { source });
      if (my === seq.current) { setAnalysis(a); setError(null); }
      return a;
    } catch (e: any) { if (my === seq.current) setError(String(e.message ?? e)); return null; }
    finally { if (my === seq.current) setAnalyzing(false); }
  }, [source]);

  // live analysis (debounced)
  useEffect(() => {
    if (!hydrated.current || !source.trim()) return;
    const h = setTimeout(() => { reanalyze(); }, 450);
    return () => clearTimeout(h);
  }, [source, reanalyze]);

  const compile = useCallback(async () => {
    setCompiling(true);
    try {
      const r = await api('/api/compile', { source });
      setCompileRes(r);
      toast(r.ok ? `✔ ${r.artifactId} — ${r.tests.passed}/${r.tests.total}` : `✘ ${r.error ?? 'compile failed'}`, r.ok ? 'ok' : 'err');
      return r;
    } catch (e: any) { toast(String(e.message ?? e), 'err'); return null; }
    finally { setCompiling(false); }
  }, [source, toast]);

  const loadExample = useCallback(async (name: string) => {
    const e = await api(`/api/examples/${name}`);
    setSource(e.source); setCompileRes(null);
    toast(`${name}`, 'info');
  }, [setSource, toast]);

  const t = useCallback((k: string, v?: Record<string, string | number>) => translate(lang, k, v), [lang]);
  const value = useMemo<Ctx>(() => ({
    lang, setLang, t, dir: dirOf(lang), theme, setTheme, source, setSource, project: analysis?.project?.name ?? '', analysis, analyzing, error, reanalyze,
    compileRes, compiling, compile, examples, loadExample, toast, toasts, backendUp: health?.ok !== false, health, patchSource, paletteOpen, setPalette,
  }), [lang, t, theme, source, setSource, analysis, analyzing, error, reanalyze, compileRes, compiling, compile, examples, loadExample, toast, toasts, health, patchSource, paletteOpen]);
  return <C.Provider value={value}>{children}</C.Provider>;
}
