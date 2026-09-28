'use client';
import React from 'react';
import { Badge, Card, CardHeader, PageHeader } from '@/components/ui/kit';
import { LANGS } from '@/lib/i18n';
import { ThemeId, useApp } from '@/lib/store';
import { cn } from '@/lib/util';

const THEMES: { id: ThemeId; sw: string[] }[] = [
  { id: 'system', sw: ['#f3f3f3', '#202020'] }, { id: 'light', sw: ['#f3f3f3', '#0067c0'] }, { id: 'dark', sw: ['#202020', '#60cdff'] },
  { id: 'amoled', sw: ['#000000', '#60cdff'] }, { id: 'red', sw: ['#201012', '#ff6363'] }, { id: 'blue', sw: ['#0c182c', '#4cc2ff'] },
];

export default function SettingsView() {
  const { t, theme, setTheme, lang, setLang, dir } = useApp();
  return (
    <div className="max-w-3xl">
      <PageHeader title={t('settings.title')} />
      <Card className="mb-4"><CardHeader title={t('appearance')} />
        <div className="p-4 grid grid-cols-2 sm:grid-cols-3 gap-3">
          {THEMES.map((x) => (
            <button key={x.id} onClick={() => setTheme(x.id)} className={cn('rounded-win border p-3 text-start hover:border-accent/70 transition-colors', theme === x.id ? 'border-accent ring-2 ring-accent/40' : 'border-stroke')}>
              <div className="flex h-10 rounded overflow-hidden border border-stroke mb-2"><div className="flex-1" style={{ background: x.sw[0] }} /><div className="flex-1" style={{ background: x.sw[1] }} /></div>
              <div className="font-medium">{t(x.id)}</div></button>))}
        </div></Card>
      <Card><CardHeader title={t('language')} />
        <div className="p-4 grid grid-cols-1 sm:grid-cols-3 gap-3">
          {LANGS.map((l) => (
            <button key={l.id} onClick={() => setLang(l.id)} className={cn('rounded-win border p-3 text-start hover:border-accent/70', lang === l.id ? 'border-accent ring-2 ring-accent/40' : 'border-stroke')}>
              <div className="text-lg font-medium">{l.label}</div><Badge tone={l.dir === 'rtl' ? 'accent' : 'muted'}>{l.dir === 'rtl' ? t('settings.rtl') : t('settings.ltr')}</Badge></button>))}
        </div>
        <p className="px-4 pb-4 text-muted">{t('settings.direction')}: <b>{dir.toUpperCase()}</b> — {t('settings.codeLtr')}</p></Card>
    </div>
  );
}
