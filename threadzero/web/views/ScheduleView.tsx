'use client';
import { Clock, Plus, Trash2 } from 'lucide-react';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Badge, Button, Card, CardHeader, Empty, Field, Input, PageHeader, Select, Switch } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { dayNames, num } from '@/lib/i18n';
import { useApp } from '@/lib/store';
import { cn, fmtDuration } from '@/lib/util';

type W = { name: string; days: string | number[]; from: string; to: string; tz: string; kind: string; label?: string };
const ZONES = ['UTC', 'Asia/Baku', 'Asia/Tehran', 'Asia/Shanghai', 'Europe/London', 'Europe/Berlin', 'Europe/Istanbul', 'America/New_York', 'America/Los_Angeles', 'Asia/Dubai', 'Asia/Tokyo', 'Australia/Sydney'];
const blank = (n: number, tz: string): W => ({ name: `Window${n}`, days: 'weekdays', from: '09:00', to: '17:00', tz, kind: 'open', label: '' });
const daysOf = (d: W['days']): number[] => (d === 'daily' ? [0, 1, 2, 3, 4, 5, 6] : d === 'weekdays' ? [0, 1, 2, 3, 4] : d === 'weekends' ? [5, 6] : (d as number[]));

function Countdown({ res, fetchedAt, tick, label, lang }: { res: any; fetchedAt: number; tick: number; label: string; lang: any }) {
  const left = res.seconds_until_change == null ? null : Math.max(0, res.seconds_until_change - (tick - fetchedAt) / 1000);
  return <div><div className="text-xs text-muted">{label}</div><div className="text-2xl font-semibold tabular-nums ltr">{left == null ? '—' : num(lang, fmtDuration(left))}</div></div>;
}

export default function ScheduleView() {
  const { t, lang, source, patchSource, toast, analysis: A } = useApp();
  const [windows, setWindows] = useState<W[]>([]);
  const [tz, setTz] = useState('UTC');
  const [results, setResults] = useState<any[]>([]);
  const [fetchedAt, setFetchedAt] = useState(Date.now());
  const [tick, setTick] = useState(Date.now());
  const [sim, setSim] = useState('');
  const [dsl, setDsl] = useState('');
  const loaded = useRef(false);
  const dn = dayNames(lang);

  useEffect(() => { api('/api/schedule').then((s) => { if (s.windows?.length) { setWindows(s.windows); setTz(s.timezone ?? 'UTC'); } loaded.current = true; }).catch(() => { loaded.current = true; }); }, []);
  useEffect(() => { const h = setInterval(() => setTick(Date.now()), 1000); return () => clearInterval(h); }, []);

  const evaluate = useCallback(async () => {
    if (!windows.length) { setResults([]); return; }
    try { const r = await api('/api/schedule/evaluate', { windows, timezone: tz, now: sim ? new Date(sim).toISOString().replace('Z', '+00:00') : undefined }); setResults(r.results); setFetchedAt(Date.now()); }
    catch (e: any) { toast(e.message, 'err'); }
    try { setDsl((await api('/api/schedule/dsl', { windows })).dsl); } catch { /* ignore */ }
  }, [windows, tz, sim, toast]);
  useEffect(() => { const h = setTimeout(evaluate, 250); return () => clearTimeout(h); }, [evaluate]);
  // refresh when a countdown reaches zero (state flips)
  useEffect(() => { if (sim) return; if (results.some((r) => r.seconds_until_change != null && r.seconds_until_change - (tick - fetchedAt) / 1000 <= 0)) evaluate(); }, [tick]); // eslint-disable-line

  const upd = (i: number, p: Partial<W>) => setWindows((w) => w.map((x, k) => (k === i ? { ...x, ...p } : x)));
  const clock = (zone: string) => { try { return new Intl.DateTimeFormat(lang === 'fa' ? 'fa-IR-u-nu-latn' : lang === 'zh' ? 'zh-CN' : 'en-GB', { timeZone: zone, weekday: 'long', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(sim ? new Date(sim) : new Date(tick)); } catch { return '—'; } };
  const save = async () => { await api('/api/schedule', { timezone: tz, windows }, 'PUT'); toast(t('schedule.saved'), 'ok'); };
  const insert = () => patchSource((s) => {
    let out = s; for (const w of windows) out = out.replace(new RegExp(`^\\s*window\\s+${w.name}\\s*\\{[^}]*\\}\\s*$`, 'm'), '');
    return out.trimEnd() + '\n\n' + dsl + '\n';
  });
  const fromModel = async () => { const r = await api('/api/schedule/from-model', { source }); setWindows(r.windows); setTz(r.timezone); };
  const kindTone = (k: string) => (k === 'open' ? 'ok' : k === 'maintenance' ? 'warn' : 'danger') as any;

  return (
    <div>
      <PageHeader title={t('schedule.title')} subtitle={t('schedule.subtitle')} actions={<>
        <Button onClick={fromModel} disabled={!A}>{t('schedule.fromModel')}</Button><Button onClick={() => setWindows([...windows, blank(windows.length + 1, tz)])}><Plus className="h-4 w-4" />{t('schedule.add')}</Button>
        <Button onClick={save}>{t('save')}</Button><Button variant="primary" onClick={insert} disabled={!windows.length}>{t('schedule.insert')}</Button></>} />
      <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-2"><CardHeader title={t('schedule.now')} icon={<Clock className="h-4 w-4" />} />
          <div className="p-4 space-y-3">
            <Field label={t('schedule.tz')}><Select value={tz} onChange={(e) => setTz(e.target.value)}>{[...new Set([tz, ...ZONES])].map((z) => <option key={z}>{z}</option>)}</Select></Field>
            <div className="text-3xl font-semibold tabular-nums ltr">{num(lang, clock(tz))}</div>
            <Field label={t('schedule.simulate')}><div className="flex gap-2"><Input type="datetime-local" value={sim} onChange={(e) => setSim(e.target.value)} />{sim && <Button onClick={() => setSim('')}>✕</Button>}</div></Field>
            <div className="text-xs text-muted">{t('schedule.dslPreview')}</div><pre className="ltr text-xs bg-layer2 border border-stroke rounded-win p-2 whitespace-pre-wrap">{dsl || '—'}</pre></div></Card>
        <div className="xl:col-span-3 space-y-4">
          {!windows.length && <Empty>{t('schedule.add')}</Empty>}
          {windows.map((w, i) => { const r = results[i]; const open = r?.is_open; return (
            <Card key={i} className="fluent-in">
              <div className="p-4 grid gap-3 md:grid-cols-6 items-end">
                <Field label={t('name')} className="md:col-span-2"><Input value={w.name} onChange={(e) => upd(i, { name: e.target.value.replace(/[^A-Za-z0-9_]/g, '') })} /></Field>
                <Field label={t('schedule.kind')}><Select value={w.kind} onChange={(e) => upd(i, { kind: e.target.value })}>{['open', 'maintenance', 'emergency'].map((k) => <option key={k} value={k}>{t(`schedule.${k}`)}</option>)}</Select></Field>
                <Field label={t('schedule.from')}><Input type="time" value={w.from} onChange={(e) => upd(i, { from: e.target.value })} className="ltr" /></Field>
                <Field label={t('schedule.to')}><Input type="time" value={w.to === '24:00' ? '23:59' : w.to} onChange={(e) => upd(i, { to: e.target.value })} className="ltr" /></Field>
                <div className="flex justify-end"><Button variant="ghost" size="icon" onClick={() => setWindows(windows.filter((_, k) => k !== i))} aria-label={t('schedule.remove')}><Trash2 className="h-4 w-4 text-danger" /></Button></div>
                <div className="md:col-span-6 flex flex-wrap items-center gap-2">
                  {(['daily', 'weekdays', 'weekends'] as const).map((p) => <button key={p} onClick={() => upd(i, { days: p })} className={cn('px-2 py-1 rounded-full text-xs border', w.days === p ? 'bg-accent text-accent-fg border-accent' : 'border-stroke text-muted')}>{t(`schedule.${p}`)}</button>)}
                  <span className="w-px h-5 bg-stroke" />{dn.map((d, k) => { const on = daysOf(w.days).includes(k); return <button key={k} onClick={() => upd(i, { days: on ? daysOf(w.days).filter((x) => x !== k) : [...daysOf(w.days), k].sort() })} className={cn('px-2 py-1 rounded text-xs border min-w-[2.6rem]', on ? 'bg-accent/20 border-accent text-fg' : 'border-stroke text-muted')}>{d.slice(0, lang === 'zh' ? 2 : 3)}</button>; })}
                  <Input className="max-w-[10rem] ms-auto" placeholder={t('schedule.label')} value={w.label ?? ''} onChange={(e) => upd(i, { label: e.target.value })} /></div>
              </div>
              {r && <div className={cn('border-t border-stroke px-4 py-3 grid gap-4 sm:grid-cols-4 items-center', open ? 'bg-ok/10' : 'bg-danger/5')}>
                <div><Badge tone={open ? 'ok' : 'danger'}>{open ? t('schedule.openNow') : t('schedule.closedNow')}</Badge> <Badge tone={kindTone(r.kind)}>{t(`schedule.${r.kind}`)}</Badge>
                  <div className="text-xs text-muted mt-1">{r.intervals.length ? r.intervals.slice(0, 3).map((x: any) => `${x.day} ${x.from}–${x.to}`).join(' · ') : t('schedule.never')}</div></div>
                <Countdown res={r} fetchedAt={fetchedAt} tick={sim ? fetchedAt : tick} label={open ? t('schedule.closesIn') : t('schedule.opensIn')} lang={lang} />
                <div><div className="text-xs text-muted">{open ? t('schedule.nextClose') : t('schedule.nextOpen')}</div><div className="ltr text-sm">{(open ? r.next_close : r.next_open)?.replace('T', ' ').slice(0, 16) ?? '—'}</div></div>
                {!open && r.open_duration_seconds != null && <div><div className="text-xs text-muted">{t('schedule.lasts')}</div><div className="ltr text-sm">{fmtDuration(r.open_duration_seconds)}</div></div>}
              </div>}
            </Card>); })}
        </div>
      </div>
    </div>
  );
}
