'use client';
import { RotateCcw, Wand } from 'lucide-react';
import dynamic from 'next/dynamic';
import React, { useEffect, useState } from 'react';
import { gotoLine } from '@/components/CodeEditor';
import { Badge, Button, Card, CardHeader, diagTone, Empty, Json, PageHeader, Select, SplitPane, Table, Tabs } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { useApp } from '@/lib/store';
import { cn } from '@/lib/util';

const CodeEditor = dynamic(() => import('@/components/CodeEditor'), { ssr: false });
const REF = `project "Name" version "1.0.0" timezone "UTC";
zone Backend trust 3 kind Backend max_class Restricted;
role Admin;   env prod;   window Hours { days: weekdays; from: 09:00; to: 17:00; }
data Card class Financial { operations: [Create, Read]; zones: [Backend]; export: deny; }
service Api in Backend { controls: [authentication, authorization, audit]; }
flow Save from Web to Api carries Card op Create { channel: tls; }
policy P version "1.0.0" priority 100 scope global {
  rule R1: deny when data.classification >= Restricted and zone.trust < 3 reason "…";
  rule R2: allow when subject.role == Admin and subject.mfa and in_window(Hours);
  rule R3: require_mfa when resource == Api and action in [Write, Delete];
}
assert A1: never data Card enters zone PublicInternet;
assert A2: request not subject.mfa and action == Delete must deny;
constraint C1: max_fanout Card 3;
template T(N) { service N in Backend; }   apply T(Worker);   import "lib/common.tz";`;

export default function EditorView() {
  const { t, source, setSource, analysis: A, examples, loadExample, compile, toast } = useApp();
  const [tab, setTab] = useState('diag');
  const [sub, setSub] = useState('ast');
  const [prev, setPrev] = useState<any>(null);
  const [filter, setFilter] = useState<string>('all');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (tab !== 'play' || !A) return;
    const h = setTimeout(async () => { setBusy(true); try { setPrev(await api('/api/compile/preview', { source })); } catch (e: any) { toast(e.message, 'err'); } setBusy(false); }, 500);
    return () => clearTimeout(h);
  }, [tab, source, A?.sourceHash]); // eslint-disable-line

  const diags: any[] = (A?.diagnostics ?? []).filter((d: any) => filter === 'all' || d.severity === filter);
  const count = (s: string) => (A?.diagnostics ?? []).filter((d: any) => d.severity === s).length;
  const format = async () => { try { const r = await api('/api/format', { source }); setSource(r.source); } catch (e: any) { toast(e.message, 'err'); } };

  const right = (
    <Card className="h-full flex flex-col">
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'diag', label: <>{t('editor.diagnostics')} {count('error') ? <Badge tone="danger">{count('error')}</Badge> : null}</> }, { id: 'play', label: t('editor.playground') }, { id: 'docs', label: t('editor.docs') }]} />
      <div className="flex-1 min-h-0 overflow-auto">
        {tab === 'diag' && <div>
          <div className="flex flex-wrap gap-1 p-2 border-b border-stroke">{['all', 'error', 'warning', 'notice', 'finding', 'optimization'].map((s) => (
            <button key={s} onClick={() => setFilter(s)} className={cn('px-2 py-0.5 rounded-full text-xs border', filter === s ? 'bg-accent text-accent-fg border-accent' : 'border-stroke text-muted hover:text-fg')}>{s === 'all' ? t('all') : t(`sev.${s}`)} {s === 'all' ? '' : count(s)}</button>))}</div>
          {A && !count('error') && filter !== 'finding' && filter !== 'optimization' && <div className="px-4 py-3 text-ok">✔ {t('editor.noErrors')}</div>}
          <ul>{diags.map((d, i) => (
            <li key={i} className="border-b border-stroke/60"><button className="w-full text-start px-3 py-2 hover:bg-stroke/30" onClick={() => d.line && gotoLine(d.line)}>
              <div className="flex items-center gap-2"><Badge tone={diagTone(d.severity)}>{t(`sev.${d.severity}`)}</Badge><span className="ltr text-xs text-muted">{d.code}</span><span className="ltr text-xs text-muted ms-auto">{d.file}:{d.line}:{d.col}</span></div>
              <div className="mt-1">{d.message}</div>{d.hint && <div className="text-xs text-accent mt-0.5">💡 {d.hint}</div>}</button></li>))}</ul>
        </div>}
        {tab === 'play' && (!A?.ok ? <div className="p-4 text-muted">{t('editor.noErrors') && A ? `${A.errorCount} ${t('errors')}` : t('analyzing')}</div> : <div>
          <Tabs value={sub} onChange={setSub} tabs={[{ id: 'ast', label: t('editor.ast') }, { id: 'graph', label: t('editor.graph') }, { id: 'policy', label: t('editor.policy') }, { id: 'wasm', label: t('editor.wasm') }, { id: 'tests', label: t('editor.tests') }]} />
          <div className="p-3">{!prev ? <Empty>{t('loading')}</Empty> : <>
            {sub === 'ast' && <Json value={prev.ast} max={30000} />}
            {sub === 'graph' && <Json value={prev.graph} max={20000} />}
            {sub === 'policy' && <div className="space-y-3"><Table head={['#', t('rule'), t('effect'), t('condition')]} rows={prev.policy.rules.map((r: any) => [r.idx, r.id, r.effect, <code key="c" className="ltr text-xs">{r.condText}</code>])} />
              <details><summary className="cursor-pointer text-accent">Rego</summary><Json value={prev.policy.rego} max={20000} /></details>
              <details><summary className="cursor-pointer text-accent">WAT</summary><Json value={prev.policy.wat} max={20000} /></details>
              <details><summary className="cursor-pointer text-accent">{t('editor.json')}</summary><Json value={prev.policy.json} max={20000} /></details></div>}
            {sub === 'wasm' && <Json value={prev.wasm} />}
            {sub === 'tests' && <div className="flex gap-3 flex-wrap">{Object.entries(prev.tests.sections).map(([k, v]: any) => <Card key={k} className="p-3"><div className="text-xs text-muted">{k}</div><div className="text-lg"><span className="text-ok">{v.passed}</span>{v.failed ? <span className="text-danger"> / {v.failed}✘</span> : null}</div></Card>)}</div>}
          </>}{busy && <div className="text-xs text-muted mt-2">{t('compiling')}</div>}</div></div>)}
        {tab === 'docs' && <div className="p-3"><pre className="ltr text-xs whitespace-pre-wrap bg-layer2 rounded-win p-3 border border-stroke">{REF}</pre></div>}
      </div>
    </Card>);

  return (
    <div className="h-[calc(100vh-7.5rem)] flex flex-col">
      <PageHeader title={t('editor.title')} actions={<>
        <Select className="w-52" defaultValue="" onChange={(e) => e.target.value && loadExample(e.target.value)}><option value="">{t('examples')}…</option>{examples.map((e) => <option key={e.name} value={e.name}>{e.name}</option>)}</Select>
        <Button onClick={format}><Wand className="h-4 w-4" />{t('format')}</Button>
        <Button onClick={() => loadExample('secure_api')}><RotateCcw className="h-4 w-4" />{t('editor.reset')}</Button>
        <Button variant="primary" onClick={() => compile()}>{t('compile')}</Button></>} />
      <SplitPane className="flex-1" a={<Card className="h-full overflow-hidden"><CodeEditor value={source} onChange={setSource} diagnostics={A?.diagnostics ?? []} /></Card>} b={right} initial={0.58} />
    </div>
  );
}
