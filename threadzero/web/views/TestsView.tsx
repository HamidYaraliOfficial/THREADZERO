'use client';
import React, { useState } from 'react';
import { Badge, Button, Card, CardHeader, Empty, Mono, PageHeader, Stat, Switch, Table } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { useApp } from '@/lib/store';

export default function TestsView() {
  const { t, source, analysis: A, toast } = useApp();
  const [res, setRes] = useState<any>(null); const [busy, setBusy] = useState(false); const [failedOnly, setFailedOnly] = useState(false); const [targets, setTargets] = useState(false); const [sec, setSec] = useState('all'); const [open, setOpen] = useState<number | null>(null);
  if (!A) return <Empty />;
  const run = async () => { setBusy(true); try { setRes(await api('/api/tests', { source, targets })); } catch (e: any) { toast(e.message, 'err'); } setBusy(false); };
  const cases = (res?.cases ?? []).filter((c: any) => (!failedOnly || !c.ok) && (sec === 'all' || c.section === sec));
  return (
    <div>
      <PageHeader title={t('tests.title')} actions={<><Switch checked={targets} onChange={setTargets} label={t('tests.targets')} /><Switch checked={failedOnly} onChange={setFailedOnly} label={t('tests.onlyFailed')} /><Button variant="primary" loading={busy} onClick={run}>{t('tests.run')}</Button></>} />
      {!res ? <Empty>{t('tests.run')}</Empty> : <div className="space-y-4 fluent-in">
        <div className="grid gap-3 grid-cols-2 lg:grid-cols-6"><Stat label={t('total')} value={res.total} /><Stat label={t('passed')} value={res.passed} tone="text-ok" /><Stat label={t('failed')} value={res.failed} tone={res.failed ? 'text-danger' : 'text-ok'} />
          {Object.entries(res.sections).slice(0, 3).map(([k, v]: any) => <button key={k} onClick={() => setSec(sec === k ? 'all' : k)} className="text-start"><Stat label={k} value={<span>{v.passed}{v.failed ? <span className="text-danger text-base"> /{v.failed}</span> : null}</span>} /></button>)}</div>
        <div className="flex gap-1 flex-wrap">{['all', ...Object.keys(res.sections)].map((s) => <button key={s} onClick={() => setSec(s)} className={`px-2 py-1 rounded-full text-xs border ${sec === s ? 'bg-accent text-accent-fg border-accent' : 'border-stroke'}`}>{s}</button>)}</div>
        <Card><Table onRow={(i) => setOpen(open === i ? null : i)} head={[t('status'), 'Section', t('name'), t('kind'), t('policy'), t('tests.trace')]} rows={cases.slice(0, 400).map((c: any, i: number) => [<Badge key="s" tone={c.ok ? 'ok' : 'danger'}>{c.ok ? '✔' : '✘'}</Badge>, c.section, <span key="n" className="text-xs">{c.name}</span>, c.kind, <span key="p" className="text-xs">{c.policy}</span>, <span key="t" className="text-xs ltr">{(c.trace ?? []).join(', ')}</span>])} />
          {open != null && cases[open] && <div className="p-4 border-t border-stroke grid md:grid-cols-3 gap-3 fluent-in">
            {[['request', cases[open].request], [t('tests.expected'), cases[open].expected], [t('tests.actual'), cases[open].actual]].map(([k, v]: any) => <div key={k}><div className="text-xs text-muted mb-1">{k}</div><pre className="ltr text-xs bg-layer2 border border-stroke rounded-win p-2 whitespace-pre-wrap break-words max-h-64 overflow-auto">{JSON.stringify(v, null, 1)}</pre></div>)}</div>}</Card>
        <p className="text-xs text-muted">{cases.length > 400 ? `showing 400 / ${cases.length}` : ''}</p></div>}
    </div>
  );
}
