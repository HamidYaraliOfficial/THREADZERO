'use client';
import React, { useEffect, useState } from 'react';
import { Badge, Button, Card, CardHeader, Empty, Input, PageHeader, Select, SevBadge, Stat, Table } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { useApp } from '@/lib/store';

function History({ data }: { data: any[] }) {
  if (data.length < 1) return <div className="p-4 text-muted">—</div>;
  const w = 520, h = 140, max = Math.max(1, ...data.flatMap((d) => [d.findings, d.boundaryCrossings ?? 0]));
  const pts = (k: string) => data.map((d, i) => `${data.length === 1 ? w / 2 : (i / (data.length - 1)) * (w - 40) + 20},${h - 20 - ((d[k] ?? 0) / max) * (h - 40)}`).join(' ');
  return <div className="p-4 ltr"><svg viewBox={`0 0 ${w} ${h}`} className="w-full"><polyline fill="none" stroke="rgb(var(--danger))" strokeWidth="2" points={pts('findings')} /><polyline fill="none" stroke="rgb(var(--accent))" strokeWidth="2" points={pts('boundaryCrossings')} />
    {data.map((d, i) => <circle key={i} cx={data.length === 1 ? w / 2 : (i / (data.length - 1)) * (w - 40) + 20} cy={h - 20 - (d.findings / max) * (h - 40)} r="3" fill="rgb(var(--danger))" />)}</svg>
    <div className="flex gap-4 text-xs"><span className="text-danger">● {'findings'}</span><span className="text-accent">● boundary crossings</span></div></div>;
}

export default function ImpactView() {
  const { t, source, examples, toast, analysis: A } = useApp();
  const [base, setBase] = useState(''); const [res, setRes] = useState<any>(null); const [busy, setBusy] = useState(false);
  const [snaps, setSnaps] = useState<any[]>([]); const [hist, setHist] = useState<any[]>([]); const [label, setLabel] = useState(''); const [pair, setPair] = useState<string[]>(['', '']); const [sd, setSd] = useState<any>(null);
  const load = () => { api('/api/snapshots').then(setSnaps).catch(() => {}); api('/api/history').then(setHist).catch(() => {}); };
  useEffect(load, []);
  const run = async () => { if (!base) return; setBusy(true); try { setRes(await api('/api/impact', { base, head: source })); } catch (e: any) { toast(e.message, 'err'); } setBusy(false); };
  const loadBase = async (n: string) => { if (n) setBase((await api(`/api/examples/${n}`)).source); };
  const snap = async () => { await api('/api/snapshots', { source, label }); toast('✔', 'ok'); load(); };
  const cmp = async () => { if (pair[0] && pair[1]) setSd(await api(`/api/snapshots/diff?a=${pair[0]}&b=${pair[1]}`)); };
  const g = res?.diff?.gate;
  return (
    <div>
      <PageHeader title={t('impact.title')} actions={<><Select className="w-56" defaultValue="" onChange={(e) => loadBase(e.target.value)}><option value="">{t('impact.useExample')}…</option>{examples.map((e) => <option key={e.name} value={e.name}>{e.name}</option>)}</Select><Button variant="primary" loading={busy} disabled={!base || !A} onClick={run}>{t('impact.run')}</Button></>} />
      <div className="grid gap-4 lg:grid-cols-2 mb-4"><Card><CardHeader title={t('impact.base')} /><textarea className="win-input ltr font-mono text-xs h-40 border-0" value={base} onChange={(e) => setBase(e.target.value)} placeholder="project …" /></Card>
        <Card><CardHeader title={t('impact.head')} /><pre className="ltr font-mono text-xs h-40 overflow-auto p-3 text-muted">{source.slice(0, 2000)}</pre></Card></div>
      {res && <div className="space-y-4 fluent-in">
        <div className="grid gap-3 grid-cols-2 lg:grid-cols-5"><Stat label={t('impact.new')} value={res.diff.findings.new.length} tone={res.diff.findings.new.length ? 'text-danger' : 'text-ok'} /><Stat label={t('impact.fixed')} value={res.diff.findings.fixed.length} tone="text-ok" /><Stat label={t('impact.remaining')} value={res.diff.findings.remaining.length} />
          <Stat label={`${t('studio.coverage')}`} value={`${res.diff.coverage.base}% → ${res.diff.coverage.head}%`} /><Stat label={t('impact.gate')} value={<Badge tone={g.newCritical || g.newErrors || g.newViolatedAssertions.length || g.regressedProperties.length ? 'danger' : g.newHigh ? 'warn' : 'ok'}>{g.newCritical || g.newErrors || g.newViolatedAssertions.length || g.regressedProperties.length ? t('ci.fail') : g.newHigh ? 'warn' : t('ci.pass')}</Badge>} /></div>
        <div className="grid gap-4 lg:grid-cols-2">{(['new', 'fixed'] as const).map((k) => <Card key={k}><CardHeader title={t(`impact.${k}`)} /><Table head={[t('severity'), t('category'), t('details')]} empty="—" rows={res.diff.findings[k].map((f: any) => [<SevBadge key="s" sev={f.severity} />, f.category, <span key="m" className="text-xs">{f.message}</span>])} /></Card>)}</div>
        {res.regression && <Card><CardHeader title={t('impact.regression')} actions={<><Badge tone="danger">{res.regression.loosened} {t('impact.loosened')}</Badge><Badge tone="ok">{res.regression.tightened} {t('impact.tightened')}</Badge><Badge>{res.regression.replayed}</Badge></>} />
          <Table head={[t('request'), 'Base', 'Head', t('reason')]} empty="—" rows={res.regression.changes.slice(0, 40).map((c: any) => [<code key="r" className="ltr text-[11px]">{JSON.stringify({ d: c.request.data, a: c.request.action, z: c.request.zone })}</code>, c.base, <Badge key="h" tone={c.kind === 'loosened' ? 'danger' : 'ok'}>{c.head}</Badge>, <span key="x" className="text-xs">{c.headReason}</span>])} /></Card>}
        <Card><CardHeader title="Graph" /><div className="p-4 grid sm:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">{[['nodesAdded', '+ node'], ['nodesRemoved', '− node'], ['edgesAdded', '+ flow'], ['edgesRemoved', '− flow'], ['edgesChanged', '~ flow']].map(([k, l]) => <div key={k}><div className="text-xs text-muted">{l}</div><div className="flex gap-1 flex-wrap">{res.diff.graph[k].length ? res.diff.graph[k].map((x: string) => <Badge key={x}>{x}</Badge>) : '—'}</div></div>)}</div></Card>
      </div>}
      <div className="grid gap-4 lg:grid-cols-2 mt-4"><Card><CardHeader title={t('impact.snapshots')} actions={<><Input className="w-40" placeholder={t('schedule.label')} value={label} onChange={(e) => setLabel(e.target.value)} /><Button onClick={snap}>{t('impact.snapshot')}</Button></>} />
        <Table head={['ID', t('schedule.label'), t('findings')]} empty="—" rows={snaps.map((s) => [<span key="i" className="ltr text-xs">{s.id}</span>, s.label, Object.values(s.metrics.findingsBySeverity).reduce((a: any, b: any) => a + b, 0) as any])} />
        <div className="p-3 flex gap-2"><Select value={pair[0]} onChange={(e) => setPair([e.target.value, pair[1]])}><option value="">A</option>{snaps.map((s) => <option key={s.id}>{s.id}</option>)}</Select><Select value={pair[1]} onChange={(e) => setPair([pair[0], e.target.value])}><option value="">B</option>{snaps.map((s) => <option key={s.id}>{s.id}</option>)}</Select><Button onClick={cmp}>Diff</Button></div>
        {sd && <div className="px-4 pb-3 text-sm">+{sd.findings.new.length} / −{sd.findings.fixed.length} · {sd.coverage.base}% → {sd.coverage.head}%</div>}</Card>
        <Card><CardHeader title={t('impact.history')} /><History data={hist} /></Card></div>
    </div>
  );
}
