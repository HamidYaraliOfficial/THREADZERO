'use client';
import { ArrowRight, ShieldAlert } from 'lucide-react';
import React, { useEffect, useState } from 'react';
import { Badge, Card, CardHeader, Empty, PageHeader, Select, Table } from '@/components/ui/kit';
import { useApp } from '@/lib/store';
import { cn } from '@/lib/util';

export default function FlowsView() {
  const { t, analysis: A } = useApp();
  const [d, setD] = useState('');
  useEffect(() => { if (A && !d && A.lineage.length) setD(A.lineage[0].data); }, [A, d]);
  if (!A) return <Empty />;
  const lin = A.lineage.find((x: any) => x.data === d);
  const edges = Object.fromEntries(A.graph.edges.map((e: any) => [e.id, e]));
  const timeline = lin ? [...lin.flows].sort((a: any, b: any) => (a.step || 99) - (b.step || 99)) : [];
  return (
    <div>
      <PageHeader title={t('flows.title')} actions={<Select className="w-60" value={d} onChange={(e) => setD(e.target.value)} aria-label={t('flows.pick')}>{A.lineage.map((l: any) => <option key={l.data}>{l.data}</option>)}</Select>} />
      {!lin ? <Empty /> : <div className="grid gap-4 xl:grid-cols-3 fluent-in">
        <Card className="xl:col-span-2"><CardHeader title={<>{lin.data} <Badge tone="accent">{lin.class}</Badge>{lin.effectiveClass !== lin.class && <Badge tone="danger">{t('flows.effective')}: {lin.effectiveClass}</Badge>}</>} />
          <div className="p-4 grid sm:grid-cols-2 gap-4">
            <div><div className="text-xs text-muted mb-1">{t('flows.origins')}</div><div className="flex gap-1 flex-wrap">{lin.origins.map((o: string) => <Badge key={o} tone="info">{o}</Badge>)}</div></div>
            <div><div className="text-xs text-muted mb-1">{t('flows.stores')}</div><div className="flex gap-1 flex-wrap">{lin.stores.length ? lin.stores.map((o: string) => <Badge key={o} tone="ok">{o}</Badge>) : '—'}</div></div>
          </div>
          <div className="px-4 pb-4"><div className="text-xs text-muted mb-2">{t('flows.journeys')}</div>
            <div className="space-y-2">{lin.journeys.length ? lin.journeys.map((j: any[], i: number) => (
              <div key={i} className="flex items-center flex-wrap gap-1 ltr">{j.map((s, k) => { const e = edges[s.flow]; return (
                <React.Fragment key={k}>{k === 0 && <Badge tone="info">{e?.from}</Badge>}<ArrowRight className={cn('h-3.5 w-3.5', s.crossing ? 'text-danger' : 'text-muted')} />
                  <span className={cn('px-1.5 py-0.5 rounded text-[11px] border', s.crossing ? 'border-danger/60 text-danger' : 'border-stroke text-muted')}>{s.flow}{s.crossing ? ' ⛔' : ''}</span><ArrowRight className="h-3.5 w-3.5 text-muted" /><Badge tone={k === j.length - 1 ? 'ok' : 'info'}>{e?.to}</Badge></React.Fragment>); })}</div>)) : <div className="text-muted">—</div>}</div></div>
        </Card>
        <Card><CardHeader title={t('flows.timeline')} />
          <ol className="p-4 relative ltr">{timeline.map((f: any, i: number) => (
            <li key={f.flow} className="ps-6 pb-4 relative"><span className="absolute start-1.5 top-1.5 h-2.5 w-2.5 rounded-full bg-accent" />{i < timeline.length - 1 && <span className="absolute start-[10px] top-4 bottom-0 w-px bg-stroke" />}
              <div className="font-medium">{f.step ? `#${f.step} ` : ''}{f.flow} <span className="text-muted text-xs">v{f.version}</span></div>
              <div className="text-xs text-muted">{f.from} ({f.fromZone}) → {f.to} ({f.toZone}) · {f.op}</div>
              <div className="flex gap-1 flex-wrap mt-1">{f.controls.map((c: string) => <Badge key={c} tone="ok">{c}</Badge>)}</div></li>))}</ol></Card>
        <Card className="xl:col-span-3"><CardHeader title={t('flows.propagation')} icon={<ShieldAlert className="h-4 w-4" />} />
          <Table head={[t('data'), t('flows.lineage'), t('flows.effective'), t('flows.declass')]} rows={A.propagation.map((p: any) => [p.data, p.derivedFrom.join(', ') || '—', <Badge key="e" tone={p.declared !== p.effective ? 'danger' : 'muted'}>{p.declared}{p.declared !== p.effective ? ` → ${p.effective}` : ''}</Badge>,
            A.lineage.find((l: any) => l.data === p.data)?.declassifications.map((x: any) => x.name).join(', ') || ''])} /></Card>
      </div>}
    </div>
  );
}
