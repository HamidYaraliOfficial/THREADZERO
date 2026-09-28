'use client';
import { CheckCircle2, ChevronRight, XCircle } from 'lucide-react';
import React, { useState } from 'react';
import { Badge, Button, Card, CardHeader, Empty, Field, Input, Mono, PageHeader, Select, Switch, Tabs } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { dayNames } from '@/lib/i18n';
import { useApp } from '@/lib/store';
import { cn } from '@/lib/util';

function Tree({ n, depth = 0 }: { n: any; depth?: number }) {
  return <div style={{ marginInlineStart: depth * 14 }} className="ltr text-xs"><span className={n.value ? 'text-ok' : 'text-danger'}>{n.value ? '✔' : '✘'}</span> {n.children ? <b>{n.op}</b> : <>{n.text}{n.actual ? <span className="text-muted"> ({n.actual})</span> : null}</>}{n.children?.map((c: any, i: number) => <Tree key={i} n={c} depth={depth + 1} />)}</div>;
}
const tone = (d: string) => (d === 'allow' ? 'ok' : d === 'deny' ? 'danger' : 'warn') as any;

export default function SimulatorView() {
  const { t, lang, source, analysis: A, toast } = useApp();
  const [tab, setTab] = useState('policy');
  const [f, setF] = useState<any>({ roles: [] as string[], mfa: true, dt: 3, res: '', action: '', data: '', zone: '', env: '', day: 0, hour: 10, approved: false, emergency: false, secure: true, tenant: true });
  const [out, setOut] = useState<any>(null);
  const [flow, setFlow] = useState<string>(''); const [prov, setProv] = useState<string[]>([]); const [bout, setBout] = useState<any>(null); const [step, setStep] = useState(-1); const [journey, setJourney] = useState<any[]>([]);
  if (!A) return <Empty />;
  const S = A.symbols; const dn = dayNames(lang);
  const set = (p: any) => setF({ ...f, ...p });
  const evaluate = async () => {
    const req: any = { subject: { roles: f.roles, mfa: f.mfa, device_trust: f.dt }, action: f.action || undefined, data: f.data || undefined, zone: f.zone || undefined, resource: f.res || undefined, env: f.env || undefined,
      context: { time: f.day * 1440 + f.hour * 60, approved: f.approved, emergency: f.emergency, secure_channel: f.secure, tenant_match: f.tenant } };
    try { setOut(await api('/api/simulate', { source, request: req })); } catch (e: any) { toast(e.message, 'err'); }
  };
  const edges = A.graph.edges;
  const pickFlow = (id: string) => { setFlow(id); const e = edges.find((x: any) => x.id === id); setProv(e ? e.controls : []); setBout(null); };
  const simFlow = async (id: string, controls: string[]) => {
    const e = edges.find((x: any) => x.id === id); const zone = (n: string) => A.graph.nodes.find((x: any) => x.id === n).zone;
    return api('/api/simulate/boundary', { source, request: { flow: { src_zone: zone(e.from), dst_zone: zone(e.to), controls, source: e.from, destination: e.to }, data: e.data[0], action: e.op, context: { secure_channel: e.channel === 'tls' || e.channel === 'mtls' } } });
  };
  const runBoundary = async () => { try { setBout(await simFlow(flow, prov)); } catch (e: any) { toast(e.message, 'err'); } };
  const runJourney = async (dataName: string) => {
    const lin = A.lineage.find((l: any) => l.data === dataName); const path = lin?.journeys[0] ?? []; const res: any[] = []; setJourney([]); setStep(-1);
    for (let i = 0; i < path.length; i++) { const e = edges.find((x: any) => x.id === path[i].flow); res.push({ flow: path[i].flow, crossing: path[i].crossing, r: await simFlow(path[i].flow, e.controls) }); setStep(i); setJourney([...res]); await new Promise((r) => setTimeout(r, 450)); }
  };
  return (
    <div>
      <PageHeader title={t('sim.title')} actions={<Tabs className="border-0" value={tab} onChange={setTab} tabs={[{ id: 'policy', label: t('nav.policies') }, { id: 'boundary', label: t('sim.boundary') }]} />} />
      {tab === 'policy' ? <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-2"><CardHeader title={t('request')} />
          <div className="p-4 grid grid-cols-2 gap-3">
            <Field label={t('sim.roles')} className="col-span-2"><div className="flex gap-1 flex-wrap">{S.roles.map((r: any) => <button key={r.name} onClick={() => set({ roles: f.roles.includes(r.name) ? f.roles.filter((x: string) => x !== r.name) : [...f.roles, r.name] })} className={cn('px-2 py-1 rounded-full border text-xs', f.roles.includes(r.name) ? 'bg-accent text-accent-fg border-accent' : 'border-stroke')}>{r.name}</button>)}</div></Field>
            <Field label={t('sim.resource')}><Select value={f.res} onChange={(e) => set({ res: e.target.value })}><option value="">—</option>{S.nodes.map((n: any) => <option key={n.name}>{n.name}</option>)}</Select></Field>
            <Field label={t('action')}><Select value={f.action} onChange={(e) => set({ action: e.target.value })}><option value="">—</option>{S.actions.map((n: any) => <option key={n.name}>{n.name}</option>)}</Select></Field>
            <Field label={t('data')}><Select value={f.data} onChange={(e) => set({ data: e.target.value })}><option value="">—</option>{S.data.map((n: any) => <option key={n.name}>{n.name}</option>)}</Select></Field>
            <Field label={t('zone')}><Select value={f.zone} onChange={(e) => set({ zone: e.target.value })}><option value="">—</option>{S.zones.map((n: any) => <option key={n.name}>{n.name}</option>)}</Select></Field>
            <Field label={t('sim.env')}><Select value={f.env} onChange={(e) => set({ env: e.target.value })}><option value="">—</option>{S.envs.map((n: any) => <option key={n.name}>{n.name}</option>)}</Select></Field>
            <Field label={t('sim.deviceTrust')}><Input type="number" min={0} max={5} value={f.dt} onChange={(e) => set({ dt: +e.target.value })} /></Field>
            <Field label={t('sim.day')}><Select value={f.day} onChange={(e) => set({ day: +e.target.value })}>{dn.map((d, i) => <option key={i} value={i}>{d}</option>)}</Select></Field>
            <Field label={t('sim.hour')}><Input type="number" min={0} max={23} value={f.hour} onChange={(e) => set({ hour: +e.target.value })} /></Field>
            <div className="col-span-2 grid grid-cols-2 gap-2"><Switch checked={f.mfa} onChange={(v) => set({ mfa: v })} label={t('policies.mfa')} /><Switch checked={f.approved} onChange={(v) => set({ approved: v })} label={t('sim.approved')} /><Switch checked={f.emergency} onChange={(v) => set({ emergency: v })} label={t('sim.emergency')} /><Switch checked={f.secure} onChange={(v) => set({ secure: v })} label={t('sim.secure')} /><Switch checked={f.tenant} onChange={(v) => set({ tenant: v })} label={t('sim.tenant')} /></div>
            <Button variant="primary" className="col-span-2" onClick={evaluate}>{t('sim.evaluate')}</Button></div></Card>
        <div className="xl:col-span-3 space-y-4">{!out ? <Empty>{t('sim.evaluate')}</Empty> : <>
          <Card className="p-4 fluent-in"><div className="flex items-center gap-3"><Badge tone={tone(out.decision.decision)} className="text-base px-3 py-1">{out.decision.decision.toUpperCase()}</Badge><span>{out.decision.reason_text || out.decision.reason}</span><span className="ms-auto text-xs text-muted ltr">{out.decision.duration_us.toFixed(0)} µs · #{out.decision.audit?.hash}</span></div>
            {out.decision.obligations.length > 0 && <div className="mt-3"><span className="text-xs text-muted">{t('obligations')}: </span>{out.decision.obligations.map((o: string) => <Badge key={o} tone="info">{o}</Badge>)}</div>}
            {out.context.flags.length > 0 && <div className="mt-2"><span className="text-xs text-muted">{t('sim.context')}: </span>{out.context.flags.map((o: string) => <Badge key={o} tone="warn">{o}</Badge>)}</div>}</Card>
          <Card><CardHeader title={t('sim.steps')} /><ol className="p-4 space-y-1 list-decimal ps-8">{out.steps.map((s: string, i: number) => <li key={i}>{s}</li>)}</ol></Card>
          <Card><CardHeader title={t('sim.graph')} /><div className="p-4 flex items-center gap-2 flex-wrap ltr"><Badge tone="info">request</Badge><ChevronRight className="h-4 w-4" />{out.graph.nodes.filter((n: any) => n.type === 'rule').map((n: any) => <span key={n.id} className={cn('px-2 py-1 rounded border text-xs', n.won ? 'border-accent bg-accent/15 font-semibold' : 'border-stroke')}>{n.label} <i className="text-muted">({n.effect})</i></span>)}<ChevronRight className="h-4 w-4" /><Badge tone={tone(out.decision.decision)}>{out.decision.decision}</Badge></div></Card>
          <Card><CardHeader title={`${t('sim.allRules')} (${out.rules.filter((r: any) => r.matched).length}/${out.rules.length} ${t('sim.matched')})`} />
            <div className="divide-y divide-stroke/60 max-h-[50vh] overflow-auto">{out.rules.map((r: any) => <details key={r.id} className="px-4 py-2" open={r.won}><summary className="cursor-pointer flex items-center gap-2">{r.matched ? <CheckCircle2 className="h-4 w-4 text-ok" /> : <XCircle className="h-4 w-4 text-muted" />}<span className={cn(r.won && 'text-accent font-semibold')}>{r.id}</span><Badge tone={r.effect === 'allow' ? 'ok' : r.effect === 'deny' ? 'danger' : 'warn'}>{r.effect}</Badge><span className="text-xs text-muted ltr">p{r.priority}/{r.specificity}</span></summary>{r.tree && <div className="mt-2"><Tree n={r.tree} /></div>}</details>)}</div></Card></>}</div>
      </div> : <div className="grid gap-4 lg:grid-cols-2">
        <Card><CardHeader title={t('sim.boundary')} />
          <div className="p-4 space-y-3"><Field label={t('flow')}><Select value={flow} onChange={(e) => pickFlow(e.target.value)}><option value="">—</option>{edges.map((e: any) => <option key={e.id} value={e.id}>{e.id} · {e.from} → {e.to}{e.crossing ? ' ⛔' : ''}</option>)}</Select></Field>
            <Field label={t('sim.provided')}><div className="flex gap-1 flex-wrap">{S.controls.map((c: any) => <button key={c.name} onClick={() => setProv(prov.includes(c.name) ? prov.filter((x) => x !== c.name) : [...prov, c.name])} className={cn('px-2 py-1 rounded-full border text-xs', prov.includes(c.name) ? 'bg-ok/20 border-ok' : 'border-stroke text-muted')}>{c.name}</button>)}</div></Field>
            <Button variant="primary" disabled={!flow} onClick={runBoundary}>{t('sim.simulateFlow')}</Button>
            {bout && <div className="fluent-in space-y-2"><Badge tone={bout.flow.ok ? 'ok' : 'danger'} className="text-sm px-3">{bout.flow.ok ? '✔ OK' : '✘ ' + bout.flow.reason}</Badge><div>{bout.explanation}</div>
              <div className="text-xs text-muted">required: {bout.flow.required_controls.map((c: string) => <Badge key={c} tone={bout.flow.missing_controls.includes(c) ? 'danger' : 'ok'}>{c}</Badge>)}</div></div>}</div></Card>
        <Card><CardHeader title={t('flows.journeys')} />
          <div className="p-4 space-y-3"><div className="flex gap-2 flex-wrap">{A.lineage.map((l: any) => <Button key={l.data} size="sm" onClick={() => runJourney(l.data)}>{l.data} ▶</Button>)}</div>
            <ol className="space-y-2">{journey.map((j, i) => <li key={i} className={cn('flex items-center gap-2 border rounded-win px-3 py-2 fluent-in', j.r.flow.ok ? 'border-ok/50' : 'border-danger/60')}><Badge tone={j.crossing ? 'accent' : 'muted'}>{j.crossing ? '⛔ ' + t('canvas.crossing') : t('canvas.internal')}</Badge><b>{j.flow}</b>{j.r.flow.ok ? <CheckCircle2 className="h-4 w-4 text-ok ms-auto" /> : <span className="ms-auto text-xs text-danger">{j.r.flow.missing_controls.join(', ') || j.r.flow.reason}</span>}</li>)}</ol></div></Card>
      </div>}
    </div>
  );
}
