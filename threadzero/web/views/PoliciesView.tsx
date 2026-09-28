'use client';
import React, { useState } from 'react';
import { Badge, Button, Card, CardHeader, Empty, Field, Input, PageHeader, Select, SevBadge, Switch, Table, Tabs } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { useApp } from '@/lib/store';
import { cn } from '@/lib/util';

const eff = (e: string) => (e === 'allow' ? 'ok' : e === 'deny' ? 'danger' : 'warn') as any;
export default function PoliciesView() {
  const { t, source, analysis: A, toast } = useApp();
  const [tab, setTab] = useState('rules');
  const [sel, setSel] = useState<any>(null);
  const [roles, setRoles] = useState<string[]>([]);
  const [mfa, setMfa] = useState(true);
  const [dt, setDt] = useState(3);
  const [perm, setPerm] = useState<any>(null);
  if (!A) return <Empty />;
  const P = A.policy;
  const explore = async () => { try { setPerm(await api('/api/permissions', { source, roles, mfa, deviceTrust: dt, includeDenied: false })); } catch (e: any) { toast(e.message, 'err'); } };
  const cov = P.coverage;
  return (
    <div>
      <PageHeader title={t('policies.title')} subtitle={`${P.rules.length} ${t('studio.rules')} · ${P.solver}`} />
      <Card><Tabs value={tab} onChange={setTab} tabs={[{ id: 'rules', label: t('policies.rules') }, { id: 'conflicts', label: <>{t('policies.conflicts')} <Badge tone={P.conflicts.length ? 'warn' : 'muted'}>{P.conflicts.length}</Badge></> },
          { id: 'coverage', label: t('policies.coverage') }, { id: 'opt', label: <>{t('policies.optimize')} <Badge>{P.optimizations.length}</Badge></> }, { id: 'perm', label: t('policies.permissions') }, { id: 'win', label: t('policies.windows') }]} />
        {tab === 'rules' && <div className="grid lg:grid-cols-3">
          <div className="lg:col-span-2"><Table onRow={(i) => setSel(P.rules[i])} head={['#', t('rule'), t('effect'), t('priority'), t('policies.condition')]} rows={P.rules.map((r: any) => [r.idx, <span key="i" className={cn(sel?.id === r.id && 'text-accent font-semibold')}>{r.id}</span>, <Badge key="e" tone={eff(r.effect)}>{r.effect}</Badge>, `${r.priority}/${r.specificity}`, <code key="c" className="ltr text-xs">{r.condText}</code>])} /></div>
          <div className="border-s border-stroke p-4"><div className="font-semibold mb-2">{t('policies.inspector')}</div>{!sel ? <div className="text-muted">{t('canvas.hint').split(';')[0]}</div> : <div className="space-y-2 text-sm fluent-in">
            <div className="text-base font-semibold">{sel.id}</div><Badge tone={eff(sel.effect)}>{sel.effect}</Badge> <Badge>v{sel.version}</Badge>
            <div><span className="text-muted">{t('policies.condition')}</span><pre className="ltr text-xs bg-layer2 p-2 rounded border border-stroke whitespace-pre-wrap">{sel.condText}</pre></div>
            <div><span className="text-muted">{t('reason')}</span> {sel.reason}</div>{sel.obligations.length > 0 && <div>{t('obligations')}: {sel.obligations.map((o: string) => <Badge key={o} tone="info">{o}</Badge>)}</div>}
            <div className="ltr text-xs text-muted">{sel.file}:{sel.line}</div>
            <div className="text-xs text-muted">{t('nav.tests')}: {A.policy.tests.filter((x: any) => x.rule === sel.id).length}</div></div>}</div></div>}
        {tab === 'conflicts' && <Table head={[t('category'), t('severity'), 'Allow', 'Deny', 'Winner', t('details')]} empty="—" rows={P.conflicts.map((c: any) => [c.kind, <SevBadge key="s" sev={c.severity} />, c.allow, c.deny, c.winner, <span key="e" className="text-xs">{c.explain}</span>])} />}
        {tab === 'coverage' && <div><div className="p-3 text-muted text-sm">{cov.filter((c: any) => c.covered).length}/{cov.length} {t('policies.covered')}</div>
          <Table head={[t('flow'), t('data'), t('status'), t('rule')]} rows={cov.map((c: any) => [c.flow, c.data, <Badge key="s" tone={c.covered ? (c.explicit ? 'ok' : 'warn') : 'danger'}>{c.covered ? t('policies.covered') : t('policies.uncovered')}</Badge>, <span key="r" className="text-xs">{c.rules.join(', ') || '—'}</span>])} />
          <div className="p-3 text-xs text-muted">{t('nav.tests')}: control coverage → <b>{A.controlCoverage.length}</b> {t('studio.flows')}</div></div>}
        {tab === 'opt' && <Table head={[t('kind'), t('rule'), t('details'), t('fix')]} empty="—" rows={P.optimizations.map((o: any) => [o.kind, o.rules.join(', '), o.message, <span key="p" className="text-accent">{o.proposal}</span>])} />}
        {tab === 'perm' && <div className="p-4 space-y-3">
          <div className="flex flex-wrap gap-3 items-end"><Field label={t('policies.role')}><div className="flex gap-1 flex-wrap">{A.symbols.roles.map((r: any) => <button key={r.name} onClick={() => setRoles(roles.includes(r.name) ? roles.filter((x) => x !== r.name) : [...roles, r.name])} className={cn('px-2 py-1 rounded-full border text-xs', roles.includes(r.name) ? 'bg-accent text-accent-fg border-accent' : 'border-stroke')}>{r.name}</button>)}</div></Field>
            <Switch checked={mfa} onChange={setMfa} label={t('policies.mfa')} /><Field label={t('sim.deviceTrust')}><Input type="number" min={0} max={5} value={dt} onChange={(e) => setDt(+e.target.value)} className="w-20" /></Field><Button variant="primary" onClick={explore}>{t('policies.explore')}</Button></div>
          {perm && <><div className="text-sm text-muted">{perm.total} {t('result')}</div><Table head={[t('nav.canvas').split(' ')[0] ? t('node') : '', t('zone'), t('data'), t('action'), t('decision'), t('reason')]} rows={perm.rows.map((r: any) => [r.resource, r.zone, r.data, r.action, <Badge key="d" tone={r.decision === 'allow' ? 'ok' : 'warn'}>{r.decision}</Badge>, <span key="r" className="text-xs">{r.reason}</span>])} />
            {perm.delegations.length > 0 && <div><div className="font-semibold mt-3">Delegation</div>{perm.delegations.map((d: any) => <div key={d.name} className="ltr text-sm">{d.from} → {d.to} · {d.role} · {d.expires} (chain ≤ {d.chain_max})</div>)}</div>}</>}</div>}
        {tab === 'win' && <Table head={[t('name'), t('schedule.kind'), t('schedule.days'), t('schedule.tz')]} rows={P.windows.map((w: any) => [w.name, w.kind, w.ranges.length + ' ranges', w.tz])} />}
      </Card>
    </div>
  );
}
