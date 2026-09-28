'use client';
import { useRouter } from 'next/navigation';
import React, { useEffect, useState } from 'react';
import { Badge, Button, Card, CardHeader, Empty, Modal, PageHeader, Select, SevBadge, Spinner, Table } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { useApp } from '@/lib/store';
import { cn, lineDiff } from '@/lib/util';

const METRICS: [string, string][] = [['findings', 'findings'], ['boundaryCrossings', 'studio.crossings'], ['guards', 'controls'], ['policyRules', 'studio.rules'], ['policyComplexity', 'policies.condition'], ['components', 'studio.nodes'], ['flows', 'studio.flows'], ['dataMovement', 'data'], ['runtimeOverheadEstimateMs', 'wasm.throughput']];

export default function RefactorView() {
  const { t, source, setSource, analysis: A, toast } = useApp();
  const router = useRouter();
  const [fid, setFid] = useState(''); const [res, setRes] = useState<any>(null); const [busy, setBusy] = useState(false); const [diff, setDiff] = useState<any>(null);
  useEffect(() => { if (!A?.findings.length) return; const s = sessionStorage.getItem('tz.finding'); setFid(A.findings.find((f: any) => f.id === s)?.id ?? A.findings[0].id); }, [A?.sourceHash]); // eslint-disable-line
  useEffect(() => { if (!fid) return; setBusy(true); api('/api/refactor', { source, findingId: fid }).then(setRes).catch((e) => toast(e.message, 'err')).finally(() => setBusy(false)); }, [fid, A?.sourceHash]); // eslint-disable-line
  if (!A) return <Empty />;
  const base = res?.base?.scorecard;
  const C = res?.candidates ?? [];
  const delta = (k: string, v: number) => { const d = +(v - base[k]).toFixed(2); return d === 0 ? <span className="text-muted">=</span> : <span className={d < 0 && (k === 'findings' || k === 'boundaryCrossings') ? 'text-ok' : d > 0 && k === 'findings' ? 'text-danger' : 'text-warn'}>{d > 0 ? '+' : ''}{d}</span>; };
  return (
    <div>
      <PageHeader title={t('refactor.title')} subtitle={t('refactor.notice')} actions={<Select className="w-96" value={fid} onChange={(e) => setFid(e.target.value)} aria-label={t('refactor.pick')}>{A.findings.map((f: any) => <option key={f.id} value={f.id}>{f.id} · {f.severity} · {f.category}{f.flow ? ` · ${f.flow}` : ''}</option>)}</Select>} />
      {!A.findings.length ? <Empty>{t('findings.none')}</Empty> : busy || !res ? <div className="p-10 flex justify-center"><Spinner /></div> : <div className="space-y-4 fluent-in">
        {res.finding && <Card className="p-4 flex flex-wrap gap-3 items-center"><SevBadge sev={res.finding.severity} /><b>{res.finding.category}</b><span className="text-muted">{res.finding.message}</span></Card>}
        {!C.length ? <Empty>{t('refactor.noCandidates')}</Empty> : <>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <Card><CardHeader title={<>{t('refactor.current')}</>} /><div className="p-4 space-y-2 text-sm">{METRICS.map(([k, l]) => <div key={k} className="flex justify-between"><span className="text-muted">{t(l)}</span><b>{base[k]}</b></div>)}
              <div className="flex gap-1 flex-wrap pt-1">{Object.entries(base.residualBySeverity).filter(([, v]: any) => v).map(([k, v]: any) => <Badge key={k} tone={k === 'Critical' || k === 'High' ? 'danger' : 'warn'}>{t(`sev.${k}`)} {v}</Badge>)}</div></div></Card>
            {C.slice(0, 3).map((c: any) => (
              <Card key={c.id} className={cn(!c.valid && 'opacity-60')}><CardHeader title={<span className="flex items-center gap-2"><Badge tone="accent">{c.id}</Badge>{c.title}</span>} />
                <div className="p-4 space-y-3 text-sm"><p className="text-muted">{c.description}</p>
                  <div><div className="text-xs text-muted">{t('refactor.pre')}</div>{c.preconditions.map((p: any, i: number) => <div key={i}>{p.holds ? '✔' : '✘'} {p.text}</div>)}</div>
                  <div><div className="text-xs text-muted">{t('refactor.post')}</div>{c.postconditions.map((p: any, i: number) => <div key={i} className={p.holds ? 'text-ok' : 'text-danger'}>{p.holds ? '✔' : '✘'} {p.text}</div>)}</div>
                  <div className="flex gap-1 flex-wrap"><Badge tone="ok">−{c.securityImpact.removed.length} {t('refactor.removed')}</Badge><Badge tone={c.securityImpact.added.length ? 'danger' : 'muted'}>+{c.securityImpact.added.length} {t('refactor.added')}</Badge><Badge>{c.securityImpact.remaining} {t('refactor.remaining')}</Badge></div>
                  <div className="text-xs text-muted">{t('refactor.cost')}: {c.cost.newComponents} {t('refactor.components')}, +{c.cost.rulesAdded} {t('studio.rules')}, ≈{c.cost.latencyEstimateMs} ms · <Badge tone={c.functionalImpact.equivalent ? 'ok' : 'danger'}>{t('refactor.equivalent')}: {c.functionalImpact.equivalent ? t('yes') : t('no')}</Badge></div>
                  {c.residualRisk.length > 0 && <div className="text-xs"><span className="text-muted">{t('refactor.residual')}: </span>{c.residualRisk.slice(0, 4).map((r: any, i: number) => <Badge key={i} tone="warn">{r.category}</Badge>)}</div>}
                  <div className="flex gap-2"><Button size="sm" onClick={() => setDiff(c)}>{t('refactor.diff')}</Button><Button size="sm" variant="primary" disabled={!c.valid} onClick={() => { setSource(c.dsl); toast(`${c.id}`, 'ok'); router.push('/editor/'); }}>{t('refactor.apply')}</Button></div></div></Card>))}
          </div>
          <Card><CardHeader title={t('refactor.scorecard')} />
            <Table head={['', t('refactor.current'), ...C.slice(0, 3).map((c: any) => `${t('refactor.candidate')} ${c.id}`)]} rows={METRICS.map(([k, l]) => [t(l), base[k], ...C.slice(0, 3).map((c: any) => <span key={c.id}>{c.scorecard[k]} {delta(k, c.scorecard[k])}</span>)])} />
            <p className="px-4 pb-3 text-xs text-muted">{t('refactor.scorecard')} — runtime overhead is an estimate.</p></Card></>}
      </div>}
      <Modal wide open={!!diff} onClose={() => setDiff(null)} title={diff && `${t('refactor.diff')} — ${diff.title}`}>
        {diff && <pre className="ltr text-xs font-mono overflow-auto max-h-[60vh] rounded-win border border-stroke">{lineDiff(res.base.dsl, diff.dsl).filter((l, i, a) => l.t !== ' ' || a.slice(Math.max(0, i - 2), i + 3).some((x) => x.t !== ' ')).map((l, i) => <div key={i} className={cn('px-2 whitespace-pre', l.t === '+' && 'bg-ok/15', l.t === '-' && 'bg-danger/15')}>{l.t} {l.s}</div>)}</pre>}
      </Modal>
    </div>
  );
}
