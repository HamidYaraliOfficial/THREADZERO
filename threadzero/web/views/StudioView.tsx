'use client';
import { AlertTriangle, CheckCircle2, MinusCircle } from 'lucide-react';
import Link from 'next/link';
import React from 'react';
import { BarChart, Badge, Button, Card, CardHeader, Empty, PageHeader, Select, SevBadge, Stat, Table } from '@/components/ui/kit';
import { useApp } from '@/lib/store';
import { num } from '@/lib/i18n';

export default function StudioView() {
  const { t, lang, analysis: A, examples, loadExample } = useApp();
  const n = (x: any) => num(lang, x);
  const sev = A?.metrics?.findingsBySeverity ?? {};
  const cov = A?.policy?.coverage ?? [];
  const covPct = cov.length ? Math.round((100 * cov.filter((c: any) => c.covered).length) / cov.length) : 100;
  return (
    <div>
      <PageHeader title={t('studio.title')} subtitle={t('studio.subtitle')} actions={<>
        <Select className="w-64" defaultValue="" onChange={(e) => e.target.value && loadExample(e.target.value)} aria-label={t('studio.loadExample')}>
          <option value="">{t('studio.loadExample')}…</option>{examples.map((e) => <option key={e.name} value={e.name}>{e.name}</option>)}</Select>
        <Link href="/editor/"><Button>{t('studio.open')}</Button></Link></>} />
      {!A ? <Empty /> : (
        <div className="space-y-4 fluent-in">
          <Card className="p-4 flex flex-wrap items-center gap-3"><div className="text-lg font-semibold">{A.project.name}</div><Badge tone="accent">v{A.project.version}</Badge><Badge>{A.project.timezone}</Badge>
            <Badge tone={A.ok ? 'ok' : 'danger'}>{A.ok ? t('ready') : `${A.errorCount} ${t('errors')}`}</Badge><span className="text-muted ltr text-xs">#{A.sourceHash.slice(0, 12)}</span></Card>
          <div className="grid gap-3 grid-cols-2 md:grid-cols-3 xl:grid-cols-6">
            <Stat label={t('studio.nodes')} value={n(A.metrics.nodes)} /><Stat label={t('studio.flows')} value={n(A.metrics.flows)} /><Stat label={t('studio.zones')} value={n(A.metrics.zones)} />
            <Stat label={t('studio.crossings')} value={n(A.metrics.boundaryCrossings)} /><Stat label={t('studio.rules')} value={n(A.metrics.rules)} /><Stat label={t('studio.coverage')} value={`${n(covPct)}%`} tone={covPct < 80 ? 'text-warn' : 'text-ok'} />
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card><CardHeader title={t('studio.bySeverity')} /><div className="p-4"><BarChart data={['Critical', 'High', 'Medium', 'Low'].map((s) => ({ label: t(`sev.${s}`), value: sev[s] ?? 0, color: s === 'Critical' ? 'rgb(var(--danger))' : s === 'High' ? 'rgb(var(--danger)/.7)' : s === 'Medium' ? 'rgb(var(--warn))' : 'rgb(var(--info))' }))} /></div></Card>
            <Card><CardHeader title={t('studio.properties')} />
              <ul className="p-2 grid sm:grid-cols-2 gap-1">{A.properties.map((p: any) => (
                <li key={p.name} className="flex items-center justify-between gap-2 px-3 py-2 rounded hover:bg-stroke/30">
                  <span className="flex items-center gap-2">{p.status === 'holds' ? <CheckCircle2 className="h-4 w-4 text-ok" /> : p.status === 'violated' ? <AlertTriangle className="h-4 w-4 text-danger" /> : <MinusCircle className="h-4 w-4 text-muted" />}{p.name}</span>
                  <Badge tone={p.status === 'holds' ? 'ok' : p.status === 'violated' ? 'danger' : 'muted'}>{t(`studio.${p.status}`)}</Badge></li>))}</ul></Card>
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card><CardHeader title={t('studio.assertions')} actions={<Link href="/tests/" className="text-accent text-xs">{t('nav.tests')} →</Link>} />
              <Table head={[t('name'), t('status'), t('path')]} rows={A.assertions.map((a: any) => [a.name, <Badge key="s" tone={a.status === 'violated' ? 'danger' : a.status === 'discharged' ? 'ok' : 'warn'}>{a.status}</Badge>, <span key="m" className="text-muted text-xs">{a.method}</span>])} /></Card>
            <Card><CardHeader title={t('findings')} actions={<Link href="/findings/" className="text-accent text-xs">{t('nav.findings')} →</Link>} />
              <Table head={[t('severity'), t('category'), t('flow')]} rows={A.findings.slice(0, 6).map((f: any) => [<SevBadge key="s" sev={f.severity} />, f.category, f.flow ?? f.affected?.[0]])} empty={t('findings.none')} /></Card>
          </div>
        </div>)}
    </div>
  );
}
