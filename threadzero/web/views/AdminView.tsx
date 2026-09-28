'use client';
import React, { useEffect, useState } from 'react';
import { Badge, Button, Card, CardHeader, Json, Mono, PageHeader, Table } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { useApp } from '@/lib/store';

export default function AdminView() {
  const { t, health, toast } = useApp();
  const [keys, setKeys] = useState<string[]>([]); const [log, setLog] = useState<any[]>([]); const [chain, setChain] = useState<any>(null); const [host, setHost] = useState<any>(null);
  const load = () => { api('/api/keys').then(setKeys).catch(() => {}); api('/api/decisions?n=30').then(setLog).catch(() => {}); api('/api/host/status').then(setHost).catch(() => {}); };
  useEffect(load, []);
  return (
    <div>
      <PageHeader title={t('admin.title')} actions={<Button onClick={load}>↻</Button>} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card><CardHeader title={t('admin.health')} actions={<Badge tone={health?.ok ? 'ok' : 'danger'}>{health?.ok ? 'OK' : 'DOWN'}</Badge>} /><div className="p-4 space-y-1 text-sm">{health && Object.entries(health).map(([k, v]: any) => <div key={k} className="flex justify-between gap-4"><span className="text-muted">{k}</span><Mono>{String(v)}</Mono></div>)}</div></Card>
        <Card><CardHeader title={t('admin.keys')} actions={<Button size="sm" onClick={async () => { const r = await api('/api/keys', {}); toast(`✔ ${r.keyId}`, 'ok'); load(); }}>{t('admin.newKey')}</Button>} />
          <ul className="p-4 space-y-1">{keys.length ? keys.map((k) => <li key={k}><Mono>{k}</Mono> <Badge tone="info">Ed25519</Badge></li>) : <li className="text-muted">—</li>}</ul></Card>
        <Card><CardHeader title={t('admin.host')} /><div className="p-4">{host?.versions.length ? <Table head={[t('version'), 'Project', t('status')]} rows={host.versions.map((v: any) => [<Mono key="i">{v.id}{host.active === v.id ? ' ●' : ''}</Mono>, v.project, <Badge key="s" tone={v.healthy ? 'ok' : 'danger'}>{v.healthy ? 'healthy' : 'unhealthy'}</Badge>])} /> : <span className="text-muted">—</span>}</div></Card>
        <Card><CardHeader title={t('admin.log')} actions={<Button size="sm" onClick={async () => setChain(await api('/api/decisions/verify'))}>{t('admin.verifyLog')}</Button>} />
          {chain && <div className="px-4 pt-3"><Badge tone={chain.ok ? 'ok' : 'danger'}>{chain.ok ? `chain intact · ${chain.records}` : `broken at #${chain.broken_at}`}</Badge></div>}
          <Table head={['#', t('decision'), t('rule'), 'hash']} empty="—" rows={log.slice().reverse().map((r) => [r.seq, <Badge key="d" tone={r.decision === 'allow' ? 'ok' : 'warn'}>{r.decision}</Badge>, <span key="r" className="text-xs">{r.rule}</span>, <Mono key="h">{r.hash.slice(0, 12)}</Mono>])} /></Card>
      </div>
    </div>
  );
}
