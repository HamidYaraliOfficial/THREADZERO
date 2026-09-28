'use client';
import React, { useEffect, useState } from 'react';
import { Badge, Button, Card, CardHeader, Empty, Input, Json, Mono, PageHeader, Table } from '@/components/ui/kit';
import { API, api } from '@/lib/api';
import { useApp } from '@/lib/store';

export default function RegistryView() {
  const { t, toast, compileRes } = useApp();
  const [items, setItems] = useState<any[]>([]); const [sel, setSel] = useState<any>(null); const [file, setFile] = useState<{ name: string; text: string } | null>(null); const [targets, setTargets] = useState('');
  const refresh = () => api('/api/registry').then(setItems).catch(() => {});
  useEffect(() => { refresh(); }, [compileRes]);
  const open = async (id: string) => { setSel(await api(`/api/registry/${id}`)); setFile(null); };
  const view = async (name: string) => setFile({ name, text: await api(`/api/registry/${sel.meta.id}/file?name=${encodeURIComponent(name)}`) });
  return (
    <div>
      <PageHeader title={t('registry.title')} />
      <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-2"><Table onRow={(i) => open(items[i].id)} empty={t('registry.empty')} head={['ID', 'Project', t('version'), t('studio.rules'), t('console.signed')]}
          rows={items.map((m) => [<Mono key="i">{m.id}</Mono>, m.project, m.version, m.rules, <Badge key="s" tone={m.signed ? 'ok' : 'warn'}>{m.signed ? '✔' : '—'}</Badge>])} /></Card>
        <div className="xl:col-span-3 space-y-4">{!sel ? <Empty /> : <>
          <Card className="fluent-in"><CardHeader title={<Mono>{sel.meta.id}</Mono>} actions={<><a href={`${API}/api/registry/${sel.meta.id}/package`}><Button size="sm">{t('download')} .tzpkg</Button></a><Button size="sm" onClick={async () => { await api('/api/host/load-artifact', { artifact: sel.meta.id }); toast('✔ ' + t('registry.load'), 'ok'); }}>{t('registry.load')}</Button></>} />
            <div className="p-4 grid sm:grid-cols-2 gap-3 text-sm"><div><div className="text-xs text-muted">{t('registry.sourceHash')}</div><Mono>{sel.manifest.sourceHash}</Mono></div><div><div className="text-xs text-muted">{t('registry.compiler')}</div><Mono>{JSON.stringify(sel.manifest.compiler)}</Mono></div>
              <div><div className="text-xs text-muted">{t('registry.signature')}</div>{sel.signature ? <><Badge tone="ok">{sel.signature.alg}</Badge> <Mono>{sel.signature.key_id}</Mono></> : <Badge tone="warn">unsigned</Badge>}</div><div><div className="text-xs text-muted">ruleset</div><Mono>{sel.manifest.ruleset}</Mono></div></div></Card>
          <Card><CardHeader title={t('registry.files')} /><Table onRow={(i) => view(sel.files[i].name)} head={[t('name'), t('size'), 'SHA-256']} rows={sel.files.map((f: any) => [f.name, `${f.size} B`, <Mono key="h">{sel.manifest.files[f.name]?.slice(0, 16) ?? '—'}</Mono>])} />
            {file && <div className="p-3 border-t border-stroke"><div className="text-xs text-muted mb-1">{file.name}</div><Json value={file.text} max={12000} /></div>}</Card>
          <Card><CardHeader title={t('registry.distribute')} /><div className="p-4 flex gap-2"><Input className="ltr" placeholder="./edge-runtime-dir , https://runtime.internal:8737" value={targets} onChange={(e) => setTargets(e.target.value)} /><Button onClick={async () => { const r = await api('/api/distribute', { artifact: sel.meta.id, targets: targets.split(',').map((x) => x.trim()).filter(Boolean) }); toast(r.map((x: any) => (x.ok ? '✔' : '✘') + ' ' + x.target).join(' · '), r.every((x: any) => x.ok) ? 'ok' : 'err'); }}>{t('registry.distribute')}</Button></div></Card></>}</div>
      </div>
    </div>
  );
}
