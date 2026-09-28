'use client';
import React, { useEffect, useMemo, useState } from 'react';
import ReactFlow, { Background, Controls, Edge, MarkerType, Node } from 'reactflow';
import 'reactflow/dist/style.css';
import { Badge, Card, CardHeader, Empty, PageHeader, Select } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { useApp } from '@/lib/store';

const COL = ['zone', 'node', 'flow', 'data', 'policy', 'role', 'assertion'];
const COLOR: Record<string, string> = { zone: '#0ea5e9', node: '#22c55e', flow: '#a855f7', data: '#f59e0b', policy: '#ef4444', role: '#14b8a6', assertion: '#64748b' };

export default function DependenciesView() {
  const { t, source, analysis: A } = useApp();
  const [entity, setEntity] = useState(''); const [dir, setDir] = useState('dependents'); const [res, setRes] = useState<any>(null);
  const entities: string[] = useMemo(() => (A ? [...new Set<string>(A.dependencies.flatMap((e: any) => [e.from, e.to]))].sort() : []), [A]);
  useEffect(() => { if (entities.length && !entity) setEntity(entities.find((e) => e.startsWith('data:')) ?? entities[0]); }, [entities, entity]);
  useEffect(() => { if (!entity) return; api('/api/dependencies', { source, entity, direction: dir }).then(setRes).catch(() => setRes(null)); }, [entity, dir, source]);
  const hit = new Set<string>(res ? [res.entity, ...res.impacted.map((x: any) => x.entity)] : []);
  const { nodes, edges } = useMemo(() => {
    if (!A) return { nodes: [] as Node[], edges: [] as Edge[] };
    const cnt: Record<string, number> = {};
    const nodes: Node[] = entities.map((id) => { const k = id.split(':')[0]; const c = COL.indexOf(k); cnt[k] = (cnt[k] ?? 0) + 1;
      return { id, position: { x: c * 230, y: (cnt[k] - 1) * 52 }, data: { label: id.split(':').slice(1).join(':') }, style: { width: 190, fontSize: 12, border: `2px solid ${COLOR[k] ?? '#888'}`, background: hit.has(id) ? `${COLOR[k]}55` : 'rgb(var(--layer))', color: 'rgb(var(--fg))', opacity: !res || hit.has(id) ? 1 : 0.35, borderRadius: 8 } }; });
    const edges: Edge[] = A.dependencies.map((e: any, i: number) => ({ id: `${i}`, source: e.from, target: e.to, label: e.kind, labelStyle: { fontSize: 9 }, style: { opacity: !res || (hit.has(e.from) && hit.has(e.to)) ? 0.9 : 0.12, stroke: 'rgb(var(--muted))' }, markerEnd: { type: MarkerType.ArrowClosed } }));
    return { nodes, edges };
  }, [A, entities, res]); // eslint-disable-line
  if (!A) return <Empty />;
  return (
    <div>
      <PageHeader title={t('deps.title')} actions={<><Select className="w-72" value={entity} onChange={(e) => setEntity(e.target.value)}>{entities.map((e) => <option key={e}>{e}</option>)}</Select>
        <Select className="w-56" value={dir} onChange={(e) => setDir(e.target.value)}><option value="dependents">{t('deps.dependents')}</option><option value="dependencies">{t('deps.dependencies')}</option></Select></>} />
      <div className="grid gap-4 xl:grid-cols-4">
        <Card className="xl:col-span-3 h-[68vh]"><ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.15} nodesDraggable proOptions={{ hideAttribution: true }}><Background /><Controls showInteractive={false} /></ReactFlow></Card>
        <Card><CardHeader title={t('deps.impacted')} />
          <div className="p-4 space-y-3">{res && Object.keys(res.groups).length === 0 && <div className="text-muted">—</div>}{res && Object.entries(res.groups).map(([k, v]: any) => <div key={k}><div className="text-xs text-muted mb-1" style={{ color: COLOR[k] }}>{k} ({v.length})</div><div className="flex gap-1 flex-wrap">{v.map((x: string) => <Badge key={x}>{x}</Badge>)}</div></div>)}</div></Card>
      </div>
    </div>
  );
}
