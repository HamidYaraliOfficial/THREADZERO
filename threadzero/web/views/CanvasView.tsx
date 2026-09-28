'use client';
import { Box, Database, Globe, KeyRound, Layers, ListOrdered, Server, ShieldCheck, User, Cloud, Bot, Cpu, FileBox, Laptop, Monitor } from 'lucide-react';
import dynamic from 'next/dynamic';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import ReactFlow, { Background, Controls, Edge, Handle, MarkerType, MiniMap, Node, NodeProps, Position, ReactFlowProvider, useReactFlow } from 'reactflow';
import 'reactflow/dist/style.css';
import { Badge, Button, Card, CardHeader, Empty, Field, Input, Modal, PageHeader, Select, Tabs } from '@/components/ui/kit';
import { useApp } from '@/lib/store';
import { cn } from '@/lib/util';

const Graph3D = dynamic(() => import('@/components/Graph3D'), { ssr: false });
const ICON: Record<string, any> = { user: User, identity: User, device: Laptop, application: Monitor, service: Server, api: Globe, database: Database, queue: ListOrdered, filestore: FileBox, cloud: Cloud, secret: KeyRound, external: Globe, agent: Bot, approval: ShieldCheck };
const PALETTE = ['user', 'identity', 'application', 'service', 'api', 'database', 'queue', 'filestore', 'cloud', 'secret', 'external', 'agent', 'approval'];
const ZW = 250, NH = 74, ZPAD = 46;

function ZoneNode({ data }: NodeProps) {
  const trustTone = ['border-danger/70', 'border-warn/70', 'border-warn/50', 'border-ok/50', 'border-info/60', 'border-accent/70'][Math.min(5, data.trust)];
  return <div className={cn('h-full w-full rounded-winlg border-2 border-dashed bg-layer/40', trustTone)}><div className="px-3 py-1.5 text-xs font-semibold flex justify-between"><span>{data.label}</span><span className="text-muted">trust {data.trust} · {data.kind}</span></div></div>;
}
function EntityNode({ data }: NodeProps) {
  const Icon = ICON[data.kind] ?? Box;
  return (
    <div className={cn('win-card px-3 py-2 w-[210px] shadow-win', data.selected && 'ring-2 ring-accent')}>
      <Handle type="target" position={Position.Left} /><Handle type="source" position={Position.Right} />
      <div className="flex items-center gap-2"><Icon className="h-4 w-4 text-accent shrink-0" /><span className="font-semibold truncate">{data.label}</span></div>
      <div className="flex gap-1 mt-1 flex-wrap"><Badge>{data.kind}</Badge>{data.controls > 0 && <Badge tone="ok">{data.controls} ctl</Badge>}{data.clearance && <Badge tone="info">{data.clearance}</Badge>}</div>
    </div>);
}
const nodeTypes = { zone: ZoneNode, entity: EntityNode };

function build(graph: any, selected: string | null) {
  const zones = [...graph.zones].sort((a: any, b: any) => a.trust - b.trust);
  const nodes: Node[] = []; const zoneBox: Record<string, { x: number; y: number; w: number; h: number }> = {};
  zones.forEach((z: any, zi: number) => {
    const inz = graph.nodes.filter((n: any) => n.zone === z.id);
    const h = ZPAD + Math.max(1, inz.length) * NH + 16;
    zoneBox[z.id] = { x: zi * (ZW + 90), y: 0, w: ZW, h };
    nodes.push({ id: `zone:${z.id}`, type: 'zone', position: { x: zoneBox[z.id].x, y: 0 }, data: { label: z.id, trust: z.trust, kind: z.kind }, style: { width: ZW, height: h }, draggable: false, selectable: false, zIndex: 0 });
    inz.forEach((n: any, i: number) => nodes.push({ id: n.id, type: 'entity', parentNode: `zone:${z.id}`, extent: 'parent', position: { x: 20, y: ZPAD + i * NH }, data: { label: n.id, kind: n.kind, controls: n.controls.length, clearance: n.clearance, selected: selected === n.id }, zIndex: 2 }));
  });
  const edges: Edge[] = graph.edges.map((e: any) => ({
    id: e.id, source: e.from, target: e.to, label: `${e.data.join(', ')} · ${e.op}`, animated: e.crossing,
    style: { stroke: e.missing.length ? 'rgb(var(--danger))' : e.crossing ? 'rgb(var(--accent))' : 'rgb(var(--muted))', strokeWidth: e.crossing ? 2.2 : 1.4, strokeDasharray: e.missing.length ? '6 4' : undefined },
    labelStyle: { fontSize: 10, fill: 'rgb(var(--fg))' }, labelBgStyle: { fill: 'rgb(var(--layer))' }, markerEnd: { type: MarkerType.ArrowClosed, color: e.missing.length ? 'rgb(var(--danger))' : 'rgb(var(--accent))' }, zIndex: 3,
  }));
  return { nodes, edges, zoneBox };
}

function Inner() {
  const { t, analysis: A, patchSource } = useApp();
  const [sel, setSel] = useState<{ k: string; id: string } | null>(null);
  const [mode, setMode] = useState<'2d' | '3d'>('2d');
  const [dlg, setDlg] = useState<any>(null);
  const [name, setName] = useState('');
  const rf = useReactFlow();
  const built = useMemo(() => (A?.graph ? build(A.graph, sel?.k === 'node' ? sel.id : null) : null), [A?.graph, sel]);

  const onDrop = useCallback((ev: React.DragEvent) => {
    ev.preventDefault();
    const kind = ev.dataTransfer.getData('application/tz-kind');
    if (!kind || !built) return;
    const p = rf.screenToFlowPosition({ x: ev.clientX, y: ev.clientY });
    const zone = Object.entries(built.zoneBox).find(([, b]) => p.x >= b.x && p.x <= b.x + b.w && p.y >= b.y && p.y <= b.y + b.h)?.[0];
    if (!zone) return;
    setName(kind[0].toUpperCase() + kind.slice(1) + (A.graph.nodes.length + 1)); setDlg({ type: 'node', kind, zone });
  }, [built, rf, A]);

  if (!A?.graph) return <Empty />;
  const edge = sel?.k === 'edge' ? A.graph.edges.find((e: any) => e.id === sel.id) : null;
  const node = sel?.k === 'node' ? A.graph.nodes.find((n: any) => n.id === sel.id) : null;
  const dataTypes = A.symbols.data.map((d: any) => d.name); const actions = A.symbols.actions.map((a: any) => a.name);

  return (
    <div className="h-[calc(100vh-7.5rem)] flex flex-col">
      <PageHeader title={t('canvas.title')} subtitle={t('canvas.hint')} actions={<Tabs value={mode} onChange={(v) => setMode(v as any)} className="border-0" tabs={[{ id: '2d', label: t('canvas.view2d') }, { id: '3d', label: <span className="flex items-center gap-1"><Layers className="h-3.5 w-3.5" />{t('canvas.view3d')}</span> }]} />} />
      <div className="flex-1 min-h-0 flex gap-3">
        <Card className="w-44 shrink-0 p-2 overflow-auto"><div className="text-xs text-muted px-1 pb-1">{t('canvas.palette')}</div>
          {PALETTE.map((k) => { const I = ICON[k] ?? Cpu; return <div key={k} draggable onDragStart={(e) => e.dataTransfer.setData('application/tz-kind', k)} className="flex items-center gap-2 px-2 py-1.5 mb-1 rounded-win border border-stroke bg-layer2 cursor-grab hover:border-accent"><I className="h-4 w-4 text-accent" />{k}</div>; })}</Card>
        <Card className="flex-1 min-w-0 relative overflow-hidden" onDragOver={(e) => e.preventDefault()} onDrop={onDrop}>
          {mode === '2d' && built ? (
            <ReactFlow nodes={built.nodes} edges={built.edges} nodeTypes={nodeTypes} fitView minZoom={0.2} nodesConnectable proOptions={{ hideAttribution: true }}
              onNodeClick={(_, n) => n.type === 'entity' && setSel({ k: 'node', id: n.id })} onEdgeClick={(_, e) => setSel({ k: 'edge', id: e.id })}
              onConnect={(c) => { setName(`Flow${A.graph.edges.length + 1}`); setDlg({ type: 'flow', from: c.source, to: c.target, data: dataTypes[0], op: 'Write' }); }}>
              <Background gap={20} /><Controls showInteractive={false} /><MiniMap pannable zoomable className="!bg-layer" />
            </ReactFlow>) : <Graph3D graph={A.graph} onSelect={(k, id) => setSel({ k, id })} />}
          <div className="absolute bottom-2 start-2 acrylic win-card px-3 py-2 text-xs flex gap-3 ltr"><span><i className="inline-block w-4 h-0.5 bg-accent align-middle" /> {t('canvas.crossing')}</span><span><i className="inline-block w-4 border-t-2 border-dashed border-danger align-middle" /> {t('missing')}</span><span><i className="inline-block w-4 h-0.5 bg-muted align-middle" /> {t('canvas.internal')}</span></div>
        </Card>
        <Card className="w-72 shrink-0 overflow-auto"><CardHeader title={t('canvas.inspector')} />
          {!sel ? <div className="p-4 text-muted">{t('canvas.hint')}</div> : <div className="p-4 space-y-2 text-sm fluent-in">
            {node && <><div className="font-semibold text-base">{node.id}</div><Badge>{node.kind}</Badge> <Badge tone="info">{node.zone}</Badge><div className="text-xs text-muted mt-2">{t('controls')}</div><div className="flex gap-1 flex-wrap">{node.controls.map((c: string) => <Badge key={c} tone="ok">{c}</Badge>)}</div>
              <div className="text-xs text-muted mt-2">{t('nav.findings')}</div>{A.findings.filter((f: any) => f.affected.includes(node.id)).map((f: any) => <div key={f.id} className="text-xs border-s-2 border-danger ps-2 my-1">{f.category}</div>)}</>}
            {edge && <><div className="font-semibold text-base">{edge.id}</div><div className="ltr text-xs">{edge.from} → {edge.to}</div><div>{edge.data.join(', ')} · {edge.op} · {edge.channel}</div><Badge tone={edge.crossing ? 'accent' : 'muted'}>{edge.crossing ? t('canvas.crossing') : t('canvas.internal')}</Badge>
              <div className="text-xs text-muted mt-2">{t('controls')}</div><div className="flex gap-1 flex-wrap">{edge.controls.map((c: string) => <Badge key={c} tone="ok">{c}</Badge>)}</div>
              {edge.missing.length > 0 && <><div className="text-xs text-danger mt-2">{t('missing')}</div><div className="flex gap-1 flex-wrap">{edge.missing.map((c: string) => <Badge key={c} tone="danger">{c}</Badge>)}</div></>}</>}
          </div>}
        </Card>
      </div>
      <Modal open={!!dlg} onClose={() => setDlg(null)} title={dlg?.type === 'flow' ? t('canvas.newFlow') : dlg?.kind}>
        {dlg && <div className="space-y-3">
          <Field label={t('name')}><Input value={name} onChange={(e) => setName(e.target.value.replace(/[^A-Za-z0-9_]/g, ''))} /></Field>
          {dlg.type === 'flow' && <div className="grid grid-cols-2 gap-3"><Field label={t('canvas.dataType')}><Select value={dlg.data} onChange={(e) => setDlg({ ...dlg, data: e.target.value })}>{dataTypes.map((d: string) => <option key={d}>{d}</option>)}</Select></Field>
            <Field label={t('canvas.operation')}><Select value={dlg.op} onChange={(e) => setDlg({ ...dlg, op: e.target.value })}>{actions.map((d: string) => <option key={d}>{d}</option>)}</Select></Field></div>}
          <Button variant="primary" onClick={() => {
            if (!name) return;
            patchSource((s) => s.trimEnd() + '\n' + (dlg.type === 'flow' ? `flow ${name} from ${dlg.from} to ${dlg.to} carries ${dlg.data} op ${dlg.op} { channel: tls; }\n` : `${dlg.kind} ${name} in ${dlg.zone} { controls: []; }\n`));
            setDlg(null);
          }}>{t('canvas.create')}</Button></div>}
      </Modal>
    </div>
  );
}
export default function CanvasView() { return <ReactFlowProvider><Inner /></ReactFlowProvider>; }
