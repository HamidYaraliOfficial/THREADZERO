'use client';
import React, { useState } from 'react';
import { Badge, BarChart, Button, Card, CardHeader, Empty, Field, Input, Json, Mono, PageHeader, Select, Stat, Table, Tabs, Textarea } from '@/components/ui/kit';
import { api, apiBytes } from '@/lib/api';
import { useApp } from '@/lib/store';

export default function WasmView() {
  const { t, source, compileRes: R, compile, analysis: A, toast } = useApp();
  const [tab, setTab] = useState('module');
  const [prev, setPrev] = useState<any>(null); const [req, setReq] = useState('{\n  "subject": {"roles": [], "mfa": true},\n  "action": "Read",\n  "data": "",\n  "zone": "Backend",\n  "context": {"time": 600, "secure_channel": true}\n}');
  const [browser, setBrowser] = useState<any>(null);
  const [rules, setRules] = useState('10,100,1000,5000'); const [reqs, setReqs] = useState(20000); const [threads, setThreads] = useState(1); const [perf, setPerf] = useState<any>(null); const [busy, setBusy] = useState('');
  const [faults, setFaults] = useState<any[]>([]); const [host, setHost] = useState<any>(null); const [canary, setCanary] = useState<any>(null);
  if (!A) return <Empty />;
  const load = async () => { setBusy('prev'); try { setPrev(await api('/api/compile/preview', { source })); } catch (e: any) { toast(e.message, 'err'); } setBusy(''); };
  const runBrowser = async () => {
    try {
      const r = R?.ok ? R : await compile(); if (!r?.ok) return;
      const parsed = JSON.parse(req); const enc = await api('/api/encode', { source, request: parsed });
      const bytes = await apiBytes(`/api/registry/${r.artifactId}/file?name=policy.wasm`);
      const { instance } = await WebAssembly.instantiate(bytes, {});
      const ex: any = instance.exports; const mem = new Int32Array(ex.memory.buffer, 0, 23);
      enc.fields.forEach((f: string, i: number) => { mem[i] = enc.slots[f] ?? 0; });
      const code = ex.authorize(0, 256); const out = new Int32Array(ex.memory.buffer, 256, 16);
      const server = await api('/api/simulate', { source, request: parsed });
      const names = ['deny', 'allow', 'require_mfa', 'require_approval', 'quarantine'];
      setBrowser({ decision: names[code], reason: out[1], obligations: out[2], matched: out[3], server: server.decision.decision, equal: names[code] === server.decision.decision });
    } catch (e: any) { toast(String(e.message ?? e), 'err'); }
  };
  const runPerf = async () => { setBusy('perf'); try { setPerf(await api('/api/perf', { rules: rules.split(',').map(Number), requests: reqs, threads })); } catch (e: any) { toast(e.message, 'err'); } setBusy(''); };
  const runFaults = async () => { setBusy('faults'); try { setFaults(await api('/api/faults', { source })); } catch (e: any) { toast(e.message, 'err'); } setBusy(''); };
  const refreshHost = async () => setHost(await api('/api/host/status'));
  const hostAct = async (path: string, body: any = {}) => { try { const r = await api(path, body); if (r.status) setHost(r.status); else refreshHost(); return r; } catch (e: any) { toast(e.message, 'err'); } };
  return (
    <div>
      <PageHeader title={t('wasm.title')} actions={<><Button onClick={load} loading={busy === 'prev'}>{t('editor.preview')}</Button><Button variant="primary" onClick={() => compile()}>{t('compile')}</Button></>} />
      <Card><Tabs value={tab} onChange={(v) => { setTab(v); if (v === 'host') refreshHost(); }} tabs={[{ id: 'module', label: t('editor.wasm') }, { id: 'run', label: t('wasm.inBrowser') }, { id: 'perf', label: t('wasm.perf') }, { id: 'faults', label: t('wasm.faults') }, { id: 'host', label: t('wasm.host') }]} />
        {tab === 'module' && <div className="p-4 space-y-4">{!prev ? <Button onClick={load}>{t('editor.preview')}</Button> : !prev.wasm ? <Empty>{prev.diagnostics?.filter((d: any) => d.severity === 'error').length} {t('errors')}</Empty> : <>
          <div className="grid gap-3 sm:grid-cols-3"><Stat label={t('wasm.size')} value={`${(prev.wasm.bytes / 1024).toFixed(1)} KB`} /><Stat label={t('studio.rules')} value={prev.wasm.rules} /><Stat label={t('nav.tests')} value={`${prev.tests.passed}/${prev.tests.total}`} tone={prev.tests.failed ? 'text-warn' : 'text-ok'} /></div>
          <div><div className="text-xs text-muted">{t('wasm.hash')}</div><Mono>{prev.wasm.sha256}</Mono></div>
          <div><div className="text-xs text-muted mb-1">{t('wasm.exports')}</div>{prev.wasm.exports.map((e: string) => <Badge key={e} tone="accent" className="me-1">{e}</Badge>)}</div>
          <details><summary className="cursor-pointer text-accent">WAT</summary><Json value={prev.policy.wat} max={30000} /></details></>}</div>}
        {tab === 'run' && <div className="p-4 grid lg:grid-cols-2 gap-4"><div><Field label={t('request')}><Textarea rows={12} value={req} onChange={(e) => setReq(e.target.value)} className="ltr" /></Field><Button variant="primary" className="mt-3" onClick={runBrowser}>{t('wasm.inBrowser')}</Button></div>
          <div>{browser && <Card className="p-4 space-y-2 fluent-in"><Badge tone={browser.decision === 'allow' ? 'ok' : 'warn'} className="text-base px-3">{browser.decision}</Badge><div className="text-sm">browser WebAssembly ⇄ server (wasmtime): <Badge tone={browser.equal ? 'ok' : 'danger'}>{browser.equal ? 'identical' : 'DIFFERENT'}</Badge></div><div className="ltr text-xs text-muted">reason #{browser.reason} · obligations mask {browser.obligations} · matched {browser.matched}</div></Card>}</div></div>}
        {tab === 'perf' && <div className="p-4 space-y-4"><div className="flex flex-wrap gap-3 items-end"><Field label={t('wasm.rules')}><Input value={rules} onChange={(e) => setRules(e.target.value)} className="w-48 ltr" /></Field><Field label={t('wasm.requests')}><Input type="number" value={reqs} onChange={(e) => setReqs(+e.target.value)} className="w-32" /></Field><Field label={t('wasm.threads')}><Input type="number" min={1} max={16} value={threads} onChange={(e) => setThreads(+e.target.value)} className="w-24" /></Field><Button variant="primary" loading={busy === 'perf'} onClick={runPerf}>{t('run')}</Button></div>
          {perf && <><BarChart data={perf.rows.map((r: any) => ({ label: `${r.rules}`, value: r.throughputPerSec }))} /><Table head={[t('wasm.rules'), 'WASM', 'p50 µs', 'p95 µs', 'p99 µs', t('wasm.throughput'), 'CPU s', 'RSS MB', 'Path']} rows={perf.rows.map((r: any) => [r.rules, `${(r.wasmBytes / 1024).toFixed(1)} KB`, r.p50Us, r.p95Us, r.p99Us, `${r.throughputPerSec}/s`, r.cpuSeconds, r.rssMB, r.avgDecisionPath])} /><p className="text-xs text-muted">{perf.note}</p></>}</div>}
        {tab === 'faults' && <div className="p-4 space-y-3"><Button variant="primary" loading={busy === 'faults'} onClick={runFaults}>{t('wasm.runFaults')}</Button><Table head={['Scenario', 'Expected', 'Actual', t('status')]} rows={faults.map((f) => [f.scenario, f.expected, <span key="a" className="text-xs">{f.actual}</span>, <Badge key="s" tone={f.safe ? 'ok' : 'danger'}>{f.safe ? t('wasm.safe') : t('wasm.unsafe')}</Badge>])} /></div>}
        {tab === 'host' && <div className="p-4 space-y-4"><div className="flex flex-wrap gap-2"><Button onClick={async () => { const r = R?.ok ? R : await compile(); if (r?.ok) await hostAct('/api/host/load-artifact', { artifact: r.artifactId, activate: true }); }}>{t('wasm.load')} + {t('wasm.activate')}</Button>
          <Button onClick={async () => { const r = R?.ok ? R : await compile(); if (r?.ok) setCanary(await hostAct('/api/host/canary', { artifact: r.artifactId, count: 200, maxChangedRatio: 0.1 })); }}>{t('wasm.canary')}</Button><Button variant="danger" onClick={() => hostAct('/api/host/rollback')}>{t('wasm.rollback')}</Button></div>
          {host && <Table head={[t('version'), 'Project', t('studio.rules'), t('status')]} rows={host.versions.map((v: any) => [<span key="i" className="ltr">{v.id}{host.active === v.id ? ' ●' : ''}</span>, v.project, v.rules, <Badge key="s" tone={v.healthy ? 'ok' : 'danger'}>{v.healthy ? 'healthy' : 'rolled back'}</Badge>])} />}
          {canary && <Card className="p-4 text-sm fluent-in"><b>Canary</b>: {canary.changed}/{canary.requests} {t('impact.loosened')}/{t('impact.tightened')} · latency ×{canary.latencyRatio} · <Badge tone={canary.withinThresholds ? 'ok' : 'danger'}>{canary.withinThresholds ? t('ci.pass') : t('ci.fail')}</Badge></Card>}
          <div className="text-xs text-muted">{host?.events.slice(-6).map((e: any, i: number) => <div key={i} className="ltr">{e.event} {e.id ?? e.candidate ?? ''}</div>)}</div></div>}
      </Card>
    </div>
  );
}
