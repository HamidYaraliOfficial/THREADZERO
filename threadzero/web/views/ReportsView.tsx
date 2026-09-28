'use client';
import React, { useState } from 'react';
import { Button, Card, CardHeader, Empty, Field, Json, PageHeader, Select } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { useApp } from '@/lib/store';
import { download } from '@/lib/util';

const KINDS = ['security', 'policies', 'controls', 'tests', 'compliance', 'dfd', 'tbd', 'all'];
export default function ReportsView() {
  const { t, source, analysis: A, toast } = useApp();
  const [kind, setKind] = useState('security'); const [fmt, setFmt] = useState('html'); const [out, setOut] = useState<any>(null); const [busy, setBusy] = useState(false);
  if (!A) return <Empty />;
  const gen = async () => { setBusy(true); try { setOut(await api('/api/reports', { source, kind, format: fmt })); } catch (e: any) { toast(e.message, 'err'); } setBusy(false); };
  const ext = fmt === 'yaml' ? 'yaml' : fmt === 'pdf' ? 'html' : fmt;
  return (
    <div>
      <PageHeader title={t('reports.title')} actions={<>
        <Select className="w-64" value={kind} onChange={(e) => setKind(e.target.value)}>{KINDS.map((k) => <option key={k} value={k}>{t(`reports.${k}`)}</option>)}</Select>
        <Select className="w-32" value={fmt} onChange={(e) => setFmt(e.target.value)}>{['html', 'md', 'json', 'yaml', 'pdf'].map((f) => <option key={f} value={f}>{f === 'pdf' ? 'PDF (print HTML)' : f.toUpperCase()}</option>)}</Select>
        <Button variant="primary" loading={busy} onClick={gen}>{t('reports.generate')}</Button>
        {out && <><Button onClick={() => download(`threadzero-${kind}.${ext}`, out.content, out.mime)}>{t('download')}</Button>{(fmt === 'html' || fmt === 'pdf') && <Button onClick={() => { const w = window.open(); if (w) { w.document.write(out.content); w.document.close(); if (fmt === 'pdf') setTimeout(() => w.print(), 400); } }}>{fmt === 'pdf' ? 'Print / PDF' : 'Open'}</Button>}</>}</>} />
      {!out ? <Empty>{t('reports.generate')}</Empty> : <Card className="overflow-hidden fluent-in">{fmt === 'html' || fmt === 'pdf' ? <iframe title="report" className="w-full h-[72vh] bg-white" sandbox="allow-same-origin" srcDoc={out.content} /> : <div className="p-3"><Json value={out.content} max={60000} /></div>}</Card>}
    </div>
  );
}
