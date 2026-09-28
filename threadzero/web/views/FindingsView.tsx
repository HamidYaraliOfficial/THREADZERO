'use client';
import { useRouter } from 'next/navigation';
import React, { useState } from 'react';
import { gotoLine } from '@/components/CodeEditor';
import { Badge, Button, Card, CardHeader, Empty, Input, Modal, PageHeader, Select, SevBadge, Table } from '@/components/ui/kit';
import { useApp } from '@/lib/store';

export default function FindingsView() {
  const { t, analysis: A } = useApp();
  const router = useRouter();
  const [sev, setSev] = useState('all'); const [q, setQ] = useState(''); const [open, setOpen] = useState<any>(null);
  if (!A) return <Empty />;
  const rows = A.findings.filter((f: any) => (sev === 'all' || f.severity === sev) && (`${f.category} ${f.message} ${f.affected.join(' ')}`.toLowerCase().includes(q.toLowerCase())));
  const refactor = (id: string) => { sessionStorage.setItem('tz.finding', id); router.push('/refactor/'); };
  return (
    <div>
      <PageHeader title={t('findings.title')} subtitle={`${A.findings.length} ${t('findings')}`} actions={<>
        <Input className="w-56" placeholder={t('search')} value={q} onChange={(e) => setQ(e.target.value)} />
        <Select className="w-40" value={sev} onChange={(e) => setSev(e.target.value)}><option value="all">{t('all')}</option>{['Critical', 'High', 'Medium', 'Low'].map((s) => <option key={s} value={s}>{t(`sev.${s}`)}</option>)}</Select></>} />
      <Card><Table onRow={(i) => setOpen(rows[i])} empty={t('findings.none')} head={['ID', t('severity'), t('category'), t('flow'), t('findings.affected'), t('confidence'), '']}
        rows={rows.map((f: any) => [<span key="i" className="ltr">{f.id}</span>, <SevBadge key="s" sev={f.severity} />, f.category, f.flow ?? '—', <span key="a" className="ltr text-xs">{f.affected.slice(0, 3).join(', ')}</span>, `${Math.round(f.confidence * 100)}%`,
          <Button key="r" size="sm" onClick={(e) => { e.stopPropagation(); refactor(f.id); }}>{t('findings.refactor')}</Button>])} /></Card>
      <Modal wide open={!!open} onClose={() => setOpen(null)} title={open && <span className="flex items-center gap-2"><SevBadge sev={open.severity} />{open.category}</span>}>
        {open && <div className="space-y-3 text-sm">
          <p>{open.message}</p>
          <div><div className="text-xs text-muted">{t('path')}</div><div className="ltr flex gap-1 flex-wrap items-center">{open.path.map((p: string, i: number) => <React.Fragment key={i}>{i > 0 && <span>→</span>}<Badge tone="info">{p}</Badge></React.Fragment>)}</div></div>
          <div><div className="text-xs text-muted">{t('evidence')}</div><ul className="list-disc ps-5">{open.evidence.map((e: string, i: number) => <li key={i}>{e}</li>)}</ul></div>
          <div className="grid sm:grid-cols-2 gap-3"><div><div className="text-xs text-muted">{t('findings.rule')}</div>{open.violatedRule}</div><div><div className="text-xs text-muted">{t('confidence')}</div>{Math.round(open.confidence * 100)}%</div></div>
          <div><div className="text-xs text-muted">{t('fix')}</div><div className="text-accent">{open.suggestedFix}</div></div>
          {open.missing.length > 0 && <div><div className="text-xs text-muted">{t('missing')}</div>{open.missing.map((m: string) => <Badge key={m} tone="danger">{m}</Badge>)}</div>}
          <div className="flex gap-2 pt-2"><Button variant="primary" onClick={() => refactor(open.id)}>{t('findings.refactor')}</Button>{open.line > 0 && <Button onClick={() => { setOpen(null); router.push('/editor/'); setTimeout(() => gotoLine(open.line), 500); }}>{t('line')} {open.line}</Button>}</div></div>}
      </Modal>
    </div>
  );
}
