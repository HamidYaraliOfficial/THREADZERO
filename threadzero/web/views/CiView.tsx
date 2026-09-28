'use client';
import React, { useState } from 'react';
import { Badge, Button, Card, CardHeader, Empty, Field, Json, PageHeader, Select, SevBadge, Table, Textarea } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { useApp } from '@/lib/store';
import { download } from '@/lib/util';

const GH = `name: threadzero
on: [pull_request]
jobs:
  security-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -r requirements.txt
      - run: threadzero ci architecture/main.tz --fail-on high --sarif threadzero.sarif --junit threadzero.xml
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: threadzero.sarif }`;
const GL = `threadzero:
  image: python:3.12
  script:
    - pip install -r requirements.txt
    - threadzero ci architecture/main.tz --fail-on high --junit threadzero.xml
  artifacts:
    when: always
    reports: { junit: threadzero.xml }`;

export default function CiView() {
  const { t, source, analysis: A, toast } = useApp();
  const [failOn, setFailOn] = useState('high'); const [baseline, setBaseline] = useState(''); const [res, setRes] = useState<any>(null); const [busy, setBusy] = useState(false);
  if (!A) return <Empty />;
  const run = async () => { setBusy(true); try { setRes(await api('/api/ci', { source, failOn, baseline: baseline || undefined })); } catch (e: any) { toast(e.message, 'err'); } setBusy(false); };
  return (
    <div>
      <PageHeader title={t('ci.title')} actions={<><Select className="w-40" value={failOn} onChange={(e) => setFailOn(e.target.value)}>{['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{t('ci.failOn')}: {s}</option>)}</Select><Button variant="primary" loading={busy} onClick={run}>{t('ci.run')}</Button></>} />
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-4">
          <Card><CardHeader title={t('ci.baseline')} /><Textarea rows={5} className="ltr border-0" placeholder="(optional) DSL of the target branch — only NEW findings will block" value={baseline} onChange={(e) => setBaseline(e.target.value)} /></Card>
          {res && <Card className="fluent-in"><div className={`p-4 flex items-center gap-3 ${res.passed ? 'bg-ok/10' : 'bg-danger/10'}`}><Badge tone={res.passed ? 'ok' : 'danger'} className="text-base px-3">{res.passed ? t('ci.pass') : t('ci.fail')}</Badge><span>{res.reasons.join(' · ') || '—'}</span></div>
            <Table head={[t('severity'), t('category'), t('details')]} empty="—" rows={res.blocking.map((f: any) => [<SevBadge key="s" sev={f.severity} />, f.category, <span key="m" className="text-xs">{f.message}</span>])} />
            <div className="p-3 flex gap-2"><Button size="sm" onClick={() => download('threadzero.sarif', JSON.stringify(res.sarif, null, 1), 'application/json')}>{t('ci.sarif')}</Button><Button size="sm" onClick={() => download('threadzero.xml', res.junit, 'application/xml')}>{t('ci.junit')}</Button>{res.markdown && <Button size="sm" onClick={() => download('pr-comment.md', res.markdown)}>PR comment</Button>}</div></Card>}
        </div>
        <div className="space-y-4"><Card><CardHeader title={`${t('ci.workflow')} — GitHub Actions`} actions={<Button size="sm" onClick={() => navigator.clipboard.writeText(GH)}>{t('copy')}</Button>} /><Json value={GH} /></Card>
          <Card><CardHeader title={`${t('ci.workflow')} — GitLab CI`} actions={<Button size="sm" onClick={() => navigator.clipboard.writeText(GL)}>{t('copy')}</Button>} /><Json value={GL} /></Card></div>
      </div>
    </div>
  );
}
