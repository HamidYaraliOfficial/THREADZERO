'use client';
import { Bot, Send } from 'lucide-react';
import { useRouter } from 'next/navigation';
import React, { useState } from 'react';
import { Badge, Button, Card, CardHeader, Empty, Input, PageHeader } from '@/components/ui/kit';
import { api } from '@/lib/api';
import { useApp } from '@/lib/store';

export default function AssistantView() {
  const { t, source, analysis: A, setSource, toast } = useApp();
  const router = useRouter();
  const [q, setQ] = useState(''); const [log, setLog] = useState<any[]>([]); const [busy, setBusy] = useState(false);
  const ask = async (text: string) => { if (!text.trim()) return; setBusy(true); setQ('');
    try { const r = await api('/api/ai', { source, question: text }); setLog((l) => [...l, { q: text, r }]); } catch (e: any) { toast(e.message, 'err'); } setBusy(false); };
  const ideas = A ? ['what boundary violations exist?', A.findings[0] ? `propose a refactoring for ${A.findings[0].id}` : 'inspect graph', A.symbols.data[0] ? `trace ${A.symbols.data[0].name}` : 'trace', A.policy.rules[0] ? `explain policy ${A.policy.rules[0].policy}` : 'explain policy'] : [];
  return (
    <div className="max-w-4xl">
      <PageHeader title={t('assistant.title')} subtitle={t('assistant.proposalsOnly')} />
      {!A ? <Empty /> : <>
        <div className="flex gap-2 flex-wrap mb-3">{ideas.map((i) => <button key={i} onClick={() => ask(i)} className="px-3 py-1 rounded-full border border-stroke text-xs hover:border-accent">{i}</button>)}</div>
        <div className="space-y-4">{log.map((m, i) => (
          <div key={i} className="space-y-2 fluent-in"><div className="ms-auto max-w-[80%] rounded-winlg bg-accent text-accent-fg px-4 py-2 w-fit">{m.q}</div>
            <Card className="p-4 space-y-3"><div className="flex items-center gap-2 text-accent"><Bot className="h-4 w-4" /><b>{m.r.intent}</b>{m.r.tools.map((x: any, k: number) => <Badge key={k} tone="info">{x.tool}</Badge>)}<Badge tone="ok">0 production changes</Badge></div>
              <p>{m.r.llmAnswer ?? m.r.answer}</p>
              {m.r.evidence.length > 0 && <div><div className="text-xs text-muted mb-1">{t('evidence')}</div><div className="flex gap-1 flex-wrap ltr">{m.r.evidence.slice(0, 16).map((e: any, k: number) => <Badge key={k}>{e.type}: {e.ref}</Badge>)}</div></div>}
              {m.r.results[0]?.proposals?.map((p: any) => <div key={p.id} className="border border-stroke rounded-win p-3 text-sm"><b>{p.id} — {p.title}</b><div className="text-muted">{p.description}</div><Badge tone={p.verified ? 'ok' : 'warn'}>{p.verified ? 'verified by compiler' : 'partially verified'}</Badge></div>)}
              {m.r.results[0]?.proposals?.length > 0 && <Button size="sm" onClick={() => router.push('/refactor/')}>{t('nav.refactor')} →</Button>}</Card></div>))}</div>
        <form className="flex gap-2 mt-4 sticky bottom-0" onSubmit={(e) => { e.preventDefault(); ask(q); }}><Input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('assistant.ask')} /><Button variant="primary" type="submit" loading={busy}><Send className="h-4 w-4 flip-rtl" />{t('assistant.send')}</Button></form></>}
    </div>
  );
}
