'use client';
import { CheckCircle2, Circle, Loader2, XCircle } from 'lucide-react';
import React from 'react';
import { Badge, Button, Card, CardHeader, diagTone, Empty, Mono, PageHeader } from '@/components/ui/kit';
import { useApp } from '@/lib/store';
import { cn } from '@/lib/util';

export default function ConsoleView() {
  const { t, analysis: A, compileRes: R, compiling, compile, analyzing } = useApp();
  if (!A) return <Empty />;
  const errs = A.diagnostics.filter((d: any) => d.severity === 'error');
  const syntax = errs.filter((d: any) => d.code.startsWith('TZ1'));
  const steps: { id: string; state: 'ok' | 'fail' | 'idle' | 'run'; note: string }[] = [
    { id: 'parse', state: syntax.length ? 'fail' : 'ok', note: `${syntax.length} ${t('errors')}` },
    { id: 'validate', state: errs.length ? 'fail' : 'ok', note: `${errs.length} ${t('errors')}, ${A.diagnostics.filter((d: any) => d.severity === 'warning').length} ${t('warnings')}` },
    { id: 'analyze', state: analyzing ? 'run' : 'ok', note: `${A.findings.length} ${t('findings')}` },
    { id: 'refactor', state: A.findings.length ? 'ok' : 'idle', note: `${A.findings.length} → ${t('nav.refactor')}` },
    { id: 'generate', state: R?.ok ? 'ok' : compiling ? 'run' : 'idle', note: R?.ok ? `${R.files.length} files` : '' },
    { id: 'test', state: R?.ok ? (R.tests.failed ? 'fail' : 'ok') : 'idle', note: R?.ok ? `${R.tests.passed}/${R.tests.total}` : '' },
    { id: 'package', state: R?.ok ? 'ok' : 'idle', note: R?.ok ? R.artifactId : '' },
    { id: 'sign', state: R?.ok && R.signed ? 'ok' : 'idle', note: R?.ok && R.signed ? 'Ed25519' : '' },
    { id: 'publish', state: R?.ok ? 'ok' : 'idle', note: R?.ok ? t('registry.title') : '' },
  ];
  const Icon = ({ s }: { s: string }) => (s === 'ok' ? <CheckCircle2 className="h-5 w-5 text-ok" /> : s === 'fail' ? <XCircle className="h-5 w-5 text-danger" /> : s === 'run' ? <Loader2 className="h-5 w-5 animate-spin text-accent" /> : <Circle className="h-5 w-5 text-muted" />);
  return (
    <div>
      <PageHeader title={t('console.title')} subtitle={t('console.pipeline')} actions={<Button variant="primary" loading={compiling} onClick={() => compile()}>{t('compile')}</Button>} />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1"><CardHeader title={t('console.build')} />
          <ol className="p-3">{steps.map((s, i) => <li key={s.id} className="flex items-center gap-3 py-2 relative"><Icon s={s.state} />{i < steps.length - 1 && <span className="absolute start-[9px] top-8 h-4 w-px bg-stroke" />}
            <div className="flex-1"><div className={cn('font-medium', s.state === 'idle' && 'text-muted')}>{t(`console.step.${s.id}`)}</div><div className="text-xs text-muted">{s.note}</div></div></li>)}</ol>
          {R?.ok && <div className="px-4 pb-4 space-y-1 text-xs"><div>{t('console.artifact')}: <Mono>{R.artifactId}</Mono></div><div>{t('registry.sourceHash')}: <Mono>{R.manifest.sourceHash.slice(0, 16)}</Mono></div>
            <div>{t('registry.compiler')}: <Mono>{R.manifest.compiler.core}</Mono></div><div>{t('console.lock')}: <Badge tone="ok">{t('console.signed')}</Badge></div></div>}</Card>
        <Card className="lg:col-span-2"><CardHeader title={t('console.log')} />
          <div className="ltr font-mono text-xs p-3 max-h-[70vh] overflow-auto space-y-1">
            {A.diagnostics.length === 0 && <div className="text-ok">✔ {t('editor.noErrors')}</div>}
            {A.diagnostics.map((d: any, i: number) => <div key={i} className="flex gap-2"><Badge tone={diagTone(d.severity)} className="shrink-0">{d.severity}</Badge><span className="text-muted shrink-0">{d.file}:{d.line}:{d.col}</span><span className="text-muted">[{d.code}]</span><span className="break-words">{d.message}{d.hint ? ` — 💡 ${d.hint}` : ''}</span></div>)}
            {R?.ok && <div className="pt-2 border-t border-stroke mt-2">{R.files.map((f: any) => <div key={f.name} className="flex justify-between"><span>{f.name}</span><span className="text-muted">{f.size} B</span></div>)}</div>}
          </div></Card>
      </div>
    </div>
  );
}
