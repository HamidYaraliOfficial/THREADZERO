'use client';
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { lintGutter, setDiagnostics } from '@codemirror/lint';
import { EditorView } from '@codemirror/view';
import { tags as t } from '@lezer/highlight';
import CodeMirror from '@uiw/react-codemirror';
import React, { useEffect, useMemo, useRef } from 'react';
import { dslLanguage } from '@/lib/dsl-lang';

const style = HighlightStyle.define([
  { tag: t.keyword, class: 'tok-kw' }, { tag: t.typeName, class: 'tok-type' }, { tag: t.string, class: 'tok-str' }, { tag: t.number, class: 'tok-num' },
  { tag: t.comment, class: 'tok-cmt' }, { tag: t.operator, class: 'tok-op' }, { tag: t.atom, class: 'tok-type' }, { tag: t.special(t.variableName), class: 'tok-op' },
]);

export interface Diag { severity: string; message: string; line: number; col: number; code: string; file: string }

/** DSL editor. The code area is always left-to-right, even in the Persian (RTL) UI. */
export default function CodeEditor({ value, onChange, diagnostics = [], readOnly = false, height = '100%' }: {
  value: string; onChange?: (v: string) => void; diagnostics?: Diag[]; readOnly?: boolean; height?: string;
}) {
  const view = useRef<EditorView | null>(null);
  const exts = useMemo(() => [dslLanguage, syntaxHighlighting(style), lintGutter(), EditorView.lineWrapping], []);

  useEffect(() => {
    const v = view.current;
    if (!v) return;
    const doc = v.state.doc;
    const ds = diagnostics.filter((d) => d.line > 0 && d.line <= doc.lines && (!d.file || d.file === 'main.tz')).filter((d) => ['error', 'warning', 'notice'].includes(d.severity))
      .map((d) => {
        const ln = doc.line(d.line);
        const from = Math.min(ln.to, ln.from + Math.max(0, d.col - 1));
        const m = /^[A-Za-z0-9_]+/.exec(doc.sliceString(from, ln.to));
        return { from, to: Math.min(ln.to, from + (m ? m[0].length : 1)) || ln.to, severity: d.severity === 'error' ? 'error' : d.severity === 'warning' ? 'warning' : 'info', message: `[${d.code}] ${d.message}` } as any;
      });
    v.dispatch(setDiagnostics(v.state, ds));
  }, [diagnostics, value]);

  useEffect(() => {
    const go = (e: Event) => {
      const v = view.current; const line = (e as CustomEvent).detail as number;
      if (!v || line < 1 || line > v.state.doc.lines) return;
      const pos = v.state.doc.line(line).from;
      v.dispatch({ selection: { anchor: pos }, effects: EditorView.scrollIntoView(pos, { y: 'center' }) }); v.focus();
    };
    window.addEventListener('tz-goto', go);
    return () => window.removeEventListener('tz-goto', go);
  }, []);

  return (
    <div className="ltr h-full" dir="ltr">
      <CodeMirror value={value} height={height} extensions={exts} readOnly={readOnly} onChange={onChange} onCreateEditor={(v) => { view.current = v; }}
        basicSetup={{ lineNumbers: true, foldGutter: false, highlightActiveLine: true, autocompletion: false }} theme="none" />
    </div>
  );
}
export const gotoLine = (line: number) => window.dispatchEvent(new CustomEvent('tz-goto', { detail: line }));
