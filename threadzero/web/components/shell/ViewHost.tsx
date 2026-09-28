'use client';
import dynamic from 'next/dynamic';
import React from 'react';
import { Spinner } from '../ui/kit';

const load = (f: () => Promise<any>) => dynamic(f, { ssr: false, loading: () => <div className="p-10 flex justify-center"><Spinner /></div> });
const MAP: Record<string, any> = {
  studio: load(() => import('@/views/StudioView')), editor: load(() => import('@/views/EditorView')), canvas: load(() => import('@/views/CanvasView')),
  flows: load(() => import('@/views/FlowsView')), policies: load(() => import('@/views/PoliciesView')), schedule: load(() => import('@/views/ScheduleView')),
  console: load(() => import('@/views/ConsoleView')), findings: load(() => import('@/views/FindingsView')), refactor: load(() => import('@/views/RefactorView')),
  dependencies: load(() => import('@/views/DependenciesView')), impact: load(() => import('@/views/ImpactView')), assistant: load(() => import('@/views/AssistantView')),
  simulator: load(() => import('@/views/SimulatorView')), wasm: load(() => import('@/views/WasmView')), tests: load(() => import('@/views/TestsView')),
  registry: load(() => import('@/views/RegistryView')), ci: load(() => import('@/views/CiView')), reports: load(() => import('@/views/ReportsView')),
  admin: load(() => import('@/views/AdminView')), settings: load(() => import('@/views/SettingsView')),
};

class Boundary extends React.Component<{ children: React.ReactNode }, { err: string | null }> {
  state = { err: null as string | null };
  static getDerivedStateFromError(e: any) { return { err: String(e?.message ?? e) }; }
  render() { return this.state.err ? <div className="win-card p-6 text-danger">⚠ {this.state.err}</div> : this.props.children; }
}
export default function ViewHost({ view }: { view: string }) {
  const V = MAP[view] ?? MAP.studio;
  return <Boundary><V /></Boundary>;
}
