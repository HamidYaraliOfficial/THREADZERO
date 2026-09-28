/**
 * Renders every view against a REAL running THREADZERO backend (NEXT_PUBLIC_API) and checks that the
 * views load data and never fall into their error boundary. Run: THREADZERO_API=http://127.0.0.1:8737 npm test
 */
import { render, waitFor, screen, act } from '@testing-library/react';
import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { AppProvider, useApp } from '@/lib/store';

vi.mock('@/components/CodeEditor', () => ({ default: ({ value }: any) => <textarea data-testid="editor" readOnly value={value} />, gotoLine: () => {} }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ push() {}, replace() {} }), usePathname: () => '/' }));
vi.mock('@/components/Graph3D', () => ({ default: () => <div data-testid="graph3d" /> }));

const VIEWS: Record<string, () => Promise<any>> = {
  studio: () => import('@/views/StudioView'), editor: () => import('@/views/EditorView'), canvas: () => import('@/views/CanvasView'), flows: () => import('@/views/FlowsView'),
  policies: () => import('@/views/PoliciesView'), schedule: () => import('@/views/ScheduleView'), console: () => import('@/views/ConsoleView'), findings: () => import('@/views/FindingsView'),
  refactor: () => import('@/views/RefactorView'), dependencies: () => import('@/views/DependenciesView'), impact: () => import('@/views/ImpactView'), assistant: () => import('@/views/AssistantView'),
  simulator: () => import('@/views/SimulatorView'), wasm: () => import('@/views/WasmView'), tests: () => import('@/views/TestsView'), registry: () => import('@/views/RegistryView'),
  ci: () => import('@/views/CiView'), reports: () => import('@/views/ReportsView'), admin: () => import('@/views/AdminView'), settings: () => import('@/views/SettingsView'),
};

function Ready({ children }: { children: React.ReactNode }) {
  const { analysis } = useApp();
  return analysis ? <div data-testid="ready">{children}</div> : <div>loading</div>;
}

describe('views render with live analysis', () => {
  for (const [id, load] of Object.entries(VIEWS)) {
    it(id, async () => {
      const errors: any[] = [];
      const spy = vi.spyOn(console, 'error').mockImplementation((...a) => { errors.push(a.join(' ')); });
      const mod = await load();
      const V = mod.default;
      for (const lang of ['en', 'fa', 'zh']) {
        window.localStorage.setItem('tz.lang', lang);
        const { container, unmount } = render(<AppProvider><Ready><V /></Ready></AppProvider>);
        await waitFor(() => expect(screen.getByTestId('ready')).toBeTruthy(), { timeout: 30000 });
        await act(async () => { await new Promise((r) => setTimeout(r, 700)); });
        expect(container.textContent).not.toContain('⚠'); // error boundary marker
        expect(container.querySelector('h1')?.textContent ?? 'x').not.toBe('');
        unmount();
      }
      spy.mockRestore();
      const real = errors.filter((e) => !/act\(|not wrapped in act|Warning:.*(key|validateDOMNesting|defaultValue)/i.test(e));
      expect(real, real.join('\n')).toEqual([]);
    });
  }
});
