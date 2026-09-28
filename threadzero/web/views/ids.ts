import { Bot, CalendarClock, Code2, Cpu, FileText, FlaskConical, GitCompare, GitFork, LayoutDashboard, Network, Package, ShieldAlert, ShieldCheck, SlidersHorizontal, Settings, Terminal, TestTube2, Wand2, Waypoints, Workflow } from 'lucide-react';

export const VIEWS = [
  { id: 'studio', icon: LayoutDashboard, group: 'design' }, { id: 'editor', icon: Code2, group: 'design' }, { id: 'canvas', icon: Network, group: 'design' },
  { id: 'flows', icon: Waypoints, group: 'design' }, { id: 'policies', icon: ShieldCheck, group: 'design' }, { id: 'schedule', icon: CalendarClock, group: 'design' },
  { id: 'console', icon: Terminal, group: 'analyze' }, { id: 'findings', icon: ShieldAlert, group: 'analyze' }, { id: 'refactor', icon: Wand2, group: 'analyze' },
  { id: 'dependencies', icon: GitFork, group: 'analyze' }, { id: 'impact', icon: GitCompare, group: 'analyze' }, { id: 'assistant', icon: Bot, group: 'analyze' },
  { id: 'simulator', icon: FlaskConical, group: 'runtime' }, { id: 'wasm', icon: Cpu, group: 'runtime' }, { id: 'tests', icon: TestTube2, group: 'runtime' },
  { id: 'registry', icon: Package, group: 'ship' }, { id: 'ci', icon: Workflow, group: 'ship' }, { id: 'reports', icon: FileText, group: 'ship' },
  { id: 'admin', icon: Settings, group: 'manage' }, { id: 'settings', icon: SlidersHorizontal, group: 'manage' },
] as const;
export const VIEW_IDS = VIEWS.map((v) => v.id);
