'use client';
import { Html, Line, OrbitControls } from '@react-three/drei';
import { Canvas } from '@react-three/fiber';
import React, { useMemo } from 'react';

/** 3D security graph: each trust zone is a translucent slab stacked by trust level; edges crossing zones glow red when controls are missing. */
export default function Graph3D({ graph, onSelect }: { graph: any; onSelect?: (k: string, id: string) => void }) {
  const layout = useMemo(() => {
    const zones = [...graph.zones].sort((a: any, b: any) => a.trust - b.trust);
    const pos: Record<string, [number, number, number]> = {};
    zones.forEach((z: any, zi: number) => {
      const nodes = graph.nodes.filter((n: any) => n.zone === z.id);
      nodes.forEach((n: any, i: number) => { const a = (i / Math.max(1, nodes.length)) * Math.PI * 2; const r = nodes.length > 1 ? 1.6 : 0; pos[n.id] = [Math.cos(a) * r, zi * 2.2, Math.sin(a) * r]; });
    });
    return { zones, pos };
  }, [graph]);
  const zoneColor = (t: number) => ['#9b1c1c', '#c2410c', '#a16207', '#4d7c0f', '#0e7490', '#1d4ed8'][Math.min(5, t)];
  return (
    <Canvas camera={{ position: [7, 6, 8], fov: 50 }} style={{ background: 'transparent' }}>
      <ambientLight intensity={0.9} /><directionalLight position={[5, 8, 5]} intensity={0.8} />
      {layout.zones.map((z: any, zi: number) => (
        <group key={z.id} position={[0, zi * 2.2 - 0.6, 0]}>
          <mesh rotation={[-Math.PI / 2, 0, 0]}><planeGeometry args={[6.5, 6.5]} /><meshStandardMaterial color={zoneColor(z.trust)} transparent opacity={0.16} side={2} /></mesh>
          <Html position={[-3.1, 0.15, 3.1]} center={false}><div className="text-[11px] px-1.5 py-0.5 rounded bg-black/60 text-white whitespace-nowrap">{z.id} · trust {z.trust}</div></Html>
        </group>))}
      {graph.nodes.map((n: any) => (
        <group key={n.id} position={layout.pos[n.id] ?? [0, 0, 0]} onClick={() => onSelect?.('node', n.id)}>
          <mesh><sphereGeometry args={[0.28, 24, 24]} /><meshStandardMaterial color={n.kind === 'database' ? '#0ea5e9' : n.kind === 'secret' ? '#f59e0b' : n.kind === 'external' ? '#ef4444' : '#22c55e'} /></mesh>
          <Html position={[0, 0.5, 0]} center><div className="text-[11px] px-1 rounded bg-black/55 text-white whitespace-nowrap">{n.id}</div></Html>
        </group>))}
      {graph.edges.map((e: any) => {
        const a = layout.pos[e.from], b = layout.pos[e.to];
        if (!a || !b) return null;
        return <Line key={e.id} points={[a, b]} color={e.missing.length ? '#ef4444' : e.crossing ? '#38bdf8' : '#94a3b8'} lineWidth={e.missing.length ? 2.5 : 1.5} dashed={!!e.missing.length} onClick={() => onSelect?.('edge', e.id)} />;
      })}
      <OrbitControls enablePan enableZoom />
    </Canvas>
  );
}
