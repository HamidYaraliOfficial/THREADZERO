import type { Metadata } from 'next';
import './globals.css';
import { AppProvider } from '@/lib/store';
import { AppShell } from '@/components/shell/AppShell';

export const metadata: Metadata = { title: 'THREADZERO — Trust-Boundary Compiler', description: 'Security as compilable architecture' };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" dir="ltr" data-theme="light" suppressHydrationWarning>
      <body><AppProvider><AppShell>{children}</AppShell></AppProvider></body>
    </html>
  );
}
