import type { Metadata } from 'next';
import './globals.css';
import { Navbar } from '@/components/layout/Navbar';
import { Footer } from '@/components/layout/Footer';

export const metadata: Metadata = {
  title: 'Silhouette Reaper // Anonymous Digital Forensics Investigation Platform',
  description:
    'State-of-the-art public anonymous digital forensics pipeline. Real artifact extraction, multi-algorithm hashing, normalized timeline generation, and verifiable forensic examination reports.',
  keywords: [
    'digital forensics',
    'DFIR',
    'incident response',
    'forensic analysis',
    'evidence integrity',
    'SHA-256',
    'EXIF',
    'PDF analysis',
    'timeline analysis',
  ],
  icons: {
    icon: '/logo.svg',
    shortcut: '/logo.svg',
    apple: '/logo.svg',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen flex flex-col bg-[#06080d] bg-grid text-zinc-100 antialiased selection:bg-amber-500 selection:text-black">
        <div className="fixed inset-0 pointer-events-none bg-radial-amber z-0" />
        <Navbar />
        <main className="flex-1 z-10">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
