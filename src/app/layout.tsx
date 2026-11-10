import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Rec Reports',
  description: 'Operations platform for recreation facilities.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
