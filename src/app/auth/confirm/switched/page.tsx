import type { Metadata } from 'next';
import Link from 'next/link';
import { safeNextPath } from '@/lib/auth/redirect';

export const metadata: Metadata = {
  title: 'Signed in with a link | Rec Reports',
  robots: { index: false, follow: false },
  referrer: 'no-referrer',
};

// Shown after a confirmed link replaced a different person's session in this browser. It holds
// nothing about either account: it only explains what happened and passes on to the next step.
export default async function SwitchedPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const next = safeNextPath((await searchParams).next, '/app');
  return (
    <main>
      <h1>You are signed in with this link</h1>
      <p>
        Someone else was already signed in in this browser. We signed that account out and signed
        you in with the link instead.
      </p>
      <p>If you did not expect this, sign out now and tell your administrator.</p>
      <p>
        <Link href={next}>Continue</Link>
      </p>
    </main>
  );
}
