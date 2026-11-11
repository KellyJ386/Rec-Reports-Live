import type { Metadata } from 'next';
import { redirect } from 'next/navigation';
import { requireUser } from '@/lib/auth/session';
import { getMfaState } from '@/lib/auth/mfa-server';
import { mfaStepPath } from '@/lib/auth/mfa';
import { safeNextPath } from '@/lib/auth/redirect';
import { signOut } from '@/app/app/actions';
import { VerifyForm } from './form';

export const metadata: Metadata = { title: 'Check your code | Rec Reports' };

export default async function VerifyPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  await requireUser();
  const next = safeNextPath((await searchParams).next);
  const { step } = await getMfaState();
  if (step === 'none') redirect(next);
  if (step === 'enroll') redirect(mfaStepPath('enroll', next) ?? '/app/security');

  return (
    <main>
      <h1>Enter your code</h1>
      <p>Open your authenticator app and type the 6-digit code for Rec Reports.</p>
      <VerifyForm next={next} />
      <form action={signOut}>
        <button type="submit">Sign out</button>
      </form>
    </main>
  );
}
