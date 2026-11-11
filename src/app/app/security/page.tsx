import type { Metadata } from 'next';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { requireUser } from '@/lib/auth/session';
import { getMfaState } from '@/lib/auth/mfa-server';
import { mfaStepPath } from '@/lib/auth/mfa';
import { safeNextPath } from '@/lib/auth/redirect';
import { EnrollPanel, RemoveDeviceForm } from './form';

export const metadata: Metadata = { title: 'Two-step sign-in | Rec Reports' };

export default async function SecurityPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string; on?: string; removed?: string }>;
}) {
  // Deliberately not behind the admin guards: this is where an admin without a device lands.
  await requireUser();
  const params = await searchParams;
  const next = safeNextPath(params.next);
  const mfa = await getMfaState();
  // Has a device but has not typed a code yet: that comes first (removal needs it anyway).
  if (mfa.step === 'verify') redirect(mfaStepPath('verify', next) ?? '/sign-in/verify');

  const supabase = await createClient();
  const factors = await supabase.auth.mfa.listFactors();
  const devices = factors.error ? [] : factors.data.totp;
  const failed = Boolean(factors.error);
  const isOn = devices.length > 0;

  return (
    <main>
      <h1>Two-step sign-in</h1>
      <p>
        <Link href="/app">Home</Link>
      </p>

      {params.on ? <p role="status">Two-step sign-in is on.</p> : null}
      {params.removed ? <p role="status">Device removed.</p> : null}
      {failed ? <p role="alert">Could not load this right now. Try again in a moment.</p> : null}

      <h2>Status</h2>
      <p>{isOn ? 'Two-step sign-in is on.' : 'Two-step sign-in is off.'}</p>
      {mfa.needsMfa && !isOn ? (
        <p role="alert">Your role needs two-step sign-in. Set it up to open the admin screens.</p>
      ) : null}
      {!mfa.needsMfa && !isOn && !failed ? (
        <p>It is optional for you. It adds a code from your phone to every sign-in.</p>
      ) : null}

      {isOn ? (
        <>
          <h2>Your devices</h2>
          <ul>
            {devices.map((d) => (
              <li key={d.id}>
                <p>
                  {d.friendly_name ?? 'Authenticator app'} (added{' '}
                  {new Date(d.created_at).toISOString().slice(0, 10)})
                </p>
                <details>
                  <summary>Remove this device</summary>
                  <p>Enter a current code from it to confirm.</p>
                  <RemoveDeviceForm factorId={d.id} />
                </details>
              </li>
            ))}
          </ul>
          {params.next ? (
            <p>
              <Link href={next}>Continue</Link>
            </p>
          ) : null}
        </>
      ) : failed ? null : (
        <>
          <h2>Set up</h2>
          <EnrollPanel next={next} />
        </>
      )}
    </main>
  );
}
