import type { Metadata } from 'next';
import Link from 'next/link';
import { parseConfirmRequest } from '@/lib/auth/confirm';
import { confirmLink } from './actions';

// Rendering this page verifies nothing. The button below posts to a Server Action.
export const metadata: Metadata = {
  title: 'Continue | Rec Reports',
  robots: { index: false, follow: false },
  referrer: 'no-referrer',
};

export default async function ConfirmPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const request = parseConfirmRequest(await searchParams);

  if (!request) {
    return (
      <main>
        <h1>This link is not valid</h1>
        <p>
          It may be incomplete. <Link href="/sign-in">Go to sign in</Link>, or{' '}
          <Link href="/forgot-password">ask for a new link</Link>.
        </p>
      </main>
    );
  }

  return (
    <main>
      <h1>Continue</h1>
      <p>Press the button to finish. Nothing happens until you do.</p>
      <form action={confirmLink}>
        {request.kind === 'otp' ? (
          <>
            <input type="hidden" name="token_hash" value={request.tokenHash} />
            <input type="hidden" name="type" value={request.type} />
          </>
        ) : (
          <input type="hidden" name="code" value={request.code} />
        )}
        <input type="hidden" name="next" value={request.next} />
        <button type="submit">Continue</button>
      </form>
    </main>
  );
}
