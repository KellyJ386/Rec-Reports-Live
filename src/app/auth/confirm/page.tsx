import type { Metadata } from 'next';
import Link from 'next/link';
import { describeConfirm, parseConfirmRequest } from '@/lib/auth/confirm';
import { createClient } from '@/lib/supabase/server';
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

  const about = describeConfirm(request);
  // Only the browser's own current session is shown here (never anything from the link).
  const supabase = await createClient();
  const current = (await supabase.auth.getUser()).data.user;

  return (
    <main>
      <h1>{about.heading}</h1>
      {about.lines.map((line) => (
        <p key={line}>{line}</p>
      ))}
      <p>Nothing happens until you press the button. Only continue if you asked for this email.</p>
      {current ? (
        <p role="alert">
          You are signed in{current.email ? ` as ${current.email}` : ''} in this browser. If you
          continue, we sign you out of that account first.
        </p>
      ) : null}
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
        <button type="submit">{about.button}</button>
      </form>
    </main>
  );
}
