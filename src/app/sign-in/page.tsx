import Link from 'next/link';
import { safeNextPath } from '@/lib/auth/redirect';
import { IDLE_NOTE } from '@/lib/auth/activity';
import { RATE_LIMITED_MESSAGE } from '@/lib/rate-limit-constants';
import { SignInForm } from './form';

const LINK_ERROR = 'That link is invalid or has expired. Request a new one.';

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string; error?: string; reason?: string }>;
}) {
  const { next, error, reason } = await searchParams;
  return (
    <main>
      <h1>Sign in</h1>
      {error === 'link' ? <p role="alert">{LINK_ERROR}</p> : null}
      {error === 'limit' ? <p role="alert">{RATE_LIMITED_MESSAGE}</p> : null}
      {reason === 'idle' ? <p role="status">{IDLE_NOTE}</p> : null}
      <SignInForm next={safeNextPath(next)} />
      <p>
        <Link href="/forgot-password">Forgot password?</Link>
      </p>
    </main>
  );
}
