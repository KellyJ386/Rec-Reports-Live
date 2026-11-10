import Link from 'next/link';
import { safeNextPath } from '@/lib/auth/redirect';
import { SignInForm } from './form';

const LINK_ERROR = 'That link is invalid or has expired. Request a new one.';

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string; error?: string }>;
}) {
  const { next, error } = await searchParams;
  return (
    <main>
      <h1>Sign in</h1>
      {error === 'link' ? <p role="alert">{LINK_ERROR}</p> : null}
      <SignInForm next={safeNextPath(next)} />
      <p>
        <Link href="/forgot-password">Forgot password?</Link>
      </p>
    </main>
  );
}
