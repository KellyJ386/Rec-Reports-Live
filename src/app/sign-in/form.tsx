'use client';

import { useActionState } from 'react';
import { signIn } from './actions';
import type { FormState } from '@/lib/auth/schemas';

export function SignInForm({ next }: { next: string }) {
  const [state, action, pending] = useActionState<FormState, FormData>(signIn, {});
  return (
    <form action={action}>
      <input type="hidden" name="next" value={next} />
      <p>
        <label>
          Email <input type="email" name="email" autoComplete="username" required />
        </label>
      </p>
      <p>
        <label>
          Password{' '}
          <input type="password" name="password" autoComplete="current-password" required />
        </label>
      </p>
      {state.message ? <p role="alert">{state.message}</p> : null}
      <button type="submit" disabled={pending}>
        Sign in
      </button>
    </form>
  );
}
