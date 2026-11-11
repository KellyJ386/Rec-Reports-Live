'use client';

import { useActionState } from 'react';
import { verifySignInCode } from './actions';
import type { FormState } from '@/lib/auth/schemas';

export function VerifyForm({ next }: { next: string }) {
  const [state, action, pending] = useActionState<FormState, FormData>(verifySignInCode, {});
  return (
    <form action={action}>
      <input type="hidden" name="next" value={next} />
      <p>
        <label>
          6-digit code{' '}
          <input
            type="text"
            name="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9 \-]*"
            maxLength={10}
            required
          />
        </label>
      </p>
      {state.message ? <p role="alert">{state.message}</p> : null}
      <button type="submit" disabled={pending}>
        Check code
      </button>
    </form>
  );
}
