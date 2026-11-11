'use client';

import { useActionState } from 'react';
import { requestPasswordReset } from './actions';
import type { FormState } from '@/lib/auth/schemas';

export function ForgotPasswordForm() {
  const [state, action, pending] = useActionState<FormState, FormData>(requestPasswordReset, {});
  return (
    <form action={action}>
      <p>
        <label>
          Email <input type="email" name="email" autoComplete="email" required />
        </label>
      </p>
      {state.message ? <p role={state.ok ? 'status' : 'alert'}>{state.message}</p> : null}
      <button type="submit" disabled={pending}>
        Send reset link
      </button>
    </form>
  );
}
