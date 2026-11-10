'use client';

import { useActionState } from 'react';
import { resetPassword } from './actions';
import type { FormState } from '@/lib/auth/schemas';

export function ResetPasswordForm() {
  const [state, action, pending] = useActionState<FormState, FormData>(resetPassword, {});
  return (
    <form action={action}>
      <p>
        <label>
          New password{' '}
          <input type="password" name="password" autoComplete="new-password" required />
        </label>
      </p>
      <p>
        <label>
          Repeat new password{' '}
          <input type="password" name="confirmPassword" autoComplete="new-password" required />
        </label>
      </p>
      {state.message ? <p role="alert">{state.message}</p> : null}
      <button type="submit" disabled={pending}>
        Set password
      </button>
    </form>
  );
}
