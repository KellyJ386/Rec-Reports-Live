'use client';

import { useActionState, useState, useTransition } from 'react';
import { confirmEnrollment, removeFactor, startEnrollment, type EnrollState } from './actions';
import type { FormState } from '@/lib/auth/schemas';

const CODE_INPUT = {
  type: 'text',
  name: 'code',
  inputMode: 'numeric' as const,
  autoComplete: 'one-time-code',
  pattern: '[0-9 \\-]*',
  maxLength: 10,
  required: true,
};

export function EnrollPanel({ next }: { next: string }) {
  const [started, setStarted] = useState<EnrollState>({});
  const [pendingStart, startTransition] = useTransition();
  const [confirmState, confirmAction, confirming] = useActionState<EnrollState, FormData>(
    confirmEnrollment,
    {},
  );

  if (!started.factorId) {
    return (
      <div>
        <button
          type="button"
          disabled={pendingStart}
          onClick={() => startTransition(async () => setStarted(await startEnrollment()))}
        >
          Set up two-step sign-in
        </button>
        {started.message ? <p role="alert">{started.message}</p> : null}
      </div>
    );
  }

  return (
    <div>
      <ol>
        <li>
          Open an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password or
          similar) and add an account.
        </li>
        <li>
          {started.qrCode ? (
            <>
              Scan this code:
              <br />
              {/* eslint-disable-next-line @next/next/no-img-element -- an SVG data URI from Supabase */}
              <img
                src={started.qrCode}
                alt="QR code for your authenticator app"
                width={200}
                height={200}
              />
              <br />
              Cannot scan it? Type this key in instead:
            </>
          ) : (
            <>The picture is not available. Type this key into your app instead:</>
          )}{' '}
          <code>{started.secret}</code>
          {started.uri ? (
            <details>
              <summary>Setup link text</summary>
              <code>{started.uri}</code>
            </details>
          ) : null}
        </li>
        <li>Type the 6-digit code your app shows.</li>
      </ol>
      <form action={confirmAction}>
        <input type="hidden" name="factorId" value={started.factorId} />
        <input type="hidden" name="next" value={next} />
        <p>
          <label>
            6-digit code <input {...CODE_INPUT} />
          </label>
        </p>
        {confirmState.message ? <p role="alert">{confirmState.message}</p> : null}
        <button type="submit" disabled={confirming}>
          Turn on
        </button>
      </form>
    </div>
  );
}

export function RemoveDeviceForm({ factorId }: { factorId: string }) {
  const [state, action, pending] = useActionState<FormState, FormData>(removeFactor, {});
  return (
    <form action={action}>
      <input type="hidden" name="factorId" value={factorId} />
      <p>
        <label>
          Current 6-digit code <input {...CODE_INPUT} />
        </label>{' '}
        <button type="submit" disabled={pending}>
          Remove device
        </button>
      </p>
      {state.message ? <p role="alert">{state.message}</p> : null}
    </form>
  );
}
