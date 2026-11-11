'use client';

// A form whose refusal may be overridden. The first button asks normally. When the server
// answers with an offer (it built the offer and named the person, the shift and the rule),
// a second form with a separate "Assign anyway" button appears. Nothing is sent as an override
// until that button is pressed, and the server checks the refusal again before it acts.
import { useActionState } from 'react';
import { ActionForm } from './action-form';
import type { AdminFormState } from './actions/helpers';

type Props = {
  action: (previous: AdminFormState, formData: FormData) => Promise<AdminFormState>;
  submitLabel: string;
  overrideLabel: string;
  children?: React.ReactNode;
};

export function OverrideForm({ action, submitLabel, overrideLabel, children }: Props) {
  const [state, formAction, pending] = useActionState<AdminFormState, FormData>(action, {});
  return (
    <>
      <form action={formAction}>
        {children}
        {state.message && !state.offer ? (
          <p role={state.ok ? 'status' : 'alert'}>{state.message}</p>
        ) : null}
        <button type="submit" disabled={pending}>
          {submitLabel}
        </button>
      </form>
      {state.offer ? (
        <section aria-label={overrideLabel}>
          <p role="alert">{state.offer.message}</p>
          <ActionForm action={action} submitLabel={overrideLabel}>
            {Object.entries(state.offer.fields).map(([name, value]) => (
              <input key={name} type="hidden" name={name} value={value} />
            ))}
            <input type="hidden" name="override" value="yes" />
          </ActionForm>
        </section>
      ) : null}
    </>
  );
}
