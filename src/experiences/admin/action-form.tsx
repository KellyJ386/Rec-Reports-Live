'use client';

// A form that runs a Server Action and shows its plain-language result. The only client
// logic: useActionState for the message, and putting typed values back after a refusal
// (React clears a form after every action, which would lose what the person typed).
import { useActionState, useEffect, useRef } from 'react';
import type { AdminFormState } from './actions/helpers';

type Props = {
  action: (previous: AdminFormState, formData: FormData) => Promise<AdminFormState>;
  submitLabel: string;
  children?: React.ReactNode;
};

export function ActionForm({ action, submitLabel, children }: Props) {
  const [state, formAction, pending] = useActionState<AdminFormState, FormData>(action, {});
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    const form = formRef.current;
    if (!form || state.ok || !state.values) return;
    for (const [name, value] of Object.entries(state.values)) {
      const field = form.elements.namedItem(name);
      if (
        (field instanceof HTMLInputElement &&
          field.type !== 'checkbox' &&
          field.type !== 'radio' &&
          field.type !== 'hidden') ||
        field instanceof HTMLTextAreaElement ||
        field instanceof HTMLSelectElement
      ) {
        field.value = value;
      }
    }
  }, [state]);

  return (
    <form action={formAction} ref={formRef}>
      {children}
      {state.message ? <p role={state.ok ? 'status' : 'alert'}>{state.message}</p> : null}
      <button type="submit" disabled={pending}>
        {submitLabel}
      </button>
    </form>
  );
}
