'use client';

// The sign-out button. It is a normal form posting to the signOut Server Action, so it works
// with JavaScript off. With JavaScript on, it first looks up this browser's push subscription,
// puts its endpoint in a hidden field (the server deletes that row for the person) and
// unsubscribes it, then submits. Every step is best effort and time-boxed: a failure never stops
// the sign-out. Nothing is stored in the browser.
import { useRef, type FormEvent } from 'react';
import { signOut } from './actions';

const STEP_TIMEOUT_MS = 2500;

function withTimeout<T>(work: Promise<T>): Promise<T | null> {
  return Promise.race([
    work,
    new Promise<null>((resolve) => setTimeout(() => resolve(null), STEP_TIMEOUT_MS)),
  ]);
}

export function SignOutForm() {
  const endpoint = useRef<HTMLInputElement>(null);
  const ready = useRef(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    if (ready.current) return;
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const subscription = await withTimeout(
        (async () => {
          const registration = await navigator.serviceWorker.getRegistration('/sw.js');
          return registration ? await registration.pushManager.getSubscription() : null;
        })(),
      );
      if (subscription) {
        if (endpoint.current) endpoint.current.value = subscription.endpoint;
        await withTimeout(subscription.unsubscribe().catch(() => false));
      }
    } catch {
      // Sign out anyway.
    }
    ready.current = true;
    form.requestSubmit();
  }

  return (
    <form action={signOut} onSubmit={onSubmit}>
      <input ref={endpoint} type="hidden" name="push_endpoint" defaultValue="" />
      <button type="submit">Sign out</button>
    </form>
  );
}
