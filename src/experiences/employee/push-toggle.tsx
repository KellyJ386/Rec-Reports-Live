'use client';

// "Turn on notifications on this device": registers /sw.js, asks permission, subscribes to web
// push and saves the subscription through a Server Action. This is the one place a client
// component is needed, because only the browser can do those steps. Nothing is stored in the
// browser; the endpoint and keys go straight to the server.
import { useEffect, useState } from 'react';
import type { DeviceResult } from './actions/notifications';

type Props = {
  /** NEXT_PUBLIC_VAPID_PUBLIC_KEY, read on the server and passed in. */
  vapidPublicKey: string;
  save: (input: {
    endpoint: string;
    p256dh: string;
    auth: string;
    userAgent?: string;
  }) => Promise<DeviceResult>;
  remove: (input: { endpoint: string }) => Promise<DeviceResult>;
};

type Status = 'checking' | 'unsupported' | 'blocked' | 'off' | 'on';

function keyToBytes(base64Url: string): Uint8Array<ArrayBuffer> {
  const padded = base64Url
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(base64Url.length / 4) * 4, '=');
  const raw = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function supported(): boolean {
  return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
}

export function PushToggle({ vapidPublicKey, save, remove }: Props) {
  const [status, setStatus] = useState<Status>('checking');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function check() {
      if (!supported()) {
        if (!cancelled) setStatus('unsupported');
        return;
      }
      if (Notification.permission === 'denied') {
        if (!cancelled) setStatus('blocked');
        return;
      }
      try {
        const registration = await navigator.serviceWorker.getRegistration('/sw.js');
        const existing = registration ? await registration.pushManager.getSubscription() : null;
        if (!cancelled) setStatus(existing ? 'on' : 'off');
      } catch {
        if (!cancelled) setStatus('off');
      }
    }
    void check();
    return () => {
      cancelled = true;
    };
  }, []);

  async function turnOn() {
    setBusy(true);
    setMessage('');
    try {
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        setStatus('blocked');
        return;
      }
      const registration = await navigator.serviceWorker.register('/sw.js');
      await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: keyToBytes(vapidPublicKey),
      });
      const json = subscription.toJSON();
      const result = await save({
        endpoint: json.endpoint ?? '',
        p256dh: json.keys?.p256dh ?? '',
        auth: json.keys?.auth ?? '',
        userAgent: navigator.userAgent,
      });
      if (!result.ok) {
        await subscription.unsubscribe().catch(() => false);
        setMessage(result.message);
        return;
      }
      setStatus('on');
      setMessage(result.message);
    } catch {
      setMessage('This device could not be set up for notifications.');
    } finally {
      setBusy(false);
    }
  }

  async function turnOff() {
    setBusy(true);
    setMessage('');
    try {
      const registration = await navigator.serviceWorker.getRegistration('/sw.js');
      const subscription = registration ? await registration.pushManager.getSubscription() : null;
      if (subscription) {
        const result = await remove({ endpoint: subscription.endpoint });
        if (!result.ok) {
          setMessage(result.message);
          return;
        }
        await subscription.unsubscribe().catch(() => false);
      }
      setStatus('off');
      setMessage('Notifications are off for this device.');
    } catch {
      setMessage('Notifications could not be turned off. Try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      {status === 'checking' ? <p>Checking this device...</p> : null}
      {status === 'unsupported' ? (
        <p>
          This browser cannot show notifications. Try another browser, or add the app to your home
          screen.
        </p>
      ) : null}
      {status === 'blocked' ? (
        <p>
          Notifications are blocked for this site. Allow them in your browser settings, then reload
          this page.
        </p>
      ) : null}
      {status === 'off' ? (
        <button type="button" onClick={turnOn} disabled={busy}>
          Turn on notifications on this device
        </button>
      ) : null}
      {status === 'on' ? (
        <>
          <p>Notifications are on for this device.</p>
          <button type="button" onClick={turnOff} disabled={busy}>
            Turn off notifications on this device
          </button>
        </>
      ) : null}
      {message ? <p role="status">{message}</p> : null}
    </div>
  );
}
