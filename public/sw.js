// Rec Reports service worker: push notifications only.
//
// It shows a notification when a push arrives and opens the link when the notification is
// tapped. It does not cache anything and does not work offline (that is Phase 5; see
// docs/ARCHITECTURE.md). The payload is built by the notification worker
// (src/domains/communications/worker/payloads.ts): { title, body, url, urgent }.

const FALLBACK = {
  title: 'Rec Reports',
  body: 'Open Rec Reports to read it',
  url: '/app',
  urgent: false,
};

function readPayload(event) {
  try {
    const data = event.data ? event.data.json() : null;
    if (data && typeof data === 'object') {
      return {
        title:
          typeof data.title === 'string' && data.title ? data.title.slice(0, 120) : FALLBACK.title,
        body: typeof data.body === 'string' && data.body ? data.body.slice(0, 200) : FALLBACK.body,
        url: typeof data.url === 'string' ? data.url : FALLBACK.url,
        urgent: data.urgent === true,
      };
    }
  } catch {
    // Not JSON: show the fallback.
  }
  return FALLBACK;
}

// Only links to this site are opened, whatever the payload says.
function safeUrl(url) {
  try {
    const target = new URL(url, self.location.origin);
    return target.origin === self.location.origin
      ? target.href
      : new URL('/app', self.location.origin).href;
  } catch {
    return new URL('/app', self.location.origin).href;
  }
}

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  const n = readPayload(event);
  event.waitUntil(
    self.registration.showNotification(n.title, {
      body: n.body,
      data: { url: safeUrl(n.url) },
      requireInteraction: n.urgent,
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = safeUrl(event.notification.data && event.notification.data.url);
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windows) => {
      for (const client of windows) {
        if ('focus' in client) {
          return client
            .focus()
            .then((focused) => ('navigate' in focused ? focused.navigate(url) : focused));
        }
      }
      return self.clients.openWindow(url);
    }),
  );
});
