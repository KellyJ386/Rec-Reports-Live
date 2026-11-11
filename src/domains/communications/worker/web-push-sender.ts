import { sendNotification } from 'web-push';
import type { PushSender, VapidConfig } from './channels/push';

/** The real PushSender, using the `web-push` package. VAPID details are passed per call (no global state). */
export function createWebPushSender(vapid: VapidConfig): PushSender {
  return async (target, payload, options) => {
    await sendNotification(
      { endpoint: target.endpoint, keys: { p256dh: target.p256dh, auth: target.authSecret } },
      payload,
      {
        vapidDetails: vapid,
        TTL: options.ttlSeconds,
        urgency: options.urgency,
        timeout: options.timeoutMs,
      },
    );
  };
}
