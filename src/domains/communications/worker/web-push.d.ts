// web-push 4 ships no types. Only what channels/push.ts uses.
declare module 'web-push' {
  export interface PushSubscriptionLike {
    endpoint: string;
    keys: { p256dh: string; auth: string };
  }
  export interface SendOptions {
    vapidDetails?: { subject: string; publicKey: string; privateKey: string };
    TTL?: number;
    urgency?: 'very-low' | 'low' | 'normal' | 'high';
    timeout?: number;
  }
  export function sendNotification(
    subscription: PushSubscriptionLike,
    payload: string,
    options?: SendOptions,
  ): Promise<{ statusCode: number }>;
}
