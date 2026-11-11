// web-push 4 ships no types. Only what web-push-sender.ts uses.
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
  export interface RequestDetails {
    endpoint: string;
    method: string;
    headers: Record<string, string>;
    body: Buffer;
    timeout?: number;
  }
  /** Builds the encrypted, signed request without sending it. Throws on a bad subscription or key. */
  export function generateRequestDetails(
    subscription: PushSubscriptionLike,
    payload: string,
    options?: SendOptions,
  ): RequestDetails;
}
