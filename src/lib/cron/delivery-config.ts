import type { DeliveryEnv } from '@/lib/env';

export interface ResolvedDeliveryConfig {
  email: { apiKey?: string; from?: string };
  vapid: { subject: string; publicKey: string; privateKey: string } | null;
}

/**
 * Turns the optional environment values into channel settings. Email needs both the API key and
 * the sender; push needs both VAPID keys and a contact subject (VAPID_SUBJECT, or SITE_URL when
 * that is https). Anything less leaves the channel unconfigured, and it skips.
 */
export function resolveDeliveryConfig(env: DeliveryEnv, siteUrl: string): ResolvedDeliveryConfig {
  const subject = env.VAPID_SUBJECT ?? (siteUrl.startsWith('https://') ? siteUrl : undefined);
  const publicKey = env.NEXT_PUBLIC_VAPID_PUBLIC_KEY;
  const privateKey = env.VAPID_PRIVATE_KEY;
  return {
    email: { apiKey: env.RESEND_API_KEY, from: env.EMAIL_FROM },
    vapid: subject && publicKey && privateKey ? { subject, publicKey, privateKey } : null,
  };
}
