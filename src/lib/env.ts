import { z } from 'zod';

function tryUrl(v: string): URL | null {
  try {
    return new URL(v);
  } catch {
    return null;
  }
}

const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

/**
 * The public origin of this app, e.g. https://app.example.com. Used to build links that
 * leave the app (password reset emails), so it comes from configuration and never from
 * request headers. Must be a bare origin: http(s), no credentials, path, query or hash.
 * Plain http is only accepted for localhost. Normalised to the origin (no trailing slash).
 */
export const siteUrlSchema = z
  .url({ protocol: /^https?$/ })
  .refine((v) => {
    const u = tryUrl(v);
    return (
      u !== null &&
      u.username === '' &&
      u.password === '' &&
      (u.pathname === '/' || u.pathname === '') &&
      u.search === '' &&
      u.hash === ''
    );
  }, 'SITE_URL must be an origin only, such as https://app.example.com')
  .refine((v) => {
    const u = tryUrl(v);
    return u !== null && (u.protocol === 'https:' || LOCAL_HOSTS.includes(u.hostname));
  }, 'SITE_URL must use https (http is only allowed for localhost)')
  .transform((v) => new URL(v).origin);

export const serverEnvSchema = z.object({
  SITE_URL: siteUrlSchema,
  NEXT_PUBLIC_SUPABASE_URL: z.url(),
  NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: z.string().min(1),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
  CRON_SECRET: z.string().min(1).optional(),
  /**
   * Server secret that signs the idle-timeout cookie and keys the rate-limit hashes. At least
   * 32 characters (for example `openssl rand -base64 48`). Rotating it signs out nobody but
   * restarts the idle clock for non-admin users and signs idle admins out on their next request.
   */
  SESSION_SIGNING_SECRET: z
    .string()
    .min(32, 'SESSION_SIGNING_SECRET must be at least 32 characters'),
});

export const publicEnvSchema = serverEnvSchema.pick({
  NEXT_PUBLIC_SUPABASE_URL: true,
  NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: true,
});

export type ServerEnv = z.infer<typeof serverEnvSchema>;
export type PublicEnv = z.infer<typeof publicEnvSchema>;

/**
 * Public values. Safe in the browser. NEXT_PUBLIC_* must be read as literal
 * property accesses so Next can inline them into the client bundle.
 */
export function getPublicEnv(): PublicEnv {
  return publicEnvSchema.parse({
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
    NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY,
  });
}

/** All values, including secrets. Server only: never import this in a client component. */
export function getServerEnv(): ServerEnv {
  return serverEnvSchema.parse(process.env);
}

/** The configured site origin. Server only. Throws when SITE_URL is missing or invalid. */
export function getSiteUrl(): string {
  return siteUrlSchema.parse(process.env.SITE_URL);
}

export const sessionSecretSchema = serverEnvSchema.shape.SESSION_SIGNING_SECRET;

/**
 * Only the signing secret. The proxy and the rate limiter read this instead of getServerEnv()
 * so they never touch the service-role key. Server only. Throws when missing or too short.
 */
export function getSessionSecret(): string {
  return sessionSecretSchema.parse(process.env.SESSION_SIGNING_SECRET);
}

/** Empty strings (an unfilled `KEY=` line) count as unset. */
const optionalText = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() === '' ? undefined : v),
  z.string().trim().min(1).optional(),
);

/**
 * Optional delivery settings for the notification worker. Every one may be missing: the email
 * channel then skips ("email not configured") and the push channel skips ("push not
 * configured"); nothing here needs a paid service.
 *
 *  - RESEND_API_KEY, EMAIL_FROM: Resend's free tier is enough for the pilot (see
 *    src/domains/communications/worker/channels/email.ts).
 *  - NEXT_PUBLIC_VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY: a VAPID key pair for web push (generate
 *    one with `npx web-push generate-vapid-keys`). The public key is also what the browser
 *    needs to subscribe, which is why it has the NEXT_PUBLIC_ prefix.
 *  - VAPID_SUBJECT: `mailto:` or `https:` contact for push services; defaults to SITE_URL when
 *    that is https.
 */
export const deliveryEnvSchema = z.object({
  RESEND_API_KEY: optionalText,
  EMAIL_FROM: optionalText,
  NEXT_PUBLIC_VAPID_PUBLIC_KEY: optionalText,
  VAPID_PRIVATE_KEY: optionalText,
  VAPID_SUBJECT: optionalText.refine(
    (v) => v === undefined || /^(mailto:[^\s@]+@[^\s@]+|https:\/\/[^\s]+)$/.test(v),
    'VAPID_SUBJECT must be mailto:you@example.com or an https URL',
  ),
});

export type DeliveryEnv = z.infer<typeof deliveryEnvSchema>;

/** Optional delivery settings. Server only. Throws only when a value that is set is malformed. */
export function getDeliveryEnv(): DeliveryEnv {
  return deliveryEnvSchema.parse({
    RESEND_API_KEY: process.env.RESEND_API_KEY,
    EMAIL_FROM: process.env.EMAIL_FROM,
    NEXT_PUBLIC_VAPID_PUBLIC_KEY: process.env.NEXT_PUBLIC_VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY: process.env.VAPID_PRIVATE_KEY,
    VAPID_SUBJECT: process.env.VAPID_SUBJECT,
  });
}
