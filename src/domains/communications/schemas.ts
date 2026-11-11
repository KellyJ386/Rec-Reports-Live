// Input validation for the communications domain: notices (with their audiences),
// publishing, direct and group messages, push subscriptions and notification
// preferences. Mirrors supabase/migrations/20261112000400_communications.sql (notices,
// audiences, messages) and 20261112000500_notifications.sql (push subscriptions,
// preferences). The database stays the authority; these schemas reject bad input first.
//
// Strict objects: unknown keys are rejected (status, author, published_at and the
// like are never accepted from a client).
import { z } from 'zod';

const trimmedText = (min: number, max: number, message: string) =>
  z.string().trim().min(min, message).max(max, message);

const isoDateTime = z.iso.datetime({ offset: true });
const nonEmpty = <T extends z.ZodTypeAny>(s: T) =>
  s.refine((v) => Object.keys(v as object).length > 0, 'Nothing to update');

export const NOTICE_URGENCIES = ['normal', 'high', 'critical'] as const;
export const noticeUrgencySchema = z.enum(NOTICE_URGENCIES);

// A notice is shown until expires_at, which must come after publish_at (table CHECK).
function expiresAfterPublish(v: { publish_at?: string | null; expires_at?: string | null }) {
  if (!v.publish_at || !v.expires_at) return true;
  return Date.parse(v.expires_at) > Date.parse(v.publish_at);
}
const EXPIRY_MESSAGE = 'The notice must expire after it is shown';

// An audience row: (location or null = every location) x (job title or null = everyone).
export const noticeAudienceSchema = z.strictObject({
  location_id: z.uuid().nullable(),
  job_title_id: z.uuid().nullable(),
});

const noticeFields = {
  title: trimmedText(1, 200, 'Give the notice a title of up to 200 characters'),
  body: trimmedText(1, 5000, 'The notice needs 1 to 5000 characters'),
  urgency: noticeUrgencySchema,
  requires_acknowledgment: z.boolean(),
  publish_at: isoDateTime.nullable(),
  expires_at: isoDateTime.nullable(),
};

// Creates a draft. Status, author and publish stamps are set by the database. The
// audiences are inserted with the notice; each row must be unique, and a notice with a
// home location can only target that location (notice_audiences policy).
export const noticeCreateSchema = z
  .strictObject({
    organization_id: z.uuid(),
    location_id: z.uuid().nullable(),
    ...noticeFields,
    requires_acknowledgment: noticeFields.requires_acknowledgment.default(false),
    publish_at: noticeFields.publish_at.optional(),
    expires_at: noticeFields.expires_at.optional(),
    audiences: z.array(noticeAudienceSchema).max(200, 'Too many audiences').default([]),
  })
  .refine(expiresAfterPublish, { message: EXPIRY_MESSAGE, path: ['expires_at'] })
  .refine(
    (v) => {
      const seen = new Set<string>();
      for (const a of v.audiences) {
        const key = `${a.location_id ?? '*'}|${a.job_title_id ?? '*'}`;
        if (seen.has(key)) return false;
        seen.add(key);
      }
      return true;
    },
    { message: 'Each audience can be added only once', path: ['audiences'] },
  )
  .refine(
    (v) => v.location_id === null || v.audiences.every((a) => a.location_id === v.location_id),
    {
      message: 'A notice for one location can only be sent to that location',
      path: ['audiences'],
    },
  );

// Only drafts are edited (policy and grant: title, body, urgency, requires_acknowledgment,
// publish_at, expires_at). Audiences are changed through their own rows.
export const noticeUpdateSchema = nonEmpty(
  z
    .strictObject(noticeFields)
    .partial()
    .refine(expiresAfterPublish, { message: EXPIRY_MESSAGE, path: ['expires_at'] }),
);

// Publish a draft that has at least one audience. publish_at null or absent = now
// (the RPC keeps an earlier value set on the draft). A time in the past is shown at once.
export const noticePublishSchema = z.strictObject({
  notice_id: z.uuid(),
  publish_at: isoDateTime.nullable().optional(),
});

// A direct or group message. The sender is the caller's person (set by the RPC).
// The RPC removes duplicate recipients; after that 1 to 50 people remain.
export const messageSendSchema = z.strictObject({
  organization_id: z.uuid(),
  recipient_person_ids: z
    .array(z.uuid())
    .max(200, 'Too many recipients')
    .refine(
      (ids) => {
        const unique = new Set(ids).size;
        return unique >= 1 && unique <= 50;
      },
      { message: 'Choose 1 to 50 people' },
    ),
  body: trimmedText(1, 4000, 'A message needs 1 to 4000 characters'),
});

// Registers this browser for web push. The endpoint and keys are never sent back to a
// client (grant), so this schema is input only.
const ENDPOINT = /^https:\/\/\S+$/;
const P256DH = /^[A-Za-z0-9_-]{20,200}={0,2}$/;
const AUTH_SECRET = /^[A-Za-z0-9_-]{8,100}={0,2}$/;
/**
 * A push endpoint sent by the browser on sign-out: the same shape the table accepts (https, no
 * spaces, at most 2000 characters), else null. Anything else is ignored and sign-out goes on.
 */
export function parsePushEndpoint(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  return text.length <= 2000 && ENDPOINT.test(text) ? text : null;
}

// The same rule as private.push_endpoint_allowed (migration 20261112000600): https, no userinfo,
// port 443 or none, a path, and one of the known push services. The host part of the pattern
// excludes `/ ? # @ :` and spaces, so userinfo, other ports and look-alike hosts such as
// fcm.googleapis.com.evil.example or evil.example/fcm.googleapis.com cannot match.
const ENDPOINT_SHAPE = /^https:\/\/[^/?#@:\s]+(:443)?\/\S*$/;
const ENDPOINT_HOST = /^https:\/\/([^/?#@:\s]+)/;
const PUSH_HOSTS = new Set(['fcm.googleapis.com', 'updates.push.services.mozilla.com']);
const APPLE_HOST = /^([a-z0-9-]+\.)+push\.apple\.com$/;
const WINDOWS_HOST = /^([a-z0-9-]+\.)+notify\.windows\.com$/;

export function isAllowedPushEndpoint(value: string): boolean {
  if (value.length > 2000 || !ENDPOINT_SHAPE.test(value)) return false;
  const host = ENDPOINT_HOST.exec(value)?.[1]?.toLowerCase();
  if (!host) return false;
  return PUSH_HOSTS.has(host) || APPLE_HOST.test(host) || WINDOWS_HOST.test(host);
}

export const PUSH_NOT_SUPPORTED_MESSAGE = 'This push service is not supported.';

export const pushSubscriptionSaveSchema = z.strictObject({
  organization_id: z.uuid(),
  endpoint: z
    .string()
    .max(2000, 'The push endpoint is too long')
    .refine(isAllowedPushEndpoint, PUSH_NOT_SUPPORTED_MESSAGE),
  p256dh: z.string().regex(P256DH, 'The push key is not valid'),
  auth_secret: z.string().regex(AUTH_SECRET, 'The push secret is not valid'),
  // The RPC keeps the first 300 characters; a longer value is refused here instead.
  user_agent: z.string().max(300, 'The browser name is too long').nullable().optional(),
});

// One channel per person (unique person_id + channel). In-app is always on and is not a
// channel here. Critical notices ignore these settings.
export const NOTIFICATION_CHANNELS = ['email', 'push'] as const;
export const notificationChannelSchema = z.enum(NOTIFICATION_CHANNELS);

export const notificationPreferenceSaveSchema = z.strictObject({
  organization_id: z.uuid(),
  person_id: z.uuid(),
  channel: notificationChannelSchema,
  enabled: z.boolean(),
});

// The only column a person may change after creating the row.
export const notificationPreferenceUpdateSchema = z.strictObject({
  enabled: z.boolean(),
});

export type NoticeCreate = z.infer<typeof noticeCreateSchema>;
export type NoticeUpdate = z.infer<typeof noticeUpdateSchema>;
export type NoticePublish = z.infer<typeof noticePublishSchema>;
export type MessageSend = z.infer<typeof messageSendSchema>;
export type PushSubscriptionSave = z.infer<typeof pushSubscriptionSaveSchema>;
export type NotificationPreferenceSave = z.infer<typeof notificationPreferenceSaveSchema>;
export type NotificationPreferenceUpdate = z.infer<typeof notificationPreferenceUpdateSchema>;
