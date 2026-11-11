import { chunk, clip, isUuid } from '@/lib/cron/run-all';
import type { EventHandler, HandlerContext, OutboxEvent } from '@/lib/cron/outbox-types';
import type { NoticeReader, NotificationPort } from './types';

/** Ledger names (see HANDLER_NAMES in the workflows worker: add, never rename). */
export const COMMUNICATIONS_HANDLER_NAMES = {
  notifyNoticeAudience: 'notify_notice_audience',
  notifyMessageRecipients: 'notify_message_recipients',
} as const;

/** App-relative links (screens: src/app/app/notices, src/app/app/messages). */
export function noticeLink(noticeId: string): string {
  return `/app/notices/${noticeId}`;
}
export const MESSAGES_LINK = '/app/messages';

/** People per create_notifications call. The database takes 10,000; small chunks keep each call short. */
export const NOTIFY_CHUNK = 200;

/**
 * notice.published -> one notification for every active member of the audience
 * (`notice_audience_person_ids`, the same rule as the read policy: it returns nobody unless the
 * notice is published and live). The notice is re-read through the event (worker_notice_for_event):
 * an archived or expired notice notifies nobody, and the urgency comes from the row, not the
 * payload. A critical notice is created with urgency "critical" (it ignores notification
 * preferences). The notification carries the title only; the body of the notice is never copied.
 * The audience is notified in chunks, with a deadline check and lock extension before each.
 */
export function createNoticeNotifyHandler(
  deps: { notices: NoticeReader; notifier: NotificationPort },
  now: () => number = Date.now,
): EventHandler {
  return {
    name: COMMUNICATIONS_HANDLER_NAMES.notifyNoticeAudience,
    async run(event: OutboxEvent, ctx: HandlerContext) {
      const notice = await deps.notices.getNoticeForEvent(event.id);
      if (!notice || notice.status !== 'published') return;
      if (notice.expiresAt && Date.parse(notice.expiresAt) <= now()) return;
      const audience = await deps.notifier.noticeAudiencePersonIds(notice.id);
      for (const personIds of chunk(audience, NOTIFY_CHUNK)) {
        await ctx.checkpoint();
        await deps.notifier.createNotifications({
          eventId: event.id,
          personIds,
          kind: 'notice_published',
          title: clip(notice.title, 120),
          body: notice.requiresAcknowledgment ? 'Please read it and tap Acknowledge.' : null,
          linkPath: noticeLink(notice.id),
          urgency: notice.urgency,
        });
      }
    },
  };
}

/**
 * message.sent -> would notify the recipients, but cannot yet. Since migration 000600 the event
 * payload is `{message_id}` only and `message.*` events are hidden, and the database gives the
 * worker no function that returns a message's recipients. The handler therefore fans out only
 * when a payload still lists recipients (events written before that migration were scrubbed, so
 * in practice it does nothing). Reading `message_recipients` directly is not allowed: see the
 * "database gap" note in the report. The notification would never say who wrote the message or
 * what it said.
 */
export function createMessageNotifyHandler(deps: { notifier: NotificationPort }): EventHandler {
  return {
    name: COMMUNICATIONS_HANDLER_NAMES.notifyMessageRecipients,
    async run(event: OutboxEvent, ctx: HandlerContext) {
      const raw = event.payload.recipient_person_ids;
      const sender = event.payload.sender_person_id;
      const ids = Array.isArray(raw) ? raw.filter(isUuid) : [];
      const recipients = [...new Set(ids)].filter((id) => id !== sender);
      for (const personIds of chunk(recipients, NOTIFY_CHUNK)) {
        await ctx.checkpoint();
        await deps.notifier.createNotifications({
          eventId: event.id,
          personIds,
          kind: 'message_received',
          title: 'New message',
          body: null,
          linkPath: MESSAGES_LINK,
          urgency: 'normal',
        });
      }
    },
  };
}
