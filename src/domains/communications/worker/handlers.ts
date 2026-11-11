import { chunk, clip } from '@/lib/cron/run-all';
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
/** Same underscore style as the other kinds (notice_published, task_created). The database accepts [a-z0-9_.]. */
export const MESSAGE_NOTIFICATION_KIND = 'message_received';
export const MESSAGE_NOTIFICATION_TITLE = 'You have a new message';

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
 * message.sent -> one notification for each recipient `worker_message_recipients_for_event`
 * returns (active members who received it, never the sender), with the link it gives. The text is
 * generic on purpose: no sender, no subject, no body, so message content never reaches
 * notifications, email or push. Done in chunks with a checkpoint before each; re-runs create
 * nothing new.
 */
export function createMessageNotifyHandler(deps: { notifier: NotificationPort }): EventHandler {
  return {
    name: COMMUNICATIONS_HANDLER_NAMES.notifyMessageRecipients,
    async run(event: OutboxEvent, ctx: HandlerContext) {
      const rows = await deps.notifier.messageRecipients(event.id);
      const byLink = new Map<string, string[]>();
      for (const r of rows) byLink.set(r.linkPath, [...(byLink.get(r.linkPath) ?? []), r.personId]);
      for (const [linkPath, people] of byLink) {
        for (const personIds of chunk([...new Set(people)], NOTIFY_CHUNK)) {
          await ctx.checkpoint();
          await deps.notifier.createNotifications({
            eventId: event.id,
            personIds,
            kind: MESSAGE_NOTIFICATION_KIND,
            title: MESSAGE_NOTIFICATION_TITLE,
            body: null,
            linkPath,
            urgency: 'normal',
          });
        }
      }
    },
  };
}
