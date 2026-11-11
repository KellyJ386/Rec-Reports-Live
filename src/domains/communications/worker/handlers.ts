import { clip, isUuid, runAll } from '@/lib/cron/run-all';
import type { EventHandler, OutboxEvent } from '@/lib/cron/outbox-types';
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

const MAX_RECIPIENTS = 100;

/**
 * notice.published -> one notification for every active member of the audience
 * (`notice_audience_person_ids`, the same rule as the read policy). The notice is re-read by id:
 * an archived or expired notice notifies nobody, and the urgency comes from the row, not the
 * payload. A critical notice is created with urgency "critical" (it ignores notification
 * preferences). The notification carries the title only; the body of the notice is never copied.
 */
export function createNoticeNotifyHandler(
  deps: { notices: NoticeReader; notifier: NotificationPort },
  now: () => number = Date.now,
): EventHandler {
  return {
    name: COMMUNICATIONS_HANDLER_NAMES.notifyNoticeAudience,
    async run(event: OutboxEvent) {
      const notice = await deps.notices.getNotice(event.entityId);
      if (!notice || notice.status !== 'published') return;
      if (notice.expiresAt && Date.parse(notice.expiresAt) <= now()) return;
      const audience = await deps.notifier.noticeAudiencePersonIds(notice.id);
      await runAll(audience, async (personId) => {
        await deps.notifier.createNotification({
          eventId: event.id,
          personId,
          kind: 'notice_published',
          title: clip(notice.title, 120),
          body: notice.requiresAcknowledgment ? 'Please read it and tap Acknowledge.' : null,
          linkPath: noticeLink(notice.id),
          urgency: notice.urgency,
        });
      });
    },
  };
}

/**
 * message.sent -> one notification per recipient. The recipient ids come from the event payload
 * (ids only, written by send_message in the same transaction as the message; create_notification
 * drops anyone who is not an active member). The notification never says who wrote the message or
 * what it said: messages are private to their parties.
 */
export function createMessageNotifyHandler(deps: { notifier: NotificationPort }): EventHandler {
  return {
    name: COMMUNICATIONS_HANDLER_NAMES.notifyMessageRecipients,
    async run(event: OutboxEvent) {
      const raw = event.payload.recipient_person_ids;
      const sender = event.payload.sender_person_id;
      const ids = Array.isArray(raw) ? raw.filter(isUuid) : [];
      const recipients = [...new Set(ids)].filter((id) => id !== sender).slice(0, MAX_RECIPIENTS);
      await runAll(recipients, async (personId) => {
        await deps.notifier.createNotification({
          eventId: event.id,
          personId,
          kind: 'message_received',
          title: 'New message',
          body: null,
          linkPath: MESSAGES_LINK,
          urgency: 'normal',
        });
      });
    },
  };
}
