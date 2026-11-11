// Ports and shapes of the communications worker (notification fan-out and delivery).
// Production implementations: ./supabase-ports.ts. Test implementation: src/lib/cron/testing.

export type Urgency = 'normal' | 'high' | 'critical';
export type Channel = 'in_app' | 'email' | 'push';

export interface CreateNotificationsInput {
  eventId: string;
  /** 1 to 10,000 people. Duplicates, unknown people and people of another organization are skipped. */
  personIds: string[];
  kind: string;
  title: string;
  body?: string | null;
  linkPath?: string | null;
  urgency?: Urgency;
}

/** create_notifications, notice_audience_person_ids and task_recipient_person_ids (migrations 000500, 000600). */
export interface NotificationPort {
  /**
   * One notification per (event, person, kind), with its delivery rows, for a whole list of
   * people in one call. Idempotent: a re-run makes nothing new. Returns how many people have the
   * notification now (new or existing); people who are not active members are skipped.
   */
  createNotifications(input: CreateNotificationsInput): Promise<number>;
  /** Active members in a notice's audience. */
  noticeAudiencePersonIds(noticeId: string): Promise<string[]>;
  /** The assignee, or the holders of the job title the task is routed to. */
  taskRecipientPersonIds(taskId: string): Promise<string[]>;
  /**
   * worker_message_recipients_for_event: who to tell about a message.sent event (active members
   * who received it, never the sender) with the app link. No content, no sender.
   */
  messageRecipients(eventId: string): Promise<MessageRecipient[]>;
}

export interface MessageRecipient {
  personId: string;
  linkPath: string;
}

export interface NoticeSnapshot {
  id: string;
  title: string;
  status: string;
  urgency: Urgency;
  requiresAcknowledgment: boolean;
  publishAt: string | null;
  expiresAt: string | null;
}

/** worker_notice_for_event: the notice an outbox event is about (never its body). */
export interface NoticeReader {
  getNoticeForEvent(eventId: string): Promise<NoticeSnapshot | null>;
}

export interface Delivery {
  id: string;
  organizationId: string;
  notificationId: string;
  personId: string;
  channel: Channel;
  /** Attempts used so far, including this one. */
  attempts: number;
}

/**
 * The ONLY notification fields that may leave the building by email or push: a title, a short
 * summary and an app link. Builders take this type, never a whole notification row.
 */
export interface NotificationContent {
  title: string;
  body: string | null;
  linkPath: string | null;
  urgency: Urgency;
}

export interface PushTarget {
  id: string;
  endpoint: string;
  p256dh: string;
  authSecret: string;
}

/** Worker functions of migration 000500 plus the reads a sender needs. */
export interface DeliveryPort {
  claim(
    worker: string,
    limit: number,
    lockSeconds: number,
    channel: 'email' | 'push',
  ): Promise<Delivery[]>;
  complete(deliveryId: string, worker: string, providerMessageId?: string | null): Promise<boolean>;
  /** 'pending' = will retry, 'failed' = final, null = claim lost. */
  fail(
    deliveryId: string,
    worker: string,
    error: string,
    permanent: boolean,
  ): Promise<'pending' | 'failed' | null>;
  skip(deliveryId: string, worker: string, reason: string): Promise<boolean>;
  /** Gives a claimed delivery back unsent (the attempt is not counted). False: the claim was lost. */
  release(deliveryId: string, worker: string): Promise<boolean>;
  disablePushSubscription(subscriptionId: string): Promise<boolean>;
  /** worker_notification_for_delivery: what may be sent for this delivery. Null: gone. */
  getNotification(deliveryId: string): Promise<NotificationContent | null>;
  /** worker_email_for_delivery: the confirmed login email, or null (unconfirmed, or not an email delivery). */
  getEmailForDelivery(deliveryId: string): Promise<string | null>;
  /** worker_push_subscriptions_for_delivery: the person's active devices. */
  getPushTargets(deliveryId: string): Promise<PushTarget[]>;
}

export type SendResult =
  | { outcome: 'sent'; providerMessageId?: string }
  | { outcome: 'skipped'; reason: string }
  /** Transient: try again later (backoff, up to the attempt limit). */
  | { outcome: 'retry'; error: string }
  /** Permanent: do not retry. */
  | { outcome: 'failed'; error: string };

export interface DeliveryChannel {
  readonly channel: Channel;
  send(input: { delivery: Delivery; notification: NotificationContent }): Promise<SendResult>;
}
