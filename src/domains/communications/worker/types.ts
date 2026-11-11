// Ports and shapes of the communications worker (notification fan-out and delivery).
// Production implementations: ./supabase-ports.ts. Test implementation: src/lib/cron/testing.

export type Urgency = 'normal' | 'high' | 'critical';
export type Channel = 'in_app' | 'email' | 'push';

export interface CreateNotificationInput {
  eventId: string;
  personId: string;
  kind: string;
  title: string;
  body?: string | null;
  linkPath?: string | null;
  urgency?: Urgency;
}

/** create_notification, notice_audience_person_ids and task_recipient_person_ids (migration 000500). */
export interface NotificationPort {
  /**
   * One notification per (event, person, kind), with its delivery rows. Returns the id (the
   * existing one on a re-run), or null when the person is not an active member (nothing made).
   */
  createNotification(input: CreateNotificationInput): Promise<string | null>;
  /** Active members in a notice's audience. */
  noticeAudiencePersonIds(noticeId: string): Promise<string[]>;
  /** The assignee, or the holders of the job title the task is routed to. */
  taskRecipientPersonIds(taskId: string): Promise<string[]>;
}

export interface NoticeSnapshot {
  id: string;
  title: string;
  status: string;
  urgency: Urgency;
  requiresAcknowledgment: boolean;
  expiresAt: string | null;
}

/** No function returns a notice to a worker, so the adapter selects these columns (never the body). */
export interface NoticeReader {
  getNotice(noticeId: string): Promise<NoticeSnapshot | null>;
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
  disablePushSubscription(subscriptionId: string): Promise<boolean>;
  getNotification(
    organizationId: string,
    notificationId: string,
  ): Promise<NotificationContent | null>;
  getPersonEmail(organizationId: string, personId: string): Promise<string | null>;
  /** Active (not disabled) devices of the person. */
  getPushTargets(organizationId: string, personId: string): Promise<PushTarget[]>;
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
