import type { SupabaseClient } from '@supabase/supabase-js';
import type { Database } from '@/lib/supabase/database.types';
import { PortError } from '@/lib/cron/error-class';
import type {
  Channel,
  Delivery,
  DeliveryPort,
  NoticeReader,
  NotificationContent,
  NotificationPort,
  PushTarget,
  Urgency,
} from './types';

/**
 * Supabase implementations of the communications worker ports. The client must be the
 * service-role client built in src/lib/cron/jobs.ts. Everything goes through the service_role
 * functions of migrations 000500 and 000600 (`worker_*` for reads); no table is read directly.
 */
type Client = SupabaseClient<Database>;

function urgencyOf(value: string): Urgency {
  return value === 'critical' || value === 'high' ? value : 'normal';
}

export function createNotificationPort(client: Client): NotificationPort {
  return {
    async createNotifications(input) {
      if (input.personIds.length === 0) return 0;
      const { data, error } = await client.rpc('create_notifications', {
        p_event_id: input.eventId,
        p_person_ids: input.personIds,
        p_kind: input.kind,
        p_title: input.title,
        p_summary: input.body ?? null,
        p_link: input.linkPath ?? null,
        p_urgency: input.urgency ?? null,
      });
      if (error) throw new PortError('create_notifications', error.code);
      return data ?? 0;
    },
    async noticeAudiencePersonIds(noticeId) {
      const { data, error } = await client.rpc('notice_audience_person_ids', {
        p_notice_id: noticeId,
      });
      if (error) throw new PortError('notice_audience_person_ids', error.code);
      return data ?? [];
    },
    async messageRecipients(eventId) {
      const { data, error } = await client.rpc('worker_message_recipients_for_event', {
        p_event_id: eventId,
      });
      if (error) throw new PortError('worker_message_recipients_for_event', error.code);
      return (data ?? []).map((r) => ({ personId: r.person_id, linkPath: r.link_path }));
    },
    async taskRecipientPersonIds(taskId) {
      const { data, error } = await client.rpc('task_recipient_person_ids', { p_task_id: taskId });
      if (error) throw new PortError('task_recipient_person_ids', error.code);
      return data ?? [];
    },
  };
}

export function createNoticeReader(client: Client): NoticeReader {
  return {
    async getNoticeForEvent(eventId) {
      const { data, error } = await client.rpc('worker_notice_for_event', { p_event_id: eventId });
      if (error) throw new PortError('worker_notice_for_event', error.code);
      const row = data?.[0];
      if (!row) return null;
      return {
        id: row.notice_id,
        title: row.title,
        status: row.status,
        urgency: urgencyOf(row.urgency),
        requiresAcknowledgment: row.requires_acknowledgment,
        publishAt: row.publish_at,
        expiresAt: row.expires_at,
      };
    },
  };
}

export function createDeliveryPort(client: Client): DeliveryPort {
  return {
    async claim(worker, limit, lockSeconds, channel) {
      const { data, error } = await client.rpc('claim_notification_deliveries', {
        p_worker: worker,
        p_limit: limit,
        p_lock_seconds: lockSeconds,
        p_channel: channel,
      });
      if (error) throw new PortError('claim_notification_deliveries', error.code);
      return (data ?? []).map((row): Delivery => ({
        id: row.id,
        organizationId: row.organization_id,
        notificationId: row.notification_id,
        personId: row.person_id,
        channel: row.channel as Channel,
        attempts: row.attempts,
      }));
    },
    async complete(deliveryId, worker, providerMessageId) {
      const { data, error } = await client.rpc('complete_notification_delivery', {
        p_id: deliveryId,
        p_worker: worker,
        p_provider_message_id: providerMessageId ?? null,
      });
      if (error) throw new PortError('complete_notification_delivery', error.code);
      return data === true;
    },
    async fail(deliveryId, worker, message, permanent) {
      const { data, error } = await client.rpc('fail_notification_delivery', {
        p_id: deliveryId,
        p_worker: worker,
        p_error: message,
        p_permanent: permanent,
      });
      if (error) throw new PortError('fail_notification_delivery', error.code);
      return data === 'pending' || data === 'failed' ? data : null;
    },
    async skip(deliveryId, worker, reason) {
      const { data, error } = await client.rpc('skip_notification_delivery', {
        p_id: deliveryId,
        p_worker: worker,
        p_reason: reason,
      });
      if (error) throw new PortError('skip_notification_delivery', error.code);
      return data === true;
    },
    async disablePushSubscription(subscriptionId) {
      const { data, error } = await client.rpc('disable_push_subscription', {
        p_id: subscriptionId,
      });
      if (error) throw new PortError('disable_push_subscription', error.code);
      return data === true;
    },
    async release(deliveryId, worker) {
      const { data, error } = await client.rpc('release_notification_delivery', {
        p_id: deliveryId,
        p_worker: worker,
      });
      if (error) throw new PortError('release_notification_delivery', error.code);
      return data === true;
    },
    async getNotification(deliveryId): Promise<NotificationContent | null> {
      const { data, error } = await client.rpc('worker_notification_for_delivery', {
        p_delivery_id: deliveryId,
      });
      if (error) throw new PortError('worker_notification_for_delivery', error.code);
      const row = data?.[0];
      if (!row) return null;
      return {
        title: row.title,
        body: row.body,
        linkPath: row.link_path,
        urgency: urgencyOf(row.urgency),
      };
    },
    async getEmailForDelivery(deliveryId) {
      const { data, error } = await client.rpc('worker_email_for_delivery', {
        p_delivery_id: deliveryId,
      });
      if (error) throw new PortError('worker_email_for_delivery', error.code);
      return data ?? null;
    },
    async getPushTargets(deliveryId): Promise<PushTarget[]> {
      const { data, error } = await client.rpc('worker_push_subscriptions_for_delivery', {
        p_delivery_id: deliveryId,
      });
      if (error) throw new PortError('worker_push_subscriptions_for_delivery', error.code);
      return (data ?? []).map((row) => ({
        id: row.subscription_id,
        endpoint: row.endpoint,
        p256dh: row.p256dh,
        authSecret: row.auth_secret,
      }));
    },
  };
}
