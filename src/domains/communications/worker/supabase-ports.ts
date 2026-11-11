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
 * service-role client built in src/lib/cron/jobs.ts. The notification, audience and delivery
 * state changes all go through the service_role functions of migration 000500. The reads
 * (`getNotice`, `getNotification`, `getPersonEmail`, `getPushTargets`) are narrow SELECTs,
 * because no function returns that data to a worker; service_role has SELECT on these tables.
 */
type Client = SupabaseClient<Database>;

function urgencyOf(value: string): Urgency {
  return value === 'critical' || value === 'high' ? value : 'normal';
}

export function createNotificationPort(client: Client): NotificationPort {
  return {
    async createNotification(input) {
      const { data, error } = await client.rpc('create_notification', {
        p_event_id: input.eventId,
        p_person_id: input.personId,
        p_kind: input.kind,
        p_title: input.title,
        p_body: input.body ?? null,
        p_link_path: input.linkPath ?? null,
        p_urgency: input.urgency ?? null,
      });
      if (error) throw new PortError('create_notification', error.code);
      return data ?? null;
    },
    async noticeAudiencePersonIds(noticeId) {
      const { data, error } = await client.rpc('notice_audience_person_ids', {
        p_notice_id: noticeId,
      });
      if (error) throw new PortError('notice_audience_person_ids', error.code);
      return data ?? [];
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
    async getNotice(noticeId) {
      const { data, error } = await client
        .from('notices')
        .select('id, title, status, urgency, requires_acknowledgment, expires_at')
        .eq('id', noticeId)
        .maybeSingle();
      if (error) throw new PortError('read_notice', error.code);
      if (!data) return null;
      return {
        id: data.id,
        title: data.title,
        status: data.status,
        urgency: urgencyOf(data.urgency),
        requiresAcknowledgment: data.requires_acknowledgment,
        expiresAt: data.expires_at,
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
    async getNotification(organizationId, notificationId): Promise<NotificationContent | null> {
      const { data, error } = await client
        .from('notifications')
        .select('title, body, link_path, urgency')
        .eq('id', notificationId)
        .eq('organization_id', organizationId)
        .maybeSingle();
      if (error) throw new PortError('read_notification', error.code);
      if (!data) return null;
      return {
        title: data.title,
        body: data.body,
        linkPath: data.link_path,
        urgency: urgencyOf(data.urgency),
      };
    },
    async getPersonEmail(organizationId, personId) {
      const { data, error } = await client
        .from('people')
        .select('email')
        .eq('id', personId)
        .eq('organization_id', organizationId)
        .maybeSingle();
      if (error) throw new PortError('read_person_email', error.code);
      return data?.email ?? null;
    },
    async getPushTargets(organizationId, personId): Promise<PushTarget[]> {
      const { data, error } = await client
        .from('push_subscriptions')
        .select('id, endpoint, p256dh, auth_secret')
        .eq('person_id', personId)
        .eq('organization_id', organizationId)
        .is('disabled_at', null)
        .order('created_at', { ascending: true })
        .limit(10);
      if (error) throw new PortError('read_push_subscriptions', error.code);
      return (data ?? []).map((row) => ({
        id: row.id,
        endpoint: row.endpoint,
        p256dh: row.p256dh,
        authSecret: row.auth_secret,
      }));
    },
  };
}
