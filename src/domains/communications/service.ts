// Communications domain services: notices, messages and notifications. Reads go through the
// caller's session client, so RLS decides what is visible (messages and notifications are
// private to the people they belong to, even from admins). Changes use the database RPCs
// (publish_notice, acknowledge_notice, send_message, mark_message_read, mark_*_read,
// save_push_subscription, ...); notices are written as drafts with their own policies. Message
// and notification text is never logged.
import { createClient } from '@/lib/supabase/server';
import type { Tables } from '@/lib/supabase/database.types';
import { fail, failure, ok, requireChanged, type Result } from '@/lib/db-errors';
import { fetchAllRows, fetchClampedPage, type Paged } from '@/lib/paging';
import type { ChannelSettings } from './logic';
import { channelSettings } from './logic';
import type { MessageSend, NoticeCreate, NoticeUpdate, PushSubscriptionSave } from './schemas';

const NOTICE_LIST_COLUMNS =
  'id, location_id, title, urgency, requires_acknowledgment, status, publish_at, expires_at, published_at, archived_at, created_at';
const NOTICE_COLUMNS = `${NOTICE_LIST_COLUMNS}, body, author_person_id, organization_id`;

export type NoticeSummary = Pick<
  Tables<'notices'>,
  | 'id'
  | 'location_id'
  | 'title'
  | 'urgency'
  | 'requires_acknowledgment'
  | 'status'
  | 'publish_at'
  | 'expires_at'
  | 'published_at'
  | 'archived_at'
  | 'created_at'
>;
export type Notice = NoticeSummary &
  Pick<Tables<'notices'>, 'body' | 'author_person_id' | 'organization_id'>;
export type NoticeAudienceRow = Pick<
  Tables<'notice_audiences'>,
  'id' | 'location_id' | 'job_title_id'
>;
/** One person of a notice's audience; `acknowledged_at` is null until they confirm. */
export type AcknowledgmentRow = { person_id: string; acknowledged_at: string | null };

export type InboxRow = {
  message_id: string;
  read_at: string | null;
  received_at: string;
  sender_person_id: string;
  body: string;
};
export type SentRow = {
  message_id: string;
  created_at: string;
  body: string;
  recipients: { person_id: string; read_at: string | null }[];
};
export type MessageView = {
  id: string;
  sender_person_id: string;
  body: string;
  created_at: string;
  recipients: { person_id: string; read_at: string | null }[];
};

export type NotificationRow = Pick<
  Tables<'notifications'>,
  'id' | 'kind' | 'title' | 'body' | 'link_path' | 'urgency' | 'read_at' | 'created_at'
>;

// ---- notices: reading as a member of the audience ----

/**
 * A live notice addressed to the caller, as `my_notices` returns it: published, past its publish
 * time, not expired, and in the caller's audience, with the caller's own acknowledgment time.
 * `id` is the notice id (named like the other notice rows so the same helpers work on it).
 */
export type MyNotice = {
  id: string;
  location_id: string | null;
  title: string;
  urgency: string;
  requires_acknowledgment: boolean;
  publish_at: string | null;
  expires_at: string | null;
  acknowledged_at: string | null;
};

/** The most notices `my_notices` returns in one call. */
const MY_NOTICES_LIMIT = 200;

/**
 * The caller's live notices (the database decides who a notice is for, so a manager does not see
 * other people's notices here). The body is not needed for a list and is dropped.
 */
export async function listMyNotices(orgId: string): Promise<Result<MyNotice[]>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('my_notices', {
    p_organization_id: orgId,
    p_limit: MY_NOTICES_LIMIT,
  });
  if (error) return failure(error);
  return ok(
    (data ?? []).map((n) => ({
      id: n.notice_id,
      location_id: n.location_id,
      title: n.title,
      urgency: n.urgency,
      requires_acknowledgment: n.requires_acknowledgment,
      publish_at: n.publish_at,
      expires_at: n.expires_at,
      acknowledged_at: n.acknowledged_at,
    })),
  );
}

/** The ids of the notices in a list that the caller has acknowledged. */
export function acknowledgedIds(notices: readonly MyNotice[]): Set<string> {
  return new Set(notices.filter((n) => n.acknowledged_at !== null).map((n) => n.id));
}

export async function getNotice(orgId: string, id: string): Promise<Result<Notice | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('notices')
    .select(NOTICE_COLUMNS)
    .eq('organization_id', orgId)
    .eq('id', id)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data);
}

export async function getMyAcknowledgment(
  orgId: string,
  noticeId: string,
  personId: string,
): Promise<Result<string | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('acknowledgments')
    .select('acknowledged_at')
    .eq('organization_id', orgId)
    .eq('notice_id', noticeId)
    .eq('person_id', personId)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data?.acknowledged_at ?? null);
}

/** "I have read this". Idempotent in the database: a second tap returns the first time. */
export async function acknowledgeNotice(noticeId: string): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('acknowledge_notice', { p_notice_id: noticeId });
  if (error) return failure(error);
  if (!data) return fail('That could not be saved.');
  return ok(data);
}

// ---- notices: managing ----

export async function listManagedNotices(
  orgId: string,
  status: 'draft' | 'published' | 'archived',
  page: number,
): Promise<Result<Paged<NoticeSummary>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('notices')
      .select(NOTICE_LIST_COLUMNS, { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('status', status)
      .order('created_at', { ascending: false })
      .order('id')
      .range(from, to),
  );
}

export async function listNoticeAudiences(
  orgId: string,
  noticeId: string,
): Promise<Result<NoticeAudienceRow[]>> {
  const supabase = await createClient();
  return fetchAllRows<NoticeAudienceRow>((from, to) =>
    supabase
      .from('notice_audiences')
      .select('id, location_id, job_title_id')
      .eq('organization_id', orgId)
      .eq('notice_id', noticeId)
      .order('created_at')
      .order('id')
      .range(from, to),
  );
}

/**
 * Who the notice is for and who has confirmed (`notice_acknowledgment_status`): one row per
 * person in the audience or who confirmed, `acknowledged_at` null for those who have not. Only a
 * communications admin over the notice's home scope may ask; anyone else is refused (42501), and
 * the database limits the rows to people the caller can see.
 */
export async function listAcknowledgments(noticeId: string): Promise<Result<AcknowledgmentRow[]>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('notice_acknowledgment_status', {
    p_notice_id: noticeId,
  });
  if (error) return failure(error);
  return ok(data ?? []);
}

/**
 * Writes the draft, then its audience rows. If the audience cannot be saved the draft is
 * removed again (a draft the author may delete), so no half-made notice is left behind.
 */
export async function createNoticeDraft(input: NoticeCreate): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { audiences, ...fields } = input;
  const { data, error } = await supabase
    .from('notices')
    .insert({
      organization_id: fields.organization_id,
      location_id: fields.location_id,
      title: fields.title,
      body: fields.body,
      urgency: fields.urgency,
      requires_acknowledgment: fields.requires_acknowledgment,
      publish_at: fields.publish_at ?? null,
      expires_at: fields.expires_at ?? null,
    })
    .select('id')
    .single();
  if (error) {
    return failure(error, {
      unique: 'That notice already exists.',
      foreignKey: 'That location is not available.',
    });
  }
  const noticeId = data.id;
  if (audiences.length > 0) {
    const { error: audienceError } = await supabase.from('notice_audiences').insert(
      audiences.map((a) => ({
        organization_id: fields.organization_id,
        notice_id: noticeId,
        location_id: a.location_id,
        job_title_id: a.job_title_id,
      })),
    );
    if (audienceError) {
      await supabase.from('notices').delete().eq('id', noticeId).eq('status', 'draft');
      return failure(audienceError, { foreignKey: 'That location or job title is not available.' });
    }
  }
  return ok({ id: noticeId });
}

export async function updateNoticeDraft(
  orgId: string,
  id: string,
  patch: NoticeUpdate,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('notices')
    .update(patch)
    .eq('organization_id', orgId)
    .eq('id', id)
    .eq('status', 'draft')
    .select('id');
  if (error) return failure(error);
  return requireChanged(data, 'Nothing was saved. Only a draft can be changed.');
}

export async function publishNotice(
  noticeId: string,
  publishAt: string | null,
): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('publish_notice', {
    p_notice_id: noticeId,
    p_publish_at: publishAt,
  });
  return error ? failure(error) : ok(null);
}

export async function archiveNotice(noticeId: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('archive_notice', { p_notice_id: noticeId });
  return error ? failure(error) : ok(null);
}

// ---- messages ----

/** One page of the caller's received messages, newest first. */
export async function listInbox(
  orgId: string,
  personId: string,
  page: number,
): Promise<Result<Paged<InboxRow>>> {
  const supabase = await createClient();
  const res = await fetchClampedPage(page, (from, to) =>
    supabase
      .from('message_recipients')
      .select('message_id, read_at, created_at, messages(sender_person_id, body)', {
        count: 'exact',
      })
      .eq('organization_id', orgId)
      .eq('person_id', personId)
      .order('created_at', { ascending: false })
      .order('id')
      .range(from, to),
  );
  if (!res.ok) return res;
  return ok({
    ...res.data,
    rows: res.data.rows.flatMap((r) =>
      r.messages
        ? [
            {
              message_id: r.message_id,
              read_at: r.read_at,
              received_at: r.created_at,
              sender_person_id: r.messages.sender_person_id,
              body: r.messages.body,
            },
          ]
        : [],
    ),
  });
}

/** One page of the messages the caller sent, with who got each and whether they read it. */
export async function listSent(
  orgId: string,
  personId: string,
  page: number,
): Promise<Result<Paged<SentRow>>> {
  const supabase = await createClient();
  const res = await fetchClampedPage(page, (from, to) =>
    supabase
      .from('messages')
      .select('id, created_at, body, message_recipients(person_id, read_at)', { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('sender_person_id', personId)
      .order('created_at', { ascending: false })
      .order('id')
      .range(from, to),
  );
  if (!res.ok) return res;
  return ok({
    ...res.data,
    rows: res.data.rows.map((m) => ({
      message_id: m.id,
      created_at: m.created_at,
      body: m.body,
      recipients: m.message_recipients,
    })),
  });
}

/** A message the caller sent or received. Null for anyone else, admins included. */
export async function getMessage(orgId: string, id: string): Promise<Result<MessageView | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('messages')
    .select('id, sender_person_id, body, created_at, message_recipients(person_id, read_at)')
    .eq('organization_id', orgId)
    .eq('id', id)
    .maybeSingle();
  if (error) return failure(error);
  if (!data) return ok(null);
  return ok({
    id: data.id,
    sender_person_id: data.sender_person_id,
    body: data.body,
    created_at: data.created_at,
    recipients: data.message_recipients,
  });
}

export async function sendMessage(input: MessageSend): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('send_message', {
    p_organization_id: input.organization_id,
    p_recipient_person_ids: [...new Set(input.recipient_person_ids)],
    p_body: input.body,
  });
  if (error) return failure(error);
  if (!data) return fail('The message was not sent.');
  return ok({ id: data });
}

export async function markMessageRead(messageId: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('mark_message_read', { p_message_id: messageId });
  return error ? failure(error) : ok(null);
}

export async function countUnreadMessages(
  orgId: string,
  personId: string,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { count, error } = await supabase
    .from('message_recipients')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId)
    .eq('person_id', personId)
    .is('read_at', null);
  if (error) return failure(error);
  return ok(count ?? 0);
}

// ---- notifications ----

export async function listNotifications(
  orgId: string,
  personId: string,
  page: number,
): Promise<Result<Paged<NotificationRow>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('notifications')
      .select('id, kind, title, body, link_path, urgency, read_at, created_at', { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('person_id', personId)
      .order('created_at', { ascending: false })
      .order('id')
      .range(from, to),
  );
}

export async function countUnreadNotifications(
  orgId: string,
  personId: string,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { count, error } = await supabase
    .from('notifications')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId)
    .eq('person_id', personId)
    .is('read_at', null);
  if (error) return failure(error);
  return ok(count ?? 0);
}

/** Ids that are not the caller's are ignored by the database. */
export async function markNotificationsRead(ids: string[]): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('mark_notifications_read', {
    p_notification_ids: ids,
  });
  if (error) return failure(error);
  return ok(data ?? 0);
}

export async function markAllNotificationsRead(orgId: string): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('mark_all_notifications_read', {
    p_organization_id: orgId,
  });
  if (error) return failure(error);
  return ok(data ?? 0);
}

// ---- notification settings and devices ----

export async function getChannelSettings(
  orgId: string,
  personId: string,
): Promise<Result<ChannelSettings>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('notification_preferences')
    .select('channel, enabled')
    .eq('organization_id', orgId)
    .eq('person_id', personId);
  if (error) return failure(error);
  return ok(channelSettings(data ?? []));
}

/**
 * Saves one channel on or off for the caller. A person may insert and update only their own
 * rows (policy), and update only `enabled` (grant), so this reads the row first and then
 * updates it or inserts it.
 */
export async function setChannelEnabled(
  orgId: string,
  personId: string,
  channel: 'email' | 'push',
  enabled: boolean,
): Promise<Result<null>> {
  const supabase = await createClient();
  const existing = await supabase
    .from('notification_preferences')
    .select('id')
    .eq('organization_id', orgId)
    .eq('person_id', personId)
    .eq('channel', channel)
    .maybeSingle();
  if (existing.error) return failure(existing.error);
  if (existing.data) {
    const { data, error } = await supabase
      .from('notification_preferences')
      .update({ enabled })
      .eq('id', existing.data.id)
      .select('id');
    if (error) return failure(error);
    const changed = requireChanged(data);
    return changed.ok ? ok(null) : changed;
  }
  const { error } = await supabase
    .from('notification_preferences')
    .insert({ organization_id: orgId, person_id: personId, channel, enabled });
  return error ? failure(error) : ok(null);
}

/** How many devices of the caller can receive push. Endpoints and keys are never readable. */
export async function countPushDevices(orgId: string, personId: string): Promise<Result<number>> {
  const supabase = await createClient();
  const { count, error } = await supabase
    .from('push_subscriptions')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId)
    .eq('person_id', personId)
    .is('disabled_at', null);
  if (error) return failure(error);
  return ok(count ?? 0);
}

export async function savePushSubscription(input: PushSubscriptionSave): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('save_push_subscription', {
    p_organization_id: input.organization_id,
    p_endpoint: input.endpoint,
    p_p256dh: input.p256dh,
    p_auth_secret: input.auth_secret,
    p_user_agent: input.user_agent ?? null,
  });
  return error ? failure(error) : ok(null);
}

export async function deletePushSubscription(
  orgId: string,
  endpoint: string,
): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('delete_push_subscription', {
    p_organization_id: orgId,
    p_endpoint: endpoint,
  });
  return error ? failure(error) : ok(null);
}
