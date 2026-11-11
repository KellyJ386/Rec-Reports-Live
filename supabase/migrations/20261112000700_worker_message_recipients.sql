-- Follow-up to 20261112000600: the worker can notify message recipients
-- again without reading the message tables, and the email lookup ignores
-- banned and deleted logins.
--
--   M1  public.worker_message_recipients_for_event (service_role only)
--   M2  public.worker_email_for_delivery: null for a banned or deleted auth user

-- ===========================================================================
-- M1: who to tell about a message.sent event
-- ===========================================================================
-- Takes the message.sent event being handled. Returns one row per recipient
-- to notify: recipients of that message (never the sender) who are active
-- members of the message's organization (active account, not archived, an
-- active assignment). Nothing when the event is not message.sent, is not
-- about a message, or the message is in another organization than the event.
-- Returns no content: no body, no sender, no read state. The handler uses
-- generic text ("You have a new message") with the link below, so message
-- content never reaches notifications, the outbox or the audit log.
create function public.worker_message_recipients_for_event(p_event_id uuid)
returns table (organization_id uuid, message_id uuid, person_id uuid, link_path text)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
  perform private.assert_service_caller();
  return query
  select m.organization_id, m.id, r.person_id, '/app/messages/' || m.id::text
  from public.outbox_events e
  join public.messages m on m.id = e.entity_id and m.organization_id = e.organization_id
  join public.message_recipients r on r.message_id = m.id and r.organization_id = m.organization_id
  join public.people p on p.id = r.person_id and p.organization_id = r.organization_id and p.archived_at is null
  where e.id = p_event_id
    and e.type = 'message.sent' and e.entity_table = 'messages'
    and r.person_id <> m.sender_person_id
    and private.person_is_active_member(m.organization_id, r.person_id)
  order by r.person_id;
end;
$$;
revoke all on function public.worker_message_recipients_for_event(uuid) from public, anon, authenticated;
grant execute on function public.worker_message_recipients_for_event(uuid) to service_role;

-- ===========================================================================
-- M2: same signature as 000600. Also null when the auth user is banned now
-- (banned_until in the future) or deleted (deleted_at set).
-- ===========================================================================
create or replace function public.worker_email_for_delivery(p_delivery_id uuid)
returns text
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_email text;
begin
  perform private.assert_service_caller();
  select u.email into v_email
  from public.notification_deliveries d
  join public.people p on p.id = d.person_id and p.organization_id = d.organization_id and p.archived_at is null
  join public.accounts a on a.person_id = p.id and a.organization_id = p.organization_id and a.disabled_at is null
  join auth.users u on u.id = a.user_id
  where d.id = p_delivery_id and d.channel = 'email'
    and u.email is not null and u.email_confirmed_at is not null
    and (u.banned_until is null or u.banned_until <= now())
    and u.deleted_at is null;
  return v_email;
end;
$$;
