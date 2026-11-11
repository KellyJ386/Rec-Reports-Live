-- Phase 2: notifications.
--
--   notifications             one row per person per thing to tell them,
--                             created only by the worker (create_notification),
--                             idempotent on (source_event_id, person_id, kind)
--   notification_deliveries   one row per notification per channel
--                             (in_app / email / push), claimed by the sender
--                             worker with SKIP LOCKED
--   push_subscriptions        a person's own browser push endpoints
--   notification_preferences  per person per channel on/off; critical
--                             notifications ignore it
--
-- A person reads and marks read only their own notifications. Nobody else
-- (no admin, no platform admin) reads them, and push endpoints/keys are not
-- readable through the API by anyone, the owner included (only the worker,
-- with the service key, reads them).

create function private.delivery_max_attempts()
returns integer language sql immutable set search_path = '' as $$ select 5 $$;
revoke all on function private.delivery_max_attempts() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- notifications
-- ---------------------------------------------------------------------------
create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  person_id uuid not null,
  kind text not null check (kind ~ '^[a-z][a-z0-9_.]{0,62}$'),
  title text not null check (char_length(btrim(title)) between 1 and 200),
  body text check (char_length(body) <= 500),          -- a short summary, never a copy of a message
  link_path text check (char_length(link_path) <= 500 and link_path ~ '^/[A-Za-z0-9/_.~%?=&-]*$' and link_path !~ '^//'),
  source_table text check (source_table ~ '^[a-z][a-z0-9_]{0,62}$'),
  source_id uuid,
  -- Idempotency key, not a reference (outbox rows are purged after retention).
  source_event_id uuid not null,
  urgency text not null default 'normal' check (urgency in ('normal', 'high', 'critical')),
  read_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  unique (source_event_id, person_id, kind),
  foreign key (person_id, organization_id) references public.people (id, organization_id) on delete cascade
);

create index notifications_person_idx on public.notifications (organization_id, person_id, created_at desc);
create index notifications_person_unread_idx on public.notifications (person_id, created_at desc) where read_at is null;

create trigger notifications_timestamps before insert or update on public.notifications
  for each row execute function private.tg_set_timestamps();
create trigger notifications_immutable before update on public.notifications
  for each row execute function private.tg_immutable_columns(
    'id', 'organization_id', 'person_id', 'kind', 'title', 'body', 'link_path',
    'source_table', 'source_id', 'source_event_id', 'urgency');

-- ---------------------------------------------------------------------------
-- notification_deliveries
-- ---------------------------------------------------------------------------
create table public.notification_deliveries (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  notification_id uuid not null,
  person_id uuid not null,
  channel text not null check (channel in ('in_app', 'email', 'push')),
  status text not null default 'pending' check (status in ('pending', 'sent', 'failed', 'skipped')),
  attempts integer not null default 0 check (attempts >= 0),
  next_attempt_at timestamptz not null default now(),
  locked_at timestamptz,
  locked_by text check (char_length(locked_by) <= 100),
  lock_expires_at timestamptz,
  provider_message_id text check (char_length(provider_message_id) <= 200),
  last_error text check (char_length(last_error) <= 2000),
  sent_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (notification_id, channel),
  check ((status = 'sent') = (sent_at is not null)),
  check (status = 'pending' or locked_by is null),
  check ((locked_by is null) = (lock_expires_at is null)),
  foreign key (notification_id, organization_id) references public.notifications (id, organization_id) on delete cascade,
  foreign key (person_id, organization_id) references public.people (id, organization_id) on delete cascade
);

create index notification_deliveries_notification_idx on public.notification_deliveries (organization_id, notification_id);
create index notification_deliveries_person_idx on public.notification_deliveries (person_id, organization_id);
create index notification_deliveries_due_idx on public.notification_deliveries (next_attempt_at) where status = 'pending';

create trigger notification_deliveries_timestamps before insert or update on public.notification_deliveries
  for each row execute function private.tg_set_timestamps();
create trigger notification_deliveries_immutable before update on public.notification_deliveries
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'notification_id', 'person_id', 'channel');

-- ---------------------------------------------------------------------------
-- push_subscriptions (Web Push)
-- ---------------------------------------------------------------------------
create table public.push_subscriptions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  person_id uuid not null,
  endpoint text not null check (char_length(endpoint) <= 2000 and endpoint ~ '^https://[^\s]+$'),
  p256dh text not null check (p256dh ~ '^[A-Za-z0-9_-]{20,200}={0,2}$'),
  auth_secret text not null check (auth_secret ~ '^[A-Za-z0-9_-]{8,100}={0,2}$'),
  user_agent text check (char_length(user_agent) <= 300),
  last_used_at timestamptz,
  disabled_at timestamptz,            -- set by the worker when the push service says it is gone
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (person_id, endpoint),
  foreign key (person_id, organization_id) references public.people (id, organization_id) on delete cascade
);

create index push_subscriptions_person_idx on public.push_subscriptions (organization_id, person_id);

create trigger push_subscriptions_timestamps before insert or update on public.push_subscriptions
  for each row execute function private.tg_set_timestamps();
create trigger push_subscriptions_immutable before update on public.push_subscriptions
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'person_id', 'endpoint');

-- ---------------------------------------------------------------------------
-- notification_preferences
-- ---------------------------------------------------------------------------
create table public.notification_preferences (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  person_id uuid not null,
  channel text not null check (channel in ('email', 'push')),   -- in-app is always on
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (person_id, channel),
  foreign key (person_id, organization_id) references public.people (id, organization_id) on delete cascade
);

create index notification_preferences_person_idx on public.notification_preferences (organization_id, person_id);

create trigger notification_preferences_timestamps before insert or update on public.notification_preferences
  for each row execute function private.tg_set_timestamps();
create trigger notification_preferences_immutable before update on public.notification_preferences
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'person_id', 'channel');

-- Audit. Titles/bodies of notifications, errors and push secrets are redacted,
-- so audit readers learn that something was sent, never what it said or where.
do $$
begin
  perform private.enable_audit('public.notifications', 'id', array['title', 'body', 'link_path']);
  perform private.enable_audit('public.notification_deliveries', 'id', array['last_error', 'provider_message_id']);
  perform private.enable_audit('public.push_subscriptions', 'id', array['endpoint', 'p256dh', 'auth_secret', 'user_agent']);
  perform private.enable_audit('public.notification_preferences');
end;
$$;

-- ---------------------------------------------------------------------------
-- Worker functions (service_role only)
-- ---------------------------------------------------------------------------

-- Is this person an active member of the organization (active account, not
-- archived, at least one assignment on a non-archived role)?
create function private.person_is_active_member(p_organization_id uuid, p_person_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.people p
    join public.accounts a on a.person_id = p.id and a.organization_id = p.organization_id and a.disabled_at is null
    join public.role_assignments ra on ra.person_id = p.id and ra.organization_id = p.organization_id
    join public.roles r on r.id = ra.role_id and r.archived_at is null
    left join public.locations l on l.id = ra.location_id and l.organization_id = ra.organization_id
    where p.id = p_person_id and p.organization_id = p_organization_id and p.archived_at is null
      and (ra.location_id is null or l.archived_at is null))
$$;
revoke all on function private.person_is_active_member(uuid, uuid) from public, anon, authenticated;

-- Create the notification for (event, person, kind) once, plus its delivery
-- rows: in_app 'sent' at once; email and push 'pending', or 'skipped' when the
-- person turned that channel off (never for critical) or, for push, has no
-- active device. Returns the notification id (the existing one on a retry),
-- or null when the person is not an active member of the event's organization
-- (nothing is created).
create function public.create_notification(
  p_event_id uuid,
  p_person_id uuid,
  p_kind text,
  p_title text,
  p_body text default null,
  p_link_path text default null,
  p_urgency text default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_e public.outbox_events%rowtype;
  v_urgency text;
  v_id uuid;
begin
  perform private.assert_service_caller();
  select * into v_e from public.outbox_events e where e.id = p_event_id;
  if not found then
    raise exception 'no such event' using errcode = 'invalid_parameter_value';
  end if;
  if not private.person_is_active_member(v_e.organization_id, p_person_id) then
    return null;
  end if;
  v_urgency := coalesce(p_urgency,
                        case when v_e.payload ->> 'urgency' in ('normal', 'high', 'critical') then v_e.payload ->> 'urgency' end,
                        'normal');

  insert into public.notifications (
    organization_id, person_id, kind, title, body, link_path, source_table, source_id, source_event_id, urgency)
  values (
    v_e.organization_id, p_person_id, p_kind, btrim(p_title), nullif(btrim(p_body), ''), p_link_path,
    v_e.entity_table, v_e.entity_id, v_e.id, v_urgency)
  on conflict (source_event_id, person_id, kind) do nothing
  returning id into v_id;

  if v_id is null then
    select n.id into v_id from public.notifications n
    where n.source_event_id = v_e.id and n.person_id = p_person_id and n.kind = p_kind;
    return v_id;
  end if;

  insert into public.notification_deliveries (organization_id, notification_id, person_id, channel, status, sent_at, last_error)
  select v_e.organization_id, v_id, p_person_id, c.channel,
         case when c.channel = 'in_app' then 'sent'
              when v_urgency <> 'critical' and exists (
                     select 1 from public.notification_preferences np
                     where np.person_id = p_person_id and np.channel = c.channel and not np.enabled) then 'skipped'
              when c.channel = 'push' and not exists (
                     select 1 from public.push_subscriptions ps
                     where ps.person_id = p_person_id and ps.disabled_at is null) then 'skipped'
              else 'pending' end,
         case when c.channel = 'in_app' then now() end,
         case when c.channel = 'in_app' then null
              when v_urgency <> 'critical' and exists (
                     select 1 from public.notification_preferences np
                     where np.person_id = p_person_id and np.channel = c.channel and not np.enabled) then 'turned off by the person'
              when c.channel = 'push' and not exists (
                     select 1 from public.push_subscriptions ps
                     where ps.person_id = p_person_id and ps.disabled_at is null) then 'no push device'
         end
  from (values ('in_app'), ('email'), ('push')) c (channel)
  on conflict (notification_id, channel) do nothing;

  return v_id;
end;
$$;

-- Fan-out: active members in a notice's audience (same rule as the read policy).
create function public.notice_audience_person_ids(p_notice_id uuid)
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.id
  from public.notices n
  join public.people p on p.organization_id = n.organization_id and p.archived_at is null
  where n.id = p_notice_id
    and (select auth.uid()) is null
    and private.person_is_active_member(n.organization_id, p.id)
    and private.person_in_notice_audience(n.id, p.id)
  order by p.id
$$;

-- Fan-out: who should hear about a task. The assigned person; else, for a task
-- routed to a job title, active members holding that title at the location
-- with tasks >= view there. Empty for an unassigned task.
create function public.task_recipient_person_ids(p_task_id uuid)
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select distinct p.id
  from public.tasks t
  join public.people p on p.organization_id = t.organization_id and p.archived_at is null
  where t.id = p_task_id
    and (select auth.uid()) is null
    and coalesce(private.person_effective_level(t.organization_id, p.id, t.location_id, 'tasks') >= 'view', false)
    and (p.id = t.assigned_person_id
         or (t.assigned_person_id is null and t.assigned_job_title_id is not null and exists (
               select 1 from public.person_job_titles pjt
               where pjt.person_id = p.id and pjt.job_title_id = t.assigned_job_title_id
                 and (pjt.location_id is null or pjt.location_id = t.location_id))))
$$;

-- Claim due deliveries (pending, next_attempt_at <= now, not locked or lock
-- expired), optionally for one channel. Each claim counts as an attempt; an
-- expired lock on the last attempt fails the delivery instead.
create function public.claim_notification_deliveries(
  p_worker text, p_limit integer, p_lock_seconds integer, p_channel text default null)
returns setof public.notification_deliveries
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform private.assert_service_caller();
  if p_worker is null or char_length(btrim(p_worker)) not between 1 and 100 then
    raise exception 'invalid worker' using errcode = 'invalid_parameter_value';
  end if;
  if p_limit is null or p_limit not between 1 and 500 then
    raise exception 'invalid limit' using errcode = 'invalid_parameter_value';
  end if;
  if p_lock_seconds is null or p_lock_seconds not between 5 and 3600 then
    raise exception 'invalid lock time' using errcode = 'invalid_parameter_value';
  end if;
  if p_channel is not null and p_channel not in ('email', 'push') then
    raise exception 'invalid channel' using errcode = 'invalid_parameter_value';
  end if;

  update public.notification_deliveries d
  set status = 'failed', locked_at = null, locked_by = null, lock_expires_at = null,
      last_error = left(coalesce(d.last_error || ' | ', '') || 'lock expired on the last attempt', 2000)
  where d.id in (
    select x.id from public.notification_deliveries x
    where x.status = 'pending' and x.lock_expires_at < now()
      and x.attempts >= private.delivery_max_attempts()
    for update skip locked);

  return query
  update public.notification_deliveries d
  set attempts = d.attempts + 1, locked_at = now(), locked_by = btrim(p_worker),
      lock_expires_at = now() + make_interval(secs => p_lock_seconds)
  where d.id in (
    select x.id from public.notification_deliveries x
    where x.status = 'pending' and x.channel <> 'in_app'
      and x.next_attempt_at <= now()
      and (x.lock_expires_at is null or x.lock_expires_at < now())
      and x.attempts < private.delivery_max_attempts()
      and (p_channel is null or x.channel = p_channel)
    order by x.next_attempt_at, x.created_at
    limit p_limit
    for update skip locked)
  returning d.*;
end;
$$;

create function public.complete_notification_delivery(p_id uuid, p_worker text, p_provider_message_id text default null)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform private.assert_service_caller();
  update public.notification_deliveries d
  set status = 'sent', sent_at = now(), provider_message_id = left(p_provider_message_id, 200),
      locked_at = null, locked_by = null, lock_expires_at = null
  where d.id = p_id and d.status = 'pending' and d.locked_by = btrim(p_worker);
  return found;
end;
$$;

-- Failure: retry with backoff, or 'failed' after the last attempt or when
-- p_permanent (e.g. the address is invalid). Returns the new status, or null
-- when the caller does not hold the claim.
create function public.fail_notification_delivery(
  p_id uuid, p_worker text, p_error text, p_permanent boolean default false)
returns text
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_status text;
begin
  perform private.assert_service_caller();
  update public.notification_deliveries d
  set status = case when coalesce(p_permanent, false) or d.attempts >= private.delivery_max_attempts()
                    then 'failed' else 'pending' end,
      next_attempt_at = now() + private.outbox_backoff(d.attempts),
      last_error = left(coalesce(nullif(btrim(p_error), ''), 'unknown error'), 2000),
      locked_at = null, locked_by = null, lock_expires_at = null
  where d.id = p_id and d.status = 'pending' and d.locked_by = btrim(p_worker)
  returning d.status into v_status;
  return v_status;
end;
$$;

-- Nothing to send (no address, device gone, ...). Final.
create function public.skip_notification_delivery(p_id uuid, p_worker text, p_reason text)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform private.assert_service_caller();
  update public.notification_deliveries d
  set status = 'skipped', last_error = left(coalesce(nullif(btrim(p_reason), ''), 'skipped'), 2000),
      locked_at = null, locked_by = null, lock_expires_at = null
  where d.id = p_id and d.status = 'pending' and d.locked_by = btrim(p_worker);
  return found;
end;
$$;

-- The push service said this endpoint is gone (404/410).
create function public.disable_push_subscription(p_id uuid)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform private.assert_service_caller();
  update public.push_subscriptions s set disabled_at = now() where s.id = p_id and s.disabled_at is null;
  return found;
end;
$$;

-- ---------------------------------------------------------------------------
-- Person RPCs (authenticated): only ever the caller's own rows
-- ---------------------------------------------------------------------------

-- Mark some of my notifications read. Ids that are not mine are ignored.
-- Returns how many changed.
create function public.mark_notifications_read(p_notification_ids uuid[])
returns integer
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_n integer;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if cardinality(p_notification_ids) > 500 then
    raise exception 'too many at once' using errcode = 'invalid_parameter_value';
  end if;
  update public.notifications n set read_at = now()
  where n.id = any (coalesce(p_notification_ids, '{}'))
    and n.person_id in (select private.my_person_ids())
    and n.read_at is null;
  get diagnostics v_n = row_count;
  return v_n;
end;
$$;

create function public.mark_all_notifications_read(p_organization_id uuid)
returns integer
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_n integer;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  update public.notifications n set read_at = now()
  where n.organization_id = p_organization_id
    and n.person_id in (select private.my_person_ids())
    and n.read_at is null;
  get diagnostics v_n = row_count;
  return v_n;
end;
$$;

-- Register (or refresh) this browser's push endpoint for the caller in an
-- organization where they are a member. Returns the subscription id.
create function public.save_push_subscription(
  p_organization_id uuid, p_endpoint text, p_p256dh text, p_auth_secret text, p_user_agent text default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  v_me := public.current_person_id(p_organization_id);
  if v_me is null or v_me not in (select private.my_person_ids()) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  insert into public.push_subscriptions as s (organization_id, person_id, endpoint, p256dh, auth_secret, user_agent)
  values (p_organization_id, v_me, p_endpoint, p_p256dh, p_auth_secret, left(p_user_agent, 300))
  on conflict (person_id, endpoint) do update
    set p256dh = excluded.p256dh, auth_secret = excluded.auth_secret,
        user_agent = excluded.user_agent, disabled_at = null
  returning s.id into v_id;
  return v_id;
end;
$$;

create function public.delete_push_subscription(p_organization_id uuid, p_endpoint text)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  delete from public.push_subscriptions s
  where s.organization_id = p_organization_id
    and s.person_id in (select private.my_person_ids())
    and s.endpoint = p_endpoint;
  return found;
end;
$$;

revoke all on function
  public.create_notification(uuid, uuid, text, text, text, text, text),
  public.notice_audience_person_ids(uuid),
  public.task_recipient_person_ids(uuid),
  public.claim_notification_deliveries(text, integer, integer, text),
  public.complete_notification_delivery(uuid, text, text),
  public.fail_notification_delivery(uuid, text, text, boolean),
  public.skip_notification_delivery(uuid, text, text),
  public.disable_push_subscription(uuid),
  public.mark_notifications_read(uuid[]),
  public.mark_all_notifications_read(uuid),
  public.save_push_subscription(uuid, text, text, text, text),
  public.delete_push_subscription(uuid, text)
from public, anon, authenticated;
grant execute on function
  public.create_notification(uuid, uuid, text, text, text, text, text),
  public.notice_audience_person_ids(uuid),
  public.task_recipient_person_ids(uuid),
  public.claim_notification_deliveries(text, integer, integer, text),
  public.complete_notification_delivery(uuid, text, text),
  public.fail_notification_delivery(uuid, text, text, boolean),
  public.skip_notification_delivery(uuid, text, text),
  public.disable_push_subscription(uuid)
to service_role;
grant execute on function
  public.mark_notifications_read(uuid[]),
  public.mark_all_notifications_read(uuid),
  public.save_push_subscription(uuid, text, text, text, text),
  public.delete_push_subscription(uuid, text)
to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- RLS, policies, grants. Own rows only; no platform-admin shortcut.
-- ---------------------------------------------------------------------------
alter table public.notifications enable row level security;
alter table public.notification_deliveries enable row level security;
alter table public.push_subscriptions enable row level security;
alter table public.notification_preferences enable row level security;

create policy notifications_select on public.notifications for select to authenticated
  using (person_id in (select private.my_person_ids()));

create policy notification_deliveries_select on public.notification_deliveries for select to authenticated
  using (person_id in (select private.my_person_ids()));

create policy push_subscriptions_select on public.push_subscriptions for select to authenticated
  using (person_id in (select private.my_person_ids()));
create policy push_subscriptions_delete on public.push_subscriptions for delete to authenticated
  using (person_id in (select private.my_person_ids()));

create policy notification_preferences_select on public.notification_preferences for select to authenticated
  using (person_id in (select private.my_person_ids()));
create policy notification_preferences_insert on public.notification_preferences for insert to authenticated
  with check (person_id in (select private.my_person_ids()));
create policy notification_preferences_update on public.notification_preferences for update to authenticated
  using (person_id in (select private.my_person_ids()))
  with check (person_id in (select private.my_person_ids()));
create policy notification_preferences_delete on public.notification_preferences for delete to authenticated
  using (person_id in (select private.my_person_ids()));

revoke all on table public.notifications, public.notification_deliveries, public.push_subscriptions,
  public.notification_preferences
from public, anon, authenticated, service_role;

grant select on table public.notifications to authenticated;
-- Delivery status only; never provider ids or errors.
grant select (id, organization_id, notification_id, person_id, channel, status, sent_at, created_at, updated_at)
  on public.notification_deliveries to authenticated;
-- Never endpoint or keys, not even to the owner.
grant select (id, organization_id, person_id, user_agent, last_used_at, disabled_at, created_at, updated_at)
  on public.push_subscriptions to authenticated;
grant delete on public.push_subscriptions to authenticated;
grant select, insert, delete on table public.notification_preferences to authenticated;
grant update (enabled) on public.notification_preferences to authenticated;

-- Worker: reads everything it sends; writes only through the functions above.
grant select on table public.notifications, public.notification_deliveries, public.push_subscriptions,
  public.notification_preferences to service_role;
