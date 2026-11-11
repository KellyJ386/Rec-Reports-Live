-- Phase 2: transactional outbox and durable jobs (ADR-0003).
--
--   outbox_events          one row per domain event, written ONLY by
--                          private.emit_event() in the same transaction as the
--                          business change
--   outbox_event_handlers  per-handler idempotency ledger
--
-- Worker API (service_role only): claim_outbox_events, complete_outbox_event,
-- fail_outbox_event, record_outbox_handler, outbox_handlers_done.
-- Admin API (authenticated): retry_dead_outbox_event.
--
-- Reads by tenants: the "failed jobs" screen. Gated by the audit_log module
-- (the same people who can read the audit trail of the changes that emitted
-- the events): audit_log >= view at organization scope sees every event of
-- the organization; at a location, events whose location_id is that location.
-- Retrying a dead event needs audit_log = admin in the same scope.
-- Payloads carry ids only (enforced shape, see private.validate_event_payload);
-- handlers re-read rows with the service key.

-- ---------------------------------------------------------------------------
-- Tunables: the single place each lives.
-- ---------------------------------------------------------------------------
create function private.outbox_max_attempts()
returns integer language sql immutable set search_path = '' as $$ select 8 $$;

-- Delay before attempt n+1 after n failed attempts: 1, 2, 4, 8 ... minutes,
-- capped at 6 hours. With 8 attempts an event is dead after about 2 hours.
create function private.outbox_backoff(p_attempts integer)
returns interval language sql immutable set search_path = '' as $$
  select least(make_interval(mins => power(2, greatest(p_attempts - 1, 0))::integer), interval '6 hours')
$$;

revoke all on function private.outbox_max_attempts() from public, anon, authenticated;
revoke all on function private.outbox_backoff(integer) from public, anon, authenticated;

-- Payload shape rule: a flat JSON object of at most 32 keys (snake_case),
-- whose values are null, boolean, number, a string of at most 200 characters
-- (ids, timestamps, enum values), or an array of at most 100 such strings
-- (each at most 64 characters, i.e. ids). No nested objects, so free text and
-- record copies cannot ride along. At most 8 kB as text.
create function private.validate_event_payload(p jsonb)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select p is not null
     and jsonb_typeof(p) = 'object'
     and octet_length(p::text) <= 8192
     and (select count(*) from jsonb_object_keys(p)) <= 32
     and not exists (
       select 1 from jsonb_each(p) e
       where e.key !~ '^[a-z][a-z0-9_]{0,62}$'
          or not (
            jsonb_typeof(e.value) in ('null', 'boolean', 'number')
            or (jsonb_typeof(e.value) = 'string' and char_length(e.value #>> '{}') <= 200)
            or (jsonb_typeof(e.value) = 'array'
                and jsonb_array_length(e.value) <= 100
                and not exists (select 1 from jsonb_array_elements(e.value) a
                                where jsonb_typeof(a) <> 'string' or char_length(a #>> '{}') > 64))))
$$;
revoke all on function private.validate_event_payload(jsonb) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- outbox_events
-- ---------------------------------------------------------------------------
create table public.outbox_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid,
  type text not null check (type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$' and char_length(type) <= 100),
  schema_version integer not null default 1 check (schema_version between 1 and 1000),
  entity_table text not null check (entity_table ~ '^[a-z][a-z0-9_]{0,62}$'),
  entity_id uuid not null,
  payload jsonb not null default '{}'::jsonb check (private.validate_event_payload(payload)),
  correlation_id uuid not null,
  status text not null default 'pending' check (status in ('pending', 'processing', 'done', 'dead')),
  attempts integer not null default 0 check (attempts >= 0),
  next_attempt_at timestamptz not null default now(),
  locked_at timestamptz,
  locked_by text check (char_length(locked_by) <= 100),
  lock_expires_at timestamptz,
  last_error text check (char_length(last_error) <= 2000),
  processed_at timestamptz,
  retried_at timestamptz,              -- last manual retry of a dead event
  retried_by_person_id uuid,           -- who did it (person in this organization)
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (retried_by_person_id, organization_id) references public.people (id, organization_id),
  check ((status = 'processing') = (locked_by is not null)),
  check ((status = 'processing') = (lock_expires_at is not null)),
  check ((status = 'done') = (processed_at is not null))
);

create index outbox_events_due_idx on public.outbox_events (next_attempt_at)
  where status = 'pending';
create index outbox_events_lock_idx on public.outbox_events (lock_expires_at)
  where status = 'processing';
create index outbox_events_org_created_idx on public.outbox_events (organization_id, created_at desc);
create index outbox_events_org_status_idx on public.outbox_events (organization_id, status)
  where status = 'dead';
create index outbox_events_location_idx on public.outbox_events (location_id, organization_id)
  where location_id is not null;
create index outbox_events_entity_idx on public.outbox_events (entity_table, entity_id);
create index outbox_events_retried_by_idx on public.outbox_events (retried_by_person_id, organization_id)
  where retried_by_person_id is not null;

create trigger outbox_events_timestamps before insert or update on public.outbox_events
  for each row execute function private.tg_set_timestamps();
create trigger outbox_events_immutable before update on public.outbox_events
  for each row execute function private.tg_immutable_columns(
    'id', 'organization_id', 'location_id', 'type', 'schema_version', 'entity_table', 'entity_id',
    'payload', 'correlation_id');

-- ---------------------------------------------------------------------------
-- outbox_event_handlers: handler H finished event E. A retried event skips
-- the handlers recorded here. Handlers must still be idempotent on their own
-- (unique source_event_id keys), because a crash between a handler's effect
-- and its ledger row re-runs that handler.
-- ---------------------------------------------------------------------------
create table public.outbox_event_handlers (
  event_id uuid not null,
  handler text not null check (handler ~ '^[a-z][a-z0-9_.:-]{0,99}$'),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  completed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (event_id, handler),
  foreign key (event_id, organization_id) references public.outbox_events (id, organization_id) on delete cascade
);
create index outbox_event_handlers_event_org_idx on public.outbox_event_handlers (event_id, organization_id);
create index outbox_event_handlers_org_idx on public.outbox_event_handlers (organization_id);

create trigger outbox_event_handlers_timestamps before insert or update on public.outbox_event_handlers
  for each row execute function private.tg_set_timestamps();
create trigger outbox_event_handlers_immutable before update on public.outbox_event_handlers
  for each row execute function private.tg_immutable_columns('event_id', 'handler', 'organization_id', 'completed_at');

-- Audit: both tables (catalog rule: every public table is audited). Nothing in
-- them is free text except last_error, which handlers must keep free of
-- personal data; it is redacted anyway so audit_log never copies it.
do $$
begin
  perform private.enable_audit('public.outbox_events', 'id', array['last_error']);
  perform private.enable_audit('public.outbox_event_handlers', 'event_id');
end;
$$;

-- ---------------------------------------------------------------------------
-- private.emit_event: the ONLY way an outbox row is created. Called by the
-- security definer RPCs and service functions of each domain, inside the same
-- transaction as the business change. Not granted to anyone (callers are
-- definer functions owned by the migration role).
--   p_available_at: earliest time a worker may pick the event up (default
--   now); e.g. a notice scheduled for later.
--   p_correlation_id: defaults to the new event's own id; follow-on events
--   pass the source event's correlation id.
-- ---------------------------------------------------------------------------
create function private.emit_event(
  p_organization_id uuid,
  p_location_id uuid,
  p_type text,
  p_entity_table text,
  p_entity_id uuid,
  p_payload jsonb default '{}'::jsonb,
  p_schema_version integer default 1,
  p_correlation_id uuid default null,
  p_available_at timestamptz default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_id uuid := gen_random_uuid();
begin
  if p_organization_id is null or p_entity_id is null or p_type is null or p_entity_table is null then
    raise exception 'event is missing required fields' using errcode = 'invalid_parameter_value';
  end if;
  if not private.validate_event_payload(coalesce(p_payload, '{}'::jsonb)) then
    raise exception 'event payload must be a small flat object of ids and scalars'
      using errcode = 'invalid_parameter_value';
  end if;
  insert into public.outbox_events (
    id, organization_id, location_id, type, schema_version, entity_table, entity_id,
    payload, correlation_id, next_attempt_at)
  values (
    v_id, p_organization_id, p_location_id, p_type, coalesce(p_schema_version, 1), p_entity_table, p_entity_id,
    coalesce(p_payload, '{}'::jsonb), coalesce(p_correlation_id, v_id), greatest(coalesce(p_available_at, now()), now()));
  return v_id;
end;
$$;
revoke all on function private.emit_event(uuid, uuid, text, text, uuid, jsonb, integer, uuid, timestamptz)
  from public, anon, authenticated, service_role;

-- Worker functions refuse a caller with a user JWT (defense in depth; the
-- real control is that only service_role has EXECUTE).
create function private.assert_service_caller()
returns void
language plpgsql
stable
set search_path = ''
as $$
begin
  if (select auth.uid()) is not null then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
end;
$$;
revoke all on function private.assert_service_caller() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- Worker API (service_role only)
-- ---------------------------------------------------------------------------

-- Claim up to p_limit events that are due: pending with next_attempt_at <= now,
-- or processing whose lock has expired (a crashed worker). Each claim counts as
-- an attempt. An expired lock on an event that has used every attempt goes to
-- dead instead of being claimed again. FOR UPDATE SKIP LOCKED: two workers never
-- claim the same row.
create function public.claim_outbox_events(p_worker text, p_limit integer, p_lock_seconds integer)
returns setof public.outbox_events
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

  update public.outbox_events e
  set status = 'dead', locked_at = null, locked_by = null, lock_expires_at = null,
      last_error = left(coalesce(e.last_error || ' | ', '') || 'lock expired on the last attempt', 2000)
  where e.id in (
    select x.id from public.outbox_events x
    where x.status = 'processing' and x.lock_expires_at < now()
      and x.attempts >= private.outbox_max_attempts()
    for update skip locked);

  return query
  update public.outbox_events e
  set status = 'processing',
      attempts = e.attempts + 1,
      locked_at = now(),
      locked_by = btrim(p_worker),
      lock_expires_at = now() + make_interval(secs => p_lock_seconds)
  where e.id in (
    select x.id from public.outbox_events x
    where (x.status = 'pending' and x.next_attempt_at <= now())
       or (x.status = 'processing' and x.lock_expires_at < now()
           and x.attempts < private.outbox_max_attempts())
    order by x.next_attempt_at, x.created_at
    limit p_limit
    for update skip locked)
  returning e.*;
end;
$$;

-- Mark an event done. Only the worker that holds the claim can (false if the
-- claim was lost: reclaimed by another worker after the lock expired, or the
-- event is no longer processing).
create function public.complete_outbox_event(p_id uuid, p_worker text)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform private.assert_service_caller();
  update public.outbox_events e
  set status = 'done', processed_at = now(), locked_at = null, locked_by = null, lock_expires_at = null
  where e.id = p_id and e.status = 'processing' and e.locked_by = btrim(p_worker);
  return found;
end;
$$;

-- Record a failure. Back to pending with exponential backoff, or dead once the
-- attempts are used up. Returns the new status, or null if the caller does not
-- hold the claim. p_error is truncated to 2000 characters; it must not contain
-- personal or sensitive data.
create function public.fail_outbox_event(p_id uuid, p_worker text, p_error text)
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
  update public.outbox_events e
  set status = case when e.attempts >= private.outbox_max_attempts() then 'dead' else 'pending' end,
      next_attempt_at = case when e.attempts >= private.outbox_max_attempts() then e.next_attempt_at
                             else now() + private.outbox_backoff(e.attempts) end,
      last_error = left(coalesce(nullif(btrim(p_error), ''), 'unknown error'), 2000),
      locked_at = null, locked_by = null, lock_expires_at = null
  where e.id = p_id and e.status = 'processing' and e.locked_by = btrim(p_worker)
  returning e.status into v_status;
  return v_status;
end;
$$;

-- Ledger: record that p_handler finished p_event_id. True when newly recorded,
-- false when it was already there.
create function public.record_outbox_handler(p_event_id uuid, p_handler text)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_org uuid;
  v_n integer;
begin
  perform private.assert_service_caller();
  select e.organization_id into v_org from public.outbox_events e where e.id = p_event_id;
  if v_org is null then
    raise exception 'no such event' using errcode = 'invalid_parameter_value';
  end if;
  insert into public.outbox_event_handlers (event_id, handler, organization_id)
  values (p_event_id, p_handler, v_org)
  on conflict (event_id, handler) do nothing;
  get diagnostics v_n = row_count;
  return v_n = 1;
end;
$$;

-- Handlers already finished for an event (the worker skips these).
create function public.outbox_handlers_done(p_event_id uuid)
returns setof text
language sql
stable
security definer
set search_path = ''
as $$
  select h.handler from public.outbox_event_handlers h
  where h.event_id = p_event_id and (select auth.uid()) is null
  order by h.handler
$$;

-- ---------------------------------------------------------------------------
-- Admin: retry a dead event (failed jobs screen).
-- ---------------------------------------------------------------------------
-- audit_log = admin at organization scope, or at the event's location. Uniform
-- 42501 'not allowed' when the event does not exist, belongs to another
-- organization, or the caller lacks the permission. The handler ledger is kept,
-- so handlers that already finished are not redone.
create function public.retry_dead_outbox_event(p_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_e public.outbox_events%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_e from public.outbox_events e where e.id = p_id for update;
  if not found
     or not (public.has_permission(v_e.organization_id, null, 'audit_log', 'admin')
             or (v_e.location_id is not null
                 and public.has_permission(v_e.organization_id, v_e.location_id, 'audit_log', 'admin'))) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if v_e.status <> 'dead' then
    raise exception 'only failed events can be retried' using errcode = 'invalid_parameter_value';
  end if;
  update public.outbox_events e
  set status = 'pending', attempts = 0, next_attempt_at = now(),
      retried_at = now(), retried_by_person_id = public.current_person_id(v_e.organization_id)
  where e.id = p_id;
end;
$$;

revoke all on function
  public.claim_outbox_events(text, integer, integer),
  public.complete_outbox_event(uuid, text),
  public.fail_outbox_event(uuid, text, text),
  public.record_outbox_handler(uuid, text),
  public.outbox_handlers_done(uuid),
  public.retry_dead_outbox_event(uuid)
from public, anon, authenticated;
grant execute on function
  public.claim_outbox_events(text, integer, integer),
  public.complete_outbox_event(uuid, text),
  public.fail_outbox_event(uuid, text, text),
  public.record_outbox_handler(uuid, text),
  public.outbox_handlers_done(uuid)
to service_role;
grant execute on function public.retry_dead_outbox_event(uuid) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- RLS and grants
-- ---------------------------------------------------------------------------
alter table public.outbox_events enable row level security;
alter table public.outbox_event_handlers enable row level security;

create policy outbox_events_select on public.outbox_events for select to authenticated
  using ((select public.is_platform_admin())
         or organization_id in (select private.permitted_org_ids('audit_log', 'view'))
         or location_id in (select private.permitted_location_ids('audit_log', 'view')));

create policy outbox_event_handlers_select on public.outbox_event_handlers for select to authenticated
  using (event_id in (select e.id from public.outbox_events e));

revoke all on table public.outbox_events, public.outbox_event_handlers from public, anon, authenticated, service_role;
grant select on table public.outbox_events, public.outbox_event_handlers to authenticated;
-- service_role reads (handlers, the admin screen) but writes only through the
-- functions above, so no API key can forge or rewrite an event.
grant select on table public.outbox_events, public.outbox_event_handlers to service_role;
