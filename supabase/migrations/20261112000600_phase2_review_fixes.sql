-- Phase 2 review fixes (two independent reviews of 20261112000100-000500, plus
-- findings from the pgTAP suite). Earlier migrations are committed and are not
-- edited; functions are replaced in place (same signature, grants kept) unless
-- a section says it drops and recreates one.
--
--   R1  workflow loop: rules never react to rule-made tasks; causation depth
--       on events; overdue rules need a positive due offset; cap on enabled
--       rules per organization and event type
--   R2  fairness (round-robin by organization) in the three batch claimers;
--       per-person write limits in the event-emitting RPCs; no infinite
--       timestamps anywhere; worker bookkeeping no longer audited
--   R3  message metadata: payload is the message id only; message events and
--       person-private audit rows are hidden from every tenant
--   R4  voluntary MFA: a user with a verified factor needs aal2 for ANY grant
--   R5  push endpoint allowlist; 10 subscriptions per person (oldest replaced);
--       an endpoint belongs to one person
--   R6  notice fan-out only for a published, live notice
--   R7  workflow_rules trigger checks the caller's right first
--   R8  free-text titles redacted in audit
--   R9  assorted: archived job titles, template assignee visibility, lock
--       after check, manual retry cap, rate-limit key normalisation, platform
--       branch honours disabled/archived, critical notice cap
--   R10 create_notifications (batch)
--   R11 worker read functions
--   R12 release / extend claims
--   R13 overdue escalation
--   R14 notice_acknowledgment_status, my_notices
--   R15 can_resend_person_invite
--   R16 (test writer) condition on a missing field never matches; publish
--       validates before writing; append-only tables refuse DELETE/TRUNCATE;
--       a failed delivery keeps its next_attempt_at

-- ===========================================================================
-- LIMITS: every tunable added here, in one place
-- ===========================================================================

-- Per-person write limits (fixed window, keyed by the caller's auth user id,
-- counted with public.consume_rate_limit under bucket 'write.<action>').
create function private.write_limits()
returns table (action text, max_hits integer, window_seconds integer)
language sql
immutable
set search_path = ''
as $$
  values
    ('task_create',     60,   600),   -- create_task: 60 per 10 minutes
    ('task_comment',    60,   600),   -- add_task_comment: 60 per 10 minutes
    ('task_transition', 120,  600),   -- start/complete/reopen/assign/cancel: 120 per 10 minutes
    ('message_send',    30,   600),   -- send_message: 30 per 10 minutes
    ('notice_publish',  20,   3600),  -- publish_notice: 20 per hour
    ('notice_critical', 5,    86400), -- publish_notice of a critical notice: 5 per day (on top of the above)
    ('push_save',       10,   3600)   -- save_push_subscription: 10 per hour
$$;

-- An event may be at most this many steps from a person's action (0 = caused
-- directly by an RPC or a sweep; each event emitted while handling event E is
-- E's depth + 1).
create function private.outbox_max_causation_depth()
returns integer language sql immutable set search_path = '' as $$ select 3 $$;

-- Enabled, non-archived workflow rules per organization per event type.
create function private.max_enabled_rules_per_event_type()
returns integer language sql immutable set search_path = '' as $$ select 20 $$;

-- Push subscriptions kept per person; saving one more removes the oldest.
create function private.max_push_subscriptions_per_person()
returns integer language sql immutable set search_path = '' as $$ select 10 $$;

-- Manual retries of one dead outbox event.
create function private.outbox_max_manual_retries()
returns integer language sql immutable set search_path = '' as $$ select 3 $$;

revoke all on function private.write_limits(), private.outbox_max_causation_depth(),
  private.max_enabled_rules_per_event_type(), private.max_push_subscriptions_per_person(),
  private.outbox_max_manual_retries()
from public, anon, authenticated;

-- ===========================================================================
-- R9e: rate-limit key normalisation strips ALL Unicode whitespace
-- ===========================================================================
-- Removes every whitespace or invisible separator character anywhere in the
-- key (ASCII whitespace, NBSP, the U+2000 block, line/paragraph separators,
-- narrow NBSP, medium math space, ideographic space, zero-width space/joiners,
-- word joiner, BOM, Mongolian vowel separator, Ogham space), then lowercases.
create function private.normalize_rate_limit_key(p text)
returns text
language sql
immutable
set search_path = ''
as $$
  select lower(regexp_replace(p,
    '[\s\u0085  ᠎ -‍    ⁠　﻿]', '', 'g'))
$$;
revoke all on function private.normalize_rate_limit_key(text) from public, anon, authenticated;

-- Same signature as 000100. Bucket rule unchanged (accepts sign-in:pair,
-- sign-in:email, sign-in:ip, forgot:email, write.task_create, ...).
create or replace function public.consume_rate_limit(p_bucket text, p_key text, p_max integer, p_window_seconds integer)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_key text := private.normalize_rate_limit_key(p_key);
  v_hash bytea;
  v_epoch double precision := extract(epoch from now());
  v_start timestamptz;
  v_hits integer;
begin
  if p_bucket is null or p_bucket !~ '^[a-z][a-z0-9_.:-]{0,62}$' then
    raise exception 'invalid bucket' using errcode = 'invalid_parameter_value';
  end if;
  if v_key is null or char_length(v_key) not between 1 and 512 then
    raise exception 'invalid key' using errcode = 'invalid_parameter_value';
  end if;
  if p_max is null or p_max not between 1 and 1000000 then
    raise exception 'invalid max' using errcode = 'invalid_parameter_value';
  end if;
  if p_window_seconds is null or p_window_seconds not between 1 and 86400 then
    raise exception 'invalid window' using errcode = 'invalid_parameter_value';
  end if;

  v_hash := extensions.hmac(
    convert_to(p_bucket, 'UTF8') || '\x00'::bytea || convert_to(v_key, 'UTF8'),
    (select s.secret from private.rate_limit_secret s),
    'sha256');
  v_start := to_timestamp(floor(v_epoch / p_window_seconds) * p_window_seconds);

  delete from private.rate_limit_counters c
  where c.bucket = p_bucket and c.key_hash = v_hash and c.window_end <= now();

  insert into private.rate_limit_counters as c (bucket, key_hash, window_start, window_end, hits)
  values (p_bucket, v_hash, v_start, v_start + make_interval(secs => p_window_seconds), 1)
  on conflict (bucket, key_hash, window_start) do update set hits = c.hits + 1
  returning c.hits into v_hits;

  return v_hits <= p_max;
end;
$$;

-- R2b: the per-person write limit. Raises the uniform refusal
--   SQLSTATE PT429, message 'slow down'
-- (PostgREST answers HTTP 429). Service code (no user) is not limited here.
-- A refused call rolls back, so it does not count; the window simply has to end.
create function private.enforce_write_limit(p_action text)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_uid uuid := (select auth.uid());
  v_max integer;
  v_window integer;
begin
  if v_uid is null then
    return;
  end if;
  select w.max_hits, w.window_seconds into v_max, v_window from private.write_limits() w where w.action = p_action;
  if v_max is null then
    raise exception 'unknown write limit %', p_action using errcode = 'invalid_parameter_value';
  end if;
  if not public.consume_rate_limit('write.' || p_action, v_uid::text, v_max, v_window) then
    raise exception 'slow down' using errcode = 'PT429',
      hint = 'Too many changes in a short time. Wait a few minutes and try again.';
  end if;
end;
$$;
revoke all on function private.enforce_write_limit(text) from public, anon, authenticated;

-- ===========================================================================
-- R2c: no timestamp or date column in public accepts +/-infinity
-- ===========================================================================
-- One CHECK per column, named finite_<column>, on every table in public
-- (audit_log excepted: written only by the trigger, from now()). New tables
-- must follow the same rule (suggested catalog guard in docs/DATA_MODEL.md).
-- Added before the new columns below, which carry their own check.
do $$
declare
  r record;
begin
  for r in
    select c.relname, a.attname
    from pg_catalog.pg_attribute a
    join pg_catalog.pg_class c on c.oid = a.attrelid
    where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p')
      and c.relname <> 'audit_log'
      and a.attnum > 0 and not a.attisdropped
      and a.atttypid in ('timestamptz'::regtype, 'timestamp'::regtype, 'date'::regtype)
    order by c.relname, a.attnum
  loop
    execute format('alter table public.%I add constraint %I check (%I is null or isfinite(%I))',
                   r.relname, left('finite_' || r.attname, 63), r.attname, r.attname);
  end loop;
end;
$$;

-- ===========================================================================
-- R4: voluntary MFA. A user with a verified factor needs aal2 for ANY grant.
-- ===========================================================================
-- auth.mfa_factors always exists on Supabase. The plain-Postgres stand-in may
-- not have it; absence is treated as "no verified factor", which is safe:
-- without that table Supabase Auth cannot verify a factor at all, so no
-- session anywhere can be aal2 through one, and the result equals the old rule.
create function private.user_has_verified_mfa(p_user_id uuid)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if p_user_id is null or to_regclass('auth.mfa_factors') is null then
    return false;
  end if;
  return exists (select 1 from auth.mfa_factors f where f.user_id = p_user_id and f.status::text = 'verified');
end;
$$;
revoke all on function private.user_has_verified_mfa(uuid) from public, anon, authenticated;

-- Same signature as 000100. At aal1: admin-tier rows never count; and no row
-- counts at all for a user who has a verified factor.
create or replace function private.my_assignments()
returns table (organization_id uuid, person_id uuid, location_id uuid, role_id uuid, role_key text, rank integer)
language sql
stable
security definer
set search_path = ''
as $$
  select x.organization_id, x.person_id, x.location_id, x.role_id, x.role_key, x.rank
  from (
    select ra.organization_id, ra.person_id, ra.location_id, r.id as role_id, r.key as role_key,
           r.rank + case when ra.location_id is null then 10 else 0 end as rank
    from public.accounts a
    join public.people p on p.id = a.person_id and p.organization_id = a.organization_id
    join public.role_assignments ra on ra.person_id = p.id and ra.organization_id = p.organization_id
    join public.roles r on r.id = ra.role_id
    left join public.locations l on l.id = ra.location_id and l.organization_id = ra.organization_id
    where a.user_id = (select auth.uid())
      and a.disabled_at is null
      and p.archived_at is null
      and r.archived_at is null
      and (ra.location_id is null or l.archived_at is null)
  ) x
  where private.session_is_aal2()
     or (x.rank < private.admin_tier_min_rank()
         and not (select private.user_has_verified_mfa((select auth.uid()))))
$$;

-- Same signature as 000100. Caller's own person: the MFA rules above.
-- Platform-admin branch (R9f) now needs the target's account active and the
-- person not archived, like every other branch.
create or replace function private.person_effective_level(
  p_organization_id uuid, p_person_id uuid, p_location_id uuid, p_module_key text)
returns public.permission_level
language sql
stable
security definer
set search_path = ''
as $$
  with covering as (
    select ra.role_id
    from public.role_assignments ra
    join public.people p on p.id = ra.person_id and p.organization_id = ra.organization_id
    join public.accounts a on a.person_id = p.id and a.organization_id = p.organization_id
    join public.roles r on r.id = ra.role_id
    left join public.locations l on l.id = ra.location_id and l.organization_id = ra.organization_id
    where ra.person_id = p_person_id
      and ra.organization_id = p_organization_id
      and a.disabled_at is null
      and p.archived_at is null
      and r.archived_at is null
      and (ra.location_id is null or (ra.location_id = p_location_id and l.archived_at is null))
      and (a.user_id is distinct from (select auth.uid())
           or private.session_is_aal2()
           or (r.rank + case when ra.location_id is null then 10 else 0 end < private.admin_tier_min_rank()
               and not private.user_has_verified_mfa(a.user_id)))
  )
  select case
    when p_person_id is null or not private.scope_exists(p_organization_id, p_location_id) then null
    when exists (
      select 1 from public.accounts a
      join public.platform_admins pa on pa.user_id = a.user_id
      join public.people p on p.id = a.person_id and p.organization_id = a.organization_id
      where a.person_id = p_person_id and a.organization_id = p_organization_id
        and a.disabled_at is null and p.archived_at is null
        and (a.user_id is distinct from (select auth.uid()) or private.session_is_aal2())
    ) then 'admin'::public.permission_level
    when not exists (select 1 from covering) then null
    else coalesce(
      (select up.level from public.user_permissions up
        where up.organization_id = p_organization_id and up.person_id = p_person_id
          and up.module_key = p_module_key and up.location_id = p_location_id),
      (select up.level from public.user_permissions up
        where up.organization_id = p_organization_id and up.person_id = p_person_id
          and up.module_key = p_module_key and up.location_id is null),
      (select max(d.level) from public.role_default_permissions d
        where d.module_key = p_module_key and d.role_id in (select c.role_id from covering c)),
      'none'::public.permission_level)
  end
$$;

-- Same signature as 000100. Also true at aal1 for anyone with a verified factor.
create or replace function public.session_needs_mfa()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (select auth.uid()) is not null
     and not private.session_is_aal2()
     and (
       private.user_has_verified_mfa((select auth.uid()))
       or exists (select 1 from public.platform_admins pa where pa.user_id = (select auth.uid()))
       or exists (
         select 1
         from public.accounts a
         join public.people p on p.id = a.person_id and p.organization_id = a.organization_id
         join public.role_assignments ra on ra.person_id = p.id and ra.organization_id = p.organization_id
         join public.roles r on r.id = ra.role_id
         left join public.locations l on l.id = ra.location_id and l.organization_id = ra.organization_id
         where a.user_id = (select auth.uid())
           and a.disabled_at is null
           and p.archived_at is null
           and r.archived_at is null
           and (ra.location_id is null or l.archived_at is null)
           and r.rank + case when ra.location_id is null then 10 else 0 end >= private.admin_tier_min_rank()))
$$;

-- ===========================================================================
-- R16c: append-only tables refuse UPDATE, DELETE and TRUNCATE for every role
-- ===========================================================================
-- Exception, so an organization (or a task / notice) can still be deleted
-- as a whole: a DELETE is let through only when the row's parent is already
-- gone in the same statement, i.e. it is the FK cascade from deleting the
-- parent. tg_argv: [0] parent table, [1] the row's column holding the parent id.
-- Security definer so the parent lookup is not filtered by RLS.
create or replace function private.tg_append_only()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_parent_exists boolean;
begin
  if tg_op = 'DELETE' and tg_nargs >= 2 then
    execute format('select exists (select 1 from %s x where x.id = $1)', tg_argv[0]::regclass)
      into v_parent_exists using (to_jsonb(old) ->> tg_argv[1])::uuid;
    if not v_parent_exists then
      return old;
    end if;
  end if;
  raise exception '% is append-only (% blocked)', tg_table_name, tg_op using errcode = 'insufficient_privilege';
end;
$$;
revoke all on function private.tg_append_only() from public, anon, authenticated;

drop trigger task_events_append_only on public.task_events;
create trigger task_events_append_only before update or delete on public.task_events
  for each row execute function private.tg_append_only('public.tasks', 'task_id');
create trigger task_events_append_only_truncate before truncate on public.task_events
  for each statement execute function private.tg_append_only();

drop trigger acknowledgments_append_only on public.acknowledgments;
create trigger acknowledgments_append_only before update or delete on public.acknowledgments
  for each row execute function private.tg_append_only('public.notices', 'notice_id');
create trigger acknowledgments_append_only_truncate before truncate on public.acknowledgments
  for each statement execute function private.tg_append_only();

-- ===========================================================================
-- R1 + R3: outbox events carry causation; message events are private
-- ===========================================================================
alter table public.outbox_events
  add column causation_id uuid,                     -- the event being handled when this one was emitted (not an FK: purged)
  add column causation_depth integer not null default 0 check (causation_depth >= 0),
  add column manual_retries integer not null default 0 check (manual_retries >= 0);

drop trigger outbox_events_immutable on public.outbox_events;
create trigger outbox_events_immutable before update on public.outbox_events
  for each row execute function private.tg_immutable_columns(
    'id', 'organization_id', 'location_id', 'type', 'schema_version', 'entity_table', 'entity_id',
    'payload', 'correlation_id', 'causation_id', 'causation_depth');

create index outbox_events_org_due_idx on public.outbox_events (organization_id, next_attempt_at)
  where status in ('pending', 'processing');

-- Event types whose rows no tenant may read (the single list): message.*
-- (who messaged whom, and when, is private to sender and recipients).
create function private.outbox_type_is_private(p_type text)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select split_part(coalesce(p_type, ''), '.', 1) in ('message')
$$;
revoke all on function private.outbox_type_is_private(text) from public, anon, authenticated;
grant execute on function private.outbox_type_is_private(text) to authenticated, service_role;

-- Dropped and recreated with a 10th parameter (positional calls with 5-9
-- arguments still resolve). p_causation_event_id: the event being handled;
-- depth = its depth + 1, correlation defaults to its correlation, and it must
-- be in the same organization. A depth over the limit raises 54000.
drop function private.emit_event(uuid, uuid, text, text, uuid, jsonb, integer, uuid, timestamptz);
create function private.emit_event(
  p_organization_id uuid,
  p_location_id uuid,
  p_type text,
  p_entity_table text,
  p_entity_id uuid,
  p_payload jsonb default '{}'::jsonb,
  p_schema_version integer default 1,
  p_correlation_id uuid default null,
  p_available_at timestamptz default null,
  p_causation_event_id uuid default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_id uuid := gen_random_uuid();
  v_depth integer := 0;
  v_corr uuid := p_correlation_id;
  v_cause public.outbox_events%rowtype;
begin
  if p_organization_id is null or p_entity_id is null or p_type is null or p_entity_table is null then
    raise exception 'event is missing required fields' using errcode = 'invalid_parameter_value';
  end if;
  if not private.validate_event_payload(coalesce(p_payload, '{}'::jsonb)) then
    raise exception 'event payload must be a small flat object of ids and scalars'
      using errcode = 'invalid_parameter_value';
  end if;
  if p_available_at is not null and not isfinite(p_available_at) then
    raise exception 'invalid time' using errcode = 'invalid_parameter_value';
  end if;
  if p_causation_event_id is not null then
    select * into v_cause from public.outbox_events e where e.id = p_causation_event_id;
    if found then
      if v_cause.organization_id <> p_organization_id then
        raise exception 'cause belongs to another organization' using errcode = 'invalid_parameter_value';
      end if;
      v_depth := v_cause.causation_depth + 1;
      v_corr := coalesce(v_corr, v_cause.correlation_id);
    else
      v_depth := 1;   -- the cause was purged; still counts as one step
    end if;
    if v_depth > private.outbox_max_causation_depth() then
      raise exception 'event chain is too deep' using errcode = 'program_limit_exceeded';
    end if;
  end if;
  insert into public.outbox_events (
    id, organization_id, location_id, type, schema_version, entity_table, entity_id,
    payload, correlation_id, causation_id, causation_depth, next_attempt_at)
  values (
    v_id, p_organization_id, p_location_id, p_type, coalesce(p_schema_version, 1), p_entity_table, p_entity_id,
    coalesce(p_payload, '{}'::jsonb), coalesce(v_corr, v_id), p_causation_event_id, v_depth,
    greatest(coalesce(p_available_at, now()), now()));
  return v_id;
end;
$$;
revoke all on function private.emit_event(uuid, uuid, text, text, uuid, jsonb, integer, uuid, timestamptz, uuid)
  from public, anon, authenticated, service_role;

-- R3: tenants (platform admins included) never see message events.
drop policy outbox_events_select on public.outbox_events;
create policy outbox_events_select on public.outbox_events for select to authenticated
  using (not private.outbox_type_is_private(type)
         and ((select public.is_platform_admin())
              or organization_id in (select private.permitted_org_ids('audit_log', 'view'))
              or location_id in (select private.permitted_location_ids('audit_log', 'view'))));

-- ===========================================================================
-- R2d + R3: what is audited
-- ===========================================================================
-- outbox_events: only a person's manual retry (manual_retries or retried_at
--   changes). Not
--   audited: inserts (the business change that emitted the event is audited
--   in its own table), and every worker change (status, attempts, locks,
--   errors, processed_at, dead).
drop trigger zz_audit on public.outbox_events;
create trigger zz_audit after update on public.outbox_events
  for each row when (old.manual_retries is distinct from new.manual_retries
                     or old.retried_at is distinct from new.retried_at)
  execute function private.tg_audit_row('id', 'last_error');

-- outbox_event_handlers: the handler ledger is pure worker bookkeeping. The
-- trigger is kept (catalog rule) but fires only on UPDATE, and no code path
-- updates a ledger row (all its columns but updated_at are immutable), so in
-- practice nothing is written.
drop trigger zz_audit on public.outbox_event_handlers;
create trigger zz_audit after update on public.outbox_event_handlers
  for each row execute function private.tg_audit_row('event_id');

-- notification_deliveries: only a change of status (pending -> sent / failed
--   / skipped, or back to pending). Not audited: inserts, attempts, locks,
--   next_attempt_at, errors without a status change.
drop trigger zz_audit on public.notification_deliveries;
create trigger zz_audit after update on public.notification_deliveries
  for each row when (old.status is distinct from new.status)
  execute function private.tg_audit_row('id', 'last_error', 'provider_message_id');

-- Scrub the sender and recipients out of message events written before this
-- migration (payload is immutable, so its guard is lifted for this one update;
-- no audit row is written: outbox updates are audited only for retries).
alter table public.outbox_events disable trigger outbox_events_immutable;
update public.outbox_events e
set payload = jsonb_build_object('message_id', e.payload -> 'message_id')
where e.type = 'message.sent' and e.payload <> jsonb_build_object('message_id', e.payload -> 'message_id');
alter table public.outbox_events enable trigger outbox_events_immutable;

-- Audit rows no tenant reads (platform admins included; only service_role):
-- person-private tables, and the worker ledger.
create function private.audit_hidden_tables()
returns text[]
language sql
immutable
set search_path = ''
as $$
  select array['messages', 'message_recipients', 'notifications', 'notification_deliveries',
               'push_subscriptions', 'notification_preferences', 'outbox_event_handlers']
$$;
revoke all on function private.audit_hidden_tables() from public, anon, authenticated;
grant execute on function private.audit_hidden_tables() to authenticated, service_role;

drop policy audit_log_select on public.audit_log;
create policy audit_log_select on public.audit_log for select to authenticated
  using (not (table_schema = 'public' and table_name = any (private.audit_hidden_tables()))
         and not (table_schema = 'public' and table_name = 'outbox_events'
                  and private.outbox_type_is_private(coalesce(new_row ->> 'type', old_row ->> 'type')))
         and ((select public.is_platform_admin())
              or organization_id in (select private.permitted_org_ids('audit_log', 'view'))
              or location_id in (select private.permitted_location_ids('audit_log', 'view'))));

-- R8: free-text titles and names are redacted too.
do $$
begin
  perform private.enable_audit('public.task_templates', 'id', array['instructions', 'title']);
  perform private.enable_audit('public.workflow_rules', 'id', array['name']);
  perform private.enable_audit('public.tasks', 'id', array['instructions', 'title']);
  perform private.enable_audit('public.notices', 'id', array['body', 'title']);
end;
$$;

-- ===========================================================================
-- R2a + R12: worker API (round-robin claims, release, extend)
-- ===========================================================================
-- Claim names: workers pass a name unique per invocation (the app uses
-- '<job>:<random uuid>'), so the name already is a per-claim token: a
-- reclaim after expiry overwrites locked_by, and the earlier holder's
-- complete/fail/release/extend then match nothing. Signatures are kept.

-- Same signature as 000200. Round-robin by organization: the batch takes each
-- organization's oldest due event first, then each one's second, and so on.
-- Concurrent claimers never get the same row (SKIP LOCKED); one may get fewer
-- than p_limit in a round when the other locked part of the same candidates.
create or replace function public.claim_outbox_events(p_worker text, p_limit integer, p_lock_seconds integer)
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
    where x.id in (
        select r.id from (
          select d.id, d.next_attempt_at, d.created_at,
                 row_number() over (partition by d.organization_id order by d.next_attempt_at, d.created_at, d.id) as rn
          from public.outbox_events d
          where (d.status = 'pending' and d.next_attempt_at <= now())
             or (d.status = 'processing' and d.lock_expires_at < now()
                 and d.attempts < private.outbox_max_attempts())) r
        order by r.rn, r.next_attempt_at, r.created_at
        limit p_limit)
      and ((x.status = 'pending' and x.next_attempt_at <= now())
           or (x.status = 'processing' and x.lock_expires_at < now()
               and x.attempts < private.outbox_max_attempts()))
    for update skip locked)
  returning e.*;
end;
$$;

-- Give a claim back without using an attempt (e.g. the worker is shutting
-- down). Only the holder; false otherwise.
create function public.release_outbox_event(p_id uuid, p_worker text)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform private.assert_service_caller();
  update public.outbox_events e
  set status = 'pending', attempts = greatest(e.attempts - 1, 0), next_attempt_at = now(),
      locked_at = null, locked_by = null, lock_expires_at = null
  where e.id = p_id and e.status = 'processing' and e.locked_by = btrim(p_worker);
  return found;
end;
$$;

-- Keep a claim for p_seconds (5-3600) more from now. Only the holder, and only
-- while the lock has not expired (after expiry another worker may hold it).
create function public.extend_outbox_lock(p_id uuid, p_worker text, p_seconds integer)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform private.assert_service_caller();
  if p_seconds is null or p_seconds not between 5 and 3600 then
    raise exception 'invalid lock time' using errcode = 'invalid_parameter_value';
  end if;
  update public.outbox_events e
  set lock_expires_at = now() + make_interval(secs => p_seconds)
  where e.id = p_id and e.status = 'processing' and e.locked_by = btrim(p_worker) and e.lock_expires_at > now();
  return found;
end;
$$;

-- Same signature as 000500. Round-robin by organization, as above.
create or replace function public.claim_notification_deliveries(
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
    where x.id in (
        select r.id from (
          select y.id, y.next_attempt_at, y.created_at,
                 row_number() over (partition by y.organization_id order by y.next_attempt_at, y.created_at, y.id) as rn
          from public.notification_deliveries y
          where y.status = 'pending' and y.channel <> 'in_app'
            and y.next_attempt_at <= now()
            and (y.lock_expires_at is null or y.lock_expires_at < now())
            and y.attempts < private.delivery_max_attempts()
            and (p_channel is null or y.channel = p_channel)) r
        order by r.rn, r.next_attempt_at, r.created_at
        limit p_limit)
      and x.status = 'pending' and x.next_attempt_at <= now()
      and (x.lock_expires_at is null or x.lock_expires_at < now())
      and x.attempts < private.delivery_max_attempts()
    for update skip locked)
  returning d.*;
end;
$$;

create function public.release_notification_delivery(p_id uuid, p_worker text)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform private.assert_service_caller();
  update public.notification_deliveries d
  set attempts = greatest(d.attempts - 1, 0), next_attempt_at = now(),
      locked_at = null, locked_by = null, lock_expires_at = null
  where d.id = p_id and d.status = 'pending' and d.locked_by = btrim(p_worker);
  return found;
end;
$$;

-- Same signature as 000500. R16: a delivery that becomes failed keeps its
-- next_attempt_at (no future retry time on a final row).
create or replace function public.fail_notification_delivery(
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
      next_attempt_at = case when coalesce(p_permanent, false) or d.attempts >= private.delivery_max_attempts()
                             then d.next_attempt_at else now() + private.outbox_backoff(d.attempts) end,
      last_error = left(coalesce(nullif(btrim(p_error), ''), 'unknown error'), 2000),
      locked_at = null, locked_by = null, lock_expires_at = null
  where d.id = p_id and d.status = 'pending' and d.locked_by = btrim(p_worker)
  returning d.status into v_status;
  return v_status;
end;
$$;

-- Same signature as 000200. R9d: permission is checked before the row is
-- locked; message events cannot be retried by tenants (they cannot see
-- them); at most outbox_max_manual_retries() manual retries per event.
create or replace function public.retry_dead_outbox_event(p_id uuid)
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
  select * into v_e from public.outbox_events e where e.id = p_id;
  if not found
     or private.outbox_type_is_private(v_e.type)
     or not (public.has_permission(v_e.organization_id, null, 'audit_log', 'admin')
             or (v_e.location_id is not null
                 and public.has_permission(v_e.organization_id, v_e.location_id, 'audit_log', 'admin'))) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  select * into v_e from public.outbox_events e where e.id = p_id for update;
  if v_e.status <> 'dead' then
    raise exception 'only failed events can be retried' using errcode = 'invalid_parameter_value';
  end if;
  if v_e.manual_retries >= private.outbox_max_manual_retries() then
    raise exception 'this job has been retried too many times; ask support' using errcode = 'invalid_parameter_value';
  end if;
  update public.outbox_events e
  set status = 'pending', attempts = 0, next_attempt_at = now(), manual_retries = e.manual_retries + 1,
      retried_at = now(), retried_by_person_id = public.current_person_id(v_e.organization_id)
  where e.id = p_id;
end;
$$;

revoke all on function
  public.release_outbox_event(uuid, text),
  public.extend_outbox_lock(uuid, text, integer),
  public.release_notification_delivery(uuid, text)
from public, anon, authenticated;
grant execute on function
  public.release_outbox_event(uuid, text),
  public.extend_outbox_lock(uuid, text, integer),
  public.release_notification_delivery(uuid, text)
to service_role;

-- ===========================================================================
-- Tasks and workflows: R1, R2, R7, R9, R13, R16a
-- ===========================================================================

-- R9a: archived job titles route nothing.
create or replace function private.my_job_title_scopes()
returns table (job_title_id uuid, location_id uuid)
language sql
stable
security definer
set search_path = ''
as $$
  select pjt.job_title_id, pjt.location_id
  from public.person_job_titles pjt
  join public.job_titles jt on jt.id = pjt.job_title_id and jt.organization_id = pjt.organization_id
  where pjt.person_id in (select private.my_person_ids()) and pjt.location_id is not null
    and jt.archived_at is null
  union
  select pjt.job_title_id, l.id
  from public.person_job_titles pjt
  join public.job_titles jt on jt.id = pjt.job_title_id and jt.organization_id = pjt.organization_id
  join public.locations l on l.organization_id = pjt.organization_id
  where pjt.person_id in (select private.my_person_ids()) and pjt.location_id is null
    and jt.archived_at is null
$$;

-- R16a: a clause on a field the payload does not have (or any clause that
-- would evaluate to NULL) never matches. Same signature as 000300.
create or replace function private.workflow_condition_matches(p_condition jsonb, p_payload jsonb)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select coalesce(p_condition, '{}'::jsonb) = '{}'::jsonb
      or (jsonb_typeof(p_payload) = 'object'
          and jsonb_typeof(p_condition -> 'all') = 'array'
          and not exists (
            select 1 from jsonb_array_elements(p_condition -> 'all') c
            where not coalesce(
              p_payload ? (c ->> 'field')
              and ((c ->> 'op' = 'eq' and (p_payload -> (c ->> 'field')) = (c -> 'value'))
                   or (c ->> 'op' = 'in' and jsonb_typeof(c -> 'value') = 'array' and exists (
                         select 1 from jsonb_array_elements(c -> 'value') v
                         where (p_payload -> (c ->> 'field')) = v))),
              false)))
$$;

-- R9b: may the caller read this template? The config rule, and an assigned
-- person the caller can see (so a template never reveals someone outside the
-- caller's view). Used by the select policy and the workflow_rules trigger.
create function private.can_read_task_template(
  p_organization_id uuid, p_location_id uuid, p_assign_person_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    private.can_read_task_config(p_organization_id, p_location_id)
    and (p_assign_person_id is null
         or public.is_platform_admin()
         or p_assign_person_id in (select private.visible_person_ids())),
    false)
$$;
revoke all on function private.can_read_task_template(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function private.can_read_task_template(uuid, uuid, uuid) to authenticated, service_role;

drop policy task_templates_select on public.task_templates;
create policy task_templates_select on public.task_templates for select to authenticated
  using (private.can_read_task_template(organization_id, location_id, assign_person_id));

-- R1, R7: rule validation. Order: member of the organization; tasks = admin
-- in the rule's scope; the template exists in the organization AND is
-- readable by the caller (all three: uniform 42501 'not allowed'). Then:
-- location match, not archived, an overdue rule needs a template due at
-- least 1 minute after the event, and at most
-- max_enabled_rules_per_event_type() enabled rules per organization per type.
create or replace function private.tg_workflow_rules_validate()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := (select auth.uid());
  v_t public.task_templates%rowtype;
  v_n integer;
begin
  perform private.assert_member_of(new.organization_id);
  if v_uid is not null
     and public.has_permission(new.organization_id, new.location_id, 'tasks', 'admin') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if tg_op = 'INSERT' then
    new.enabled := false;
  end if;
  select * into v_t from public.task_templates t
  where t.id = new.task_template_id and t.organization_id = new.organization_id;
  if not found
     or (v_uid is not null
         and private.can_read_task_template(v_t.organization_id, v_t.location_id, v_t.assign_person_id) is not true) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if v_t.location_id is not null and new.location_id is distinct from v_t.location_id then
    raise exception 'that task template belongs to a different location' using errcode = 'check_violation';
  end if;
  if new.enabled and v_t.archived_at is not null then
    raise exception 'that task template is archived' using errcode = 'check_violation';
  end if;
  if new.event_type = 'task.overdue' and v_t.due_offset_minutes is not null and v_t.due_offset_minutes <= 0 then
    raise exception 'a rule for overdue tasks needs a template that is due at least 1 minute later'
      using errcode = 'check_violation';
  end if;
  if new.enabled and new.archived_at is null
     and (tg_op = 'INSERT' or not old.enabled or old.archived_at is not null
          or old.event_type is distinct from new.event_type) then
    perform pg_advisory_xact_lock(hashtextextended(
      'workflow_rules:' || new.organization_id::text || ':' || new.event_type, 0));
    select count(*) into v_n from public.workflow_rules r
    where r.organization_id = new.organization_id and r.event_type = new.event_type
      and r.enabled and r.archived_at is null and r.id <> new.id;
    if v_n >= private.max_enabled_rules_per_event_type() then
      raise exception 'at most % rules can be on for one kind of event', private.max_enabled_rules_per_event_type()
        using errcode = 'check_violation';
    end if;
  end if;
  return new;
end;
$$;

-- R1: a template used by an overdue rule cannot get a due offset <= 0.
create function private.tg_task_templates_validate()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.assert_member_of(new.organization_id);
  if new.due_offset_minutes is distinct from old.due_offset_minutes
     and new.due_offset_minutes is not null and new.due_offset_minutes <= 0
     and exists (select 1 from public.workflow_rules r
                 where r.task_template_id = new.id and r.organization_id = new.organization_id
                   and r.event_type = 'task.overdue' and r.archived_at is null) then
    raise exception 'a rule for overdue tasks uses this template, so it must be due at least 1 minute later'
      using errcode = 'check_violation';
  end if;
  return new;
end;
$$;
revoke all on function private.tg_task_templates_validate() from public, anon, authenticated;
create trigger task_templates_validate before update on public.task_templates
  for each row execute function private.tg_task_templates_validate();

-- R13: escalation bookkeeping (due_at for which the escalation was recorded).
alter table public.tasks
  add column escalated_for timestamptz constraint finite_escalated_for check (escalated_for is null or isfinite(escalated_for));

-- R9c: check first, then lock, then check again on the locked row (the
-- assignee may have changed while waiting). Same signature as 000300.
create or replace function private.lock_task_for_caller(p_task_id uuid, p_level public.permission_level)
returns public.tasks
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_t from public.tasks t where t.id = p_task_id;
  if not found
     or private.can_see_task(v_t.organization_id, v_t.location_id, v_t.assigned_person_id, v_t.assigned_job_title_id) is not true
     or public.has_permission(v_t.organization_id, v_t.location_id, 'tasks', p_level) is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  select * into v_t from public.tasks t where t.id = p_task_id for update;
  if not found
     or private.can_see_task(v_t.organization_id, v_t.location_id, v_t.assigned_person_id, v_t.assigned_job_title_id) is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  return v_t;
end;
$$;

-- R1: the event a task change emits carries the handled event as its cause.
-- Same signature as 000300.
create or replace function private.record_task_change(
  p_task public.tasks, p_kind text, p_from_status text, p_body text,
  p_source_event_id uuid default null, p_correlation_id uuid default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_actor uuid := case when (select auth.uid()) is not null then public.current_person_id(p_task.organization_id) end;
  v_te uuid;
begin
  insert into public.task_events (
    organization_id, location_id, task_id, kind, actor_person_id, from_status, to_status,
    assigned_person_id, assigned_job_title_id, body, source_event_id)
  values (
    p_task.organization_id, p_task.location_id, p_task.id, p_kind, v_actor, p_from_status, p_task.status,
    case when p_kind in ('created', 'assigned') then p_task.assigned_person_id end,
    case when p_kind in ('created', 'assigned') then p_task.assigned_job_title_id end,
    p_body, p_source_event_id)
  returning id into v_te;

  perform private.emit_event(
    p_task.organization_id, p_task.location_id, 'task.' || p_kind, 'tasks', p_task.id,
    jsonb_build_object(
      'task_id', p_task.id,
      'task_event_id', v_te,
      'location_id', p_task.location_id,
      'status', p_task.status,
      'priority', p_task.priority,
      'assigned_person_id', p_task.assigned_person_id,
      'assigned_job_title_id', p_task.assigned_job_title_id,
      'actor_person_id', v_actor,
      'due_at', p_task.due_at),
    1, p_correlation_id, null, p_source_event_id);
  return v_te;
end;
$$;

-- R2b, R2c. Same signature as 000300.
create or replace function public.create_task(
  p_organization_id uuid,
  p_location_id uuid,
  p_title text,
  p_instructions text default null,
  p_due_at timestamptz default null,
  p_priority text default 'normal',
  p_space_id uuid default null,
  p_assigned_person_id uuid default null,
  p_assigned_job_title_id uuid default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_t public.tasks%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if p_organization_id is null or p_location_id is null
     or not public.has_permission(p_organization_id, p_location_id, 'tasks', 'edit') then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('task_create');
  v_me := public.current_person_id(p_organization_id);
  if not public.has_permission(p_organization_id, p_location_id, 'tasks', 'admin')
     and (p_assigned_job_title_id is not null
          or (p_assigned_person_id is not null and p_assigned_person_id is distinct from v_me)) then
    raise exception 'only a manager can assign tasks to others' using errcode = 'insufficient_privilege';
  end if;
  if p_due_at is not null and not isfinite(p_due_at) then
    raise exception 'invalid due time' using errcode = 'invalid_parameter_value';
  end if;
  if not private.valid_task_assignee(p_organization_id, p_location_id, p_assigned_person_id) then
    raise exception 'that person cannot be given tasks at this location' using errcode = 'invalid_parameter_value';
  end if;
  if p_assigned_job_title_id is not null and not exists (
       select 1 from public.job_titles j
       where j.id = p_assigned_job_title_id and j.organization_id = p_organization_id and j.archived_at is null) then
    raise exception 'unknown job title' using errcode = 'invalid_parameter_value';
  end if;
  if p_space_id is not null and not exists (
       select 1 from public.spaces s
       where s.id = p_space_id and s.organization_id = p_organization_id and s.location_id = p_location_id) then
    raise exception 'unknown space at this location' using errcode = 'invalid_parameter_value';
  end if;
  if p_priority is null or p_priority not in ('low', 'normal', 'high', 'urgent') then
    raise exception 'invalid priority' using errcode = 'invalid_parameter_value';
  end if;

  insert into public.tasks (
    organization_id, location_id, space_id, title, instructions, priority, due_at,
    assigned_person_id, assigned_job_title_id, created_by_person_id)
  values (
    p_organization_id, p_location_id, p_space_id, btrim(p_title), nullif(btrim(p_instructions), ''),
    p_priority, p_due_at, p_assigned_person_id, p_assigned_job_title_id, v_me)
  returning * into v_t;

  perform private.record_task_change(v_t, 'created', null, null);
  return v_t.id;
end;
$$;

create or replace function public.start_task(p_task_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'edit');
begin
  perform private.enforce_write_limit('task_transition');
  if v_t.status <> 'open' then
    raise exception 'only an open task can be started' using errcode = 'invalid_parameter_value';
  end if;
  update public.tasks t
  set status = 'in_progress',
      assigned_person_id = coalesce(t.assigned_person_id, public.current_person_id(t.organization_id))
  where t.id = v_t.id
  returning * into v_t;
  perform private.record_task_change(v_t, 'started', 'open', null);
end;
$$;

create or replace function public.complete_task(p_task_id uuid, p_note text default null)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'edit');
  v_from text := v_t.status;
begin
  perform private.enforce_write_limit('task_transition');
  if v_t.status not in ('open', 'in_progress') then
    raise exception 'this task is already closed' using errcode = 'invalid_parameter_value';
  end if;
  if char_length(p_note) > 2000 then
    raise exception 'note is too long' using errcode = 'invalid_parameter_value';
  end if;
  update public.tasks t
  set status = 'done', completed_at = now(),
      completed_by_person_id = public.current_person_id(t.organization_id),
      assigned_person_id = coalesce(t.assigned_person_id, public.current_person_id(t.organization_id))
  where t.id = v_t.id
  returning * into v_t;
  perform private.record_task_change(v_t, 'completed', v_from, nullif(btrim(p_note), ''));
end;
$$;

create or replace function public.reopen_task(p_task_id uuid, p_reason text default null)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'edit');
  v_from text := v_t.status;
begin
  perform private.enforce_write_limit('task_transition');
  if v_t.status not in ('done', 'cancelled') then
    raise exception 'only a closed task can be reopened' using errcode = 'invalid_parameter_value';
  end if;
  if v_t.status = 'cancelled' and not public.has_permission(v_t.organization_id, v_t.location_id, 'tasks', 'admin') then
    raise exception 'only a manager can reopen a cancelled task' using errcode = 'insufficient_privilege';
  end if;
  if char_length(p_reason) > 2000 then
    raise exception 'reason is too long' using errcode = 'invalid_parameter_value';
  end if;
  update public.tasks t
  set status = 'open', completed_at = null, completed_by_person_id = null, cancelled_at = null
  where t.id = v_t.id
  returning * into v_t;
  perform private.record_task_change(v_t, 'reopened', v_from, nullif(btrim(p_reason), ''));
end;
$$;

create or replace function public.assign_task(p_task_id uuid, p_person_id uuid, p_job_title_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'admin');
begin
  perform private.enforce_write_limit('task_transition');
  if v_t.status not in ('open', 'in_progress') then
    raise exception 'a closed task cannot be reassigned' using errcode = 'invalid_parameter_value';
  end if;
  if not private.valid_task_assignee(v_t.organization_id, v_t.location_id, p_person_id) then
    raise exception 'that person cannot be given tasks at this location' using errcode = 'invalid_parameter_value';
  end if;
  if p_job_title_id is not null and not exists (
       select 1 from public.job_titles j
       where j.id = p_job_title_id and j.organization_id = v_t.organization_id and j.archived_at is null) then
    raise exception 'unknown job title' using errcode = 'invalid_parameter_value';
  end if;
  if v_t.assigned_person_id is not distinct from p_person_id
     and v_t.assigned_job_title_id is not distinct from p_job_title_id then
    raise exception 'nothing to change' using errcode = 'invalid_parameter_value';
  end if;
  update public.tasks t
  set assigned_person_id = p_person_id, assigned_job_title_id = p_job_title_id
  where t.id = v_t.id
  returning * into v_t;
  perform private.record_task_change(v_t, 'assigned', v_t.status, null);
end;
$$;

create or replace function public.cancel_task(p_task_id uuid, p_reason text default null)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'admin');
  v_from text := v_t.status;
begin
  perform private.enforce_write_limit('task_transition');
  if v_t.status not in ('open', 'in_progress') then
    raise exception 'this task is already closed' using errcode = 'invalid_parameter_value';
  end if;
  if char_length(p_reason) > 2000 then
    raise exception 'reason is too long' using errcode = 'invalid_parameter_value';
  end if;
  update public.tasks t set status = 'cancelled', cancelled_at = now()
  where t.id = v_t.id
  returning * into v_t;
  perform private.record_task_change(v_t, 'cancelled', v_from, nullif(btrim(p_reason), ''));
end;
$$;

create or replace function public.add_task_comment(p_task_id uuid, p_body text)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'edit');
begin
  perform private.enforce_write_limit('task_comment');
  if p_body is null or char_length(btrim(p_body)) not between 1 and 2000 then
    raise exception 'a comment needs 1 to 2000 characters' using errcode = 'invalid_parameter_value';
  end if;
  return private.record_task_change(v_t, 'commented', v_t.status, btrim(p_body));
end;
$$;

-- R1 (root fix): no rule ever reacts to an event about a task that a rule
-- made, and none reacts to an event already at the depth limit (the task it
-- would create would be one step too deep). Same signature as 000300.
create or replace function public.match_workflow_rules(p_event_id uuid)
returns table (rule_id uuid, task_template_id uuid)
language sql
stable
security definer
set search_path = ''
as $$
  select r.id, r.task_template_id
  from public.outbox_events e
  join public.workflow_rules r on r.organization_id = e.organization_id and r.event_type = e.type
  join public.task_templates t on t.id = r.task_template_id and t.organization_id = r.organization_id
  where e.id = p_event_id
    and (select auth.uid()) is null
    and e.causation_depth < private.outbox_max_causation_depth()
    and not (e.entity_table = 'tasks' and exists (
               select 1 from public.tasks st
               where st.id = e.entity_id and st.organization_id = e.organization_id
                 and st.source_rule_id is not null))
    and r.enabled and r.archived_at is null and t.archived_at is null
    and (r.location_id is null or r.location_id = e.location_id)
    and (t.location_id is null or t.location_id = e.location_id)
    and e.location_id is not null
    and private.workflow_condition_matches(r.condition, e.payload)
  order by r.id
$$;

-- R2a, R1. Same signature as 000300. Round-robin by organization; the
-- task.overdue event's cause is the event that created the task (if any).
create or replace function public.emit_overdue_task_events(p_limit integer default 500)
returns integer
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype;
  v_n integer := 0;
begin
  perform private.assert_service_caller();
  if p_limit is null or p_limit not between 1 and 5000 then
    raise exception 'invalid limit' using errcode = 'invalid_parameter_value';
  end if;
  for v_t in
    select * from public.tasks t
    where t.id in (
        select r.id from (
          select x.id, x.due_at,
                 row_number() over (partition by x.organization_id order by x.due_at, x.id) as rn
          from public.tasks x
          where x.status in ('open', 'in_progress') and x.due_at < now()
            and x.overdue_emitted_for is distinct from x.due_at) r
        order by r.rn, r.due_at
        limit p_limit)
      and t.status in ('open', 'in_progress') and t.due_at < now()
      and t.overdue_emitted_for is distinct from t.due_at
    order by t.due_at
    for update skip locked
  loop
    update public.tasks t set overdue_emitted_for = t.due_at where t.id = v_t.id;
    perform private.emit_event(
      v_t.organization_id, v_t.location_id, 'task.overdue', 'tasks', v_t.id,
      jsonb_build_object(
        'task_id', v_t.id, 'location_id', v_t.location_id, 'due_at', v_t.due_at,
        'priority', v_t.priority, 'space_id', v_t.space_id,
        'assigned_person_id', v_t.assigned_person_id, 'assigned_job_title_id', v_t.assigned_job_title_id),
      1, null, null, v_t.source_event_id);
    v_n := v_n + 1;
  end loop;
  return v_n;
end;
$$;

-- R13: escalate an overdue task, once per task per due time. Takes the
-- task.overdue event being handled (same organization as the task). Records
-- one 'escalated' task_events row (system actor, source_event_id = the event)
-- and returns the people to notify: active members with tasks = admin at the
-- task's location. Only when the task is still open / in progress and past
-- that due time, and either nobody is assigned or the assignee has not acted
-- (no started / completed / reopened / commented row by them). Returns no one
-- otherwise. Idempotent: run again for the same event, it returns the same
-- people and writes nothing.
create function private.task_escalation_recipients(p_organization_id uuid, p_location_id uuid)
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.id from public.people p
  where p.organization_id = p_organization_id and p.archived_at is null
    and private.person_is_active_member(p_organization_id, p.id)
    and private.person_effective_level(p_organization_id, p.id, p_location_id, 'tasks') = 'admin'
  order by p.id
$$;
revoke all on function private.task_escalation_recipients(uuid, uuid) from public, anon, authenticated;

create function public.escalate_overdue_task(p_event_id uuid)
returns setof uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_e public.outbox_events%rowtype;
  v_t public.tasks%rowtype;
  v_due timestamptz;
begin
  perform private.assert_service_caller();
  select * into v_e from public.outbox_events e where e.id = p_event_id;
  if not found or v_e.type <> 'task.overdue' or v_e.entity_table <> 'tasks' then
    raise exception 'not a task.overdue event' using errcode = 'invalid_parameter_value';
  end if;
  select * into v_t from public.tasks t
  where t.id = v_e.entity_id and t.organization_id = v_e.organization_id
  for update;
  if not found then
    return;
  end if;
  if exists (select 1 from public.task_events te
             where te.task_id = v_t.id and te.organization_id = v_t.organization_id
               and te.kind = 'escalated' and te.source_event_id = v_e.id) then
    return query select r from private.task_escalation_recipients(v_t.organization_id, v_t.location_id) r;
    return;
  end if;
  begin
    v_due := (v_e.payload ->> 'due_at')::timestamptz;
  exception when others then
    v_due := null;
  end;
  if v_t.status not in ('open', 'in_progress') or v_t.due_at is null or v_t.due_at >= now()
     or v_due is distinct from v_t.due_at
     or v_t.escalated_for is not distinct from v_t.due_at then
    return;
  end if;
  if v_t.assigned_person_id is not null and exists (
       select 1 from public.task_events te
       where te.task_id = v_t.id and te.organization_id = v_t.organization_id
         and te.actor_person_id = v_t.assigned_person_id
         and te.kind in ('started', 'completed', 'reopened', 'commented')) then
    return;
  end if;
  update public.tasks t set escalated_for = t.due_at where t.id = v_t.id;
  insert into public.task_events (
    organization_id, location_id, task_id, kind, actor_person_id, from_status, to_status, source_event_id)
  values (v_t.organization_id, v_t.location_id, v_t.id, 'escalated', null, v_t.status, v_t.status, v_e.id);
  return query select r from private.task_escalation_recipients(v_t.organization_id, v_t.location_id) r;
end;
$$;
revoke all on function public.escalate_overdue_task(uuid) from public, anon, authenticated;
grant execute on function public.escalate_overdue_task(uuid) to service_role;

-- ===========================================================================
-- Communications: R2, R3, R9, R14, R16b
-- ===========================================================================

-- R3: message.sent carries the message id only. Same signature as 000400.
create or replace function public.send_message(p_organization_id uuid, p_recipient_person_ids uuid[], p_body text)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_recipients uuid[];
  v_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  v_me := public.current_person_id(p_organization_id);
  if v_me is null or not private.has_permission_anywhere(p_organization_id, 'communications', 'edit') then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('message_send');
  select coalesce(array_agg(distinct r), '{}') into v_recipients
  from unnest(coalesce(p_recipient_person_ids, '{}')) r where r is not null;
  if cardinality(v_recipients) not between 1 and 50 then
    raise exception 'choose 1 to 50 people' using errcode = 'invalid_parameter_value';
  end if;
  if p_body is null or char_length(btrim(p_body)) not between 1 and 4000 then
    raise exception 'a message needs 1 to 4000 characters' using errcode = 'invalid_parameter_value';
  end if;
  if v_me = any (v_recipients)
     or exists (
       select 1 from unnest(v_recipients) r
       where not exists (select 1 from public.people p
                         where p.id = r and p.organization_id = p_organization_id and p.archived_at is null)
          or r not in (select private.visible_person_ids())) then
    raise exception 'you cannot message one or more of these people' using errcode = 'insufficient_privilege';
  end if;

  insert into public.messages (organization_id, sender_person_id, body)
  values (p_organization_id, v_me, btrim(p_body))
  returning id into v_id;
  insert into public.message_recipients (organization_id, message_id, person_id)
  select p_organization_id, v_id, r from unnest(v_recipients) r;

  perform private.emit_event(
    p_organization_id, null, 'message.sent', 'messages', v_id,
    jsonb_build_object('message_id', v_id));
  return v_id;
end;
$$;

-- R9c, R2b, R2c, R16b. Same signature as 000400. Checks before locking;
-- validates every time before writing; per-person publish limits.
create or replace function public.publish_notice(p_notice_id uuid, p_publish_at timestamptz default null)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_n public.notices%rowtype;
  v_publish_at timestamptz;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_n from public.notices n where n.id = p_notice_id;
  if not found or not private.can_manage_notice(v_n.organization_id, v_n.location_id) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  select * into v_n from public.notices n where n.id = p_notice_id for update;
  if v_n.status <> 'draft' then
    raise exception 'only a draft can be published' using errcode = 'invalid_parameter_value';
  end if;
  if p_publish_at is not null and not isfinite(p_publish_at) then
    raise exception 'invalid publish time' using errcode = 'invalid_parameter_value';
  end if;
  if not exists (select 1 from public.notice_audiences a where a.notice_id = v_n.id) then
    raise exception 'choose who the notice is for first' using errcode = 'invalid_parameter_value';
  end if;
  v_publish_at := greatest(coalesce(p_publish_at, v_n.publish_at, now()), now());
  if v_n.expires_at is not null and v_n.expires_at <= v_publish_at then
    raise exception 'the notice would expire before it is shown' using errcode = 'invalid_parameter_value';
  end if;
  perform private.enforce_write_limit('notice_publish');
  if v_n.urgency = 'critical' then
    perform private.enforce_write_limit('notice_critical');
  end if;
  update public.notices n
  set status = 'published',
      publish_at = v_publish_at,
      published_at = now(),
      published_by_person_id = public.current_person_id(n.organization_id)
  where n.id = v_n.id
  returning * into v_n;
  perform private.emit_event(
    v_n.organization_id, v_n.location_id, 'notice.published', 'notices', v_n.id,
    jsonb_build_object('notice_id', v_n.id, 'location_id', v_n.location_id, 'urgency', v_n.urgency,
                       'requires_acknowledgment', v_n.requires_acknowledgment,
                       'publish_at', v_n.publish_at, 'expires_at', v_n.expires_at),
    1, null, v_n.publish_at);
end;
$$;

-- R9c. Same signature as 000400.
create or replace function public.archive_notice(p_notice_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_n public.notices%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_n from public.notices n where n.id = p_notice_id;
  if not found or not private.can_manage_notice(v_n.organization_id, v_n.location_id) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  select * into v_n from public.notices n where n.id = p_notice_id for update;
  if v_n.status = 'archived' then
    raise exception 'this notice is already archived' using errcode = 'invalid_parameter_value';
  end if;
  update public.notices n
  set status = 'archived', archived_at = now()
  where n.id = v_n.id;
  perform private.emit_event(
    v_n.organization_id, v_n.location_id, 'notice.archived', 'notices', v_n.id,
    jsonb_build_object('notice_id', v_n.id, 'location_id', v_n.location_id));
end;
$$;

-- R14: who acknowledged. Audience members (active, in the audience now) plus
-- anyone who acknowledged, limited to people the caller can see; null
-- acknowledged_at = not yet. Only for someone who manages the notice (42501
-- 'not allowed' otherwise, also for a notice that does not exist).
create function public.notice_acknowledgment_status(p_notice_id uuid)
returns table (person_id uuid, acknowledged_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
  v_n public.notices%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_n from public.notices n where n.id = p_notice_id;
  if not found or private.can_manage_notice(v_n.organization_id, v_n.location_id) is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  return query
  with people_in as (
    select p.id
    from public.people p
    where p.organization_id = v_n.organization_id and p.archived_at is null
      and private.person_is_active_member(v_n.organization_id, p.id)
      and private.person_in_notice_audience(v_n.id, p.id)
    union
    select a.person_id from public.acknowledgments a where a.notice_id = v_n.id
  )
  select pi.id, ack.acknowledged_at
  from people_in pi
  left join public.acknowledgments ack on ack.notice_id = v_n.id and ack.person_id = pi.id
  where public.is_platform_admin() or pi.id in (select private.visible_person_ids())
  order by ack.acknowledged_at nulls first, pi.id;
end;
$$;

-- R14: the notices addressed to the caller (published, live, caller in the
-- audience), newest first, optionally for one organization; at most 200.
-- Security definer with the audience read rule applied explicitly (the
-- same private.can_read_notice_as_audience the notices policy uses), so a
-- manager sees only what is addressed to them here.
create function public.my_notices(p_organization_id uuid default null, p_limit integer default 50)
returns table (
  notice_id uuid, organization_id uuid, location_id uuid, title text, body text, urgency text,
  requires_acknowledgment boolean, publish_at timestamptz, expires_at timestamptz, acknowledged_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select n.id, n.organization_id, n.location_id, n.title, n.body, n.urgency,
         n.requires_acknowledgment, n.publish_at, n.expires_at, a.acknowledged_at
  from public.notices n
  left join public.acknowledgments a
    on a.notice_id = n.id and a.person_id = public.current_person_id(n.organization_id)
  where (p_organization_id is null or n.organization_id = p_organization_id)
    and n.organization_id in (select m.organization_id from private.my_assignments() m)
    and private.can_read_notice_as_audience(n.id, n.status, n.publish_at, n.expires_at)
  order by n.publish_at desc, n.id
  limit least(greatest(coalesce(p_limit, 50), 1), 200)
$$;

revoke all on function public.notice_acknowledgment_status(uuid), public.my_notices(uuid, integer)
  from public, anon, authenticated;
grant execute on function public.notice_acknowledgment_status(uuid), public.my_notices(uuid, integer)
  to authenticated, service_role;

-- ===========================================================================
-- Notifications: R5, R6, R9a, R10, R11
-- ===========================================================================

-- R5: the single definition of where push may go. https only, no userinfo,
-- port 443 or none, host one of:
--   fcm.googleapis.com, updates.push.services.mozilla.com,
--   *.push.apple.com, *.notify.windows.com
create function private.push_endpoint_allowed(p_endpoint text)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select coalesce(
    char_length(p_endpoint) <= 2000
    and p_endpoint ~ '^https://[^/?#@:\s]+(:443)?/[^\s]*$'
    and (lower(substring(p_endpoint from '^https://([^/?#@:\s]+)')) in ('fcm.googleapis.com', 'updates.push.services.mozilla.com')
         or lower(substring(p_endpoint from '^https://([^/?#@:\s]+)')) ~ '^([a-z0-9-]+\.)+push\.apple\.com$'
         or lower(substring(p_endpoint from '^https://([^/?#@:\s]+)')) ~ '^([a-z0-9-]+\.)+notify\.windows\.com$'),
    false)
$$;
revoke all on function private.push_endpoint_allowed(text) from public, anon, authenticated;
grant execute on function private.push_endpoint_allowed(text) to authenticated, service_role;

-- Rows that could never be delivered are removed before the check is added
-- (pilot data is mock only).
delete from public.push_subscriptions s where not private.push_endpoint_allowed(s.endpoint);
alter table public.push_subscriptions
  add constraint push_subscriptions_endpoint_allowed check (private.push_endpoint_allowed(endpoint));

-- R5, R2b. Same signature as 000500. Allowlisted endpoints only; one person
-- per endpoint (saving removes every other person's row for that endpoint,
-- in any organization, without saying whether there was one); at most
-- max_push_subscriptions_per_person() per person (saving a new endpoint
-- beyond that removes the least recently saved).
create or replace function public.save_push_subscription(
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
  perform private.enforce_write_limit('push_save');
  if p_endpoint is null or not private.push_endpoint_allowed(p_endpoint) then
    raise exception 'this push service is not supported' using errcode = 'invalid_parameter_value';
  end if;
  perform pg_advisory_xact_lock(hashtextextended('push_subscriptions:' || v_me::text, 0));
  if not exists (select 1 from public.push_subscriptions s where s.person_id = v_me and s.endpoint = p_endpoint) then
    delete from public.push_subscriptions s
    where s.id in (select s2.id from public.push_subscriptions s2
                   where s2.person_id = v_me
                   order by s2.updated_at desc, s2.id desc
                   offset private.max_push_subscriptions_per_person() - 1);
  end if;
  with gone as (
    delete from public.push_subscriptions s where s.endpoint = p_endpoint and s.person_id <> v_me
  )
  insert into public.push_subscriptions as s (organization_id, person_id, endpoint, p256dh, auth_secret, user_agent)
  values (p_organization_id, v_me, p_endpoint, p_p256dh, p_auth_secret, left(p_user_agent, 300))
  on conflict (person_id, endpoint) do update
    set p256dh = excluded.p256dh, auth_secret = excluded.auth_secret,
        user_agent = excluded.user_agent, disabled_at = null
  returning s.id into v_id;
  return v_id;
end;
$$;

-- R6: fan-out only for a notice that is published and live. Same signature.
create or replace function public.notice_audience_person_ids(p_notice_id uuid)
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
    and n.status = 'published' and n.publish_at <= now()
    and (n.expires_at is null or n.expires_at > now())
    and private.person_is_active_member(n.organization_id, p.id)
    and private.person_in_notice_audience(n.id, p.id)
  order by p.id
$$;

-- R9a: archived job titles route nothing. Same signature.
create or replace function public.task_recipient_person_ids(p_task_id uuid)
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
               join public.job_titles jt on jt.id = pjt.job_title_id and jt.organization_id = pjt.organization_id
               where pjt.person_id = p.id and pjt.job_title_id = t.assigned_job_title_id
                 and jt.archived_at is null
                 and (pjt.location_id is null or pjt.location_id = t.location_id))))
$$;

-- R10: batch create_notification. Same rules per person (idempotent on
-- (event, person, kind); inactive people are skipped). Returns how many of
-- the given people now have this notification (new or already there).
-- 1-10000 distinct people per call.
create function public.create_notifications(
  p_event_id uuid,
  p_person_ids uuid[],
  p_kind text,
  p_title text,
  p_summary text default null,
  p_link text default null,
  p_urgency text default null)
returns integer
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_person uuid;
  v_n integer := 0;
begin
  perform private.assert_service_caller();
  if cardinality(p_person_ids) is null or cardinality(p_person_ids) > 10000 then
    raise exception 'give 1 to 10000 people' using errcode = 'invalid_parameter_value';
  end if;
  for v_person in select distinct x from unnest(p_person_ids) x where x is not null order by 1 loop
    if public.create_notification(p_event_id, v_person, p_kind, p_title, p_summary, p_link, p_urgency) is not null then
      v_n := v_n + 1;
    end if;
  end loop;
  return v_n;
end;
$$;

-- R11: worker read functions. Each takes the event or delivery being
-- handled, joins only rows of that same organization, refuses a user JWT,
-- and returns nothing for a mismatch.

create function public.worker_task_for_event(p_event_id uuid)
returns table (task_id uuid, organization_id uuid, location_id uuid, location_name text, title text,
               status text, priority text, due_at timestamptz, assigned_person_id uuid, assigned_job_title_id uuid)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
  perform private.assert_service_caller();
  return query
  select t.id, t.organization_id, t.location_id, l.name, t.title, t.status, t.priority, t.due_at,
         t.assigned_person_id, t.assigned_job_title_id
  from public.outbox_events e
  join public.tasks t on t.id = e.entity_id and t.organization_id = e.organization_id
  join public.locations l on l.id = t.location_id and l.organization_id = t.organization_id
  where e.id = p_event_id and e.entity_table = 'tasks';
end;
$$;

create function public.worker_notice_for_event(p_event_id uuid)
returns table (notice_id uuid, organization_id uuid, location_id uuid, title text, status text, urgency text,
               requires_acknowledgment boolean, publish_at timestamptz, expires_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
  perform private.assert_service_caller();
  return query
  select n.id, n.organization_id, n.location_id, n.title, n.status, n.urgency,
         n.requires_acknowledgment, n.publish_at, n.expires_at
  from public.outbox_events e
  join public.notices n on n.id = e.entity_id and n.organization_id = e.organization_id
  where e.id = p_event_id and e.entity_table = 'notices';
end;
$$;

create function public.worker_notification_for_delivery(p_delivery_id uuid)
returns table (delivery_id uuid, notification_id uuid, organization_id uuid, person_id uuid, channel text,
               status text, attempts integer, kind text, title text, body text, link_path text, urgency text)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
  perform private.assert_service_caller();
  return query
  select d.id, n.id, n.organization_id, n.person_id, d.channel, d.status, d.attempts,
         n.kind, n.title, n.body, n.link_path, n.urgency
  from public.notification_deliveries d
  join public.notifications n on n.id = d.notification_id and n.organization_id = d.organization_id
                             and n.person_id = d.person_id
  where d.id = p_delivery_id;
end;
$$;

-- The verified login email of the delivery's person: auth.users.email of
-- their active account in that organization, only when the address is
-- confirmed. Never people.email. Null when there is no such login.
create function public.worker_email_for_delivery(p_delivery_id uuid)
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
    and u.email is not null and u.email_confirmed_at is not null;
  return v_email;
end;
$$;

create function public.worker_push_subscriptions_for_delivery(p_delivery_id uuid)
returns table (subscription_id uuid, endpoint text, p256dh text, auth_secret text)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
  perform private.assert_service_caller();
  return query
  select s.id, s.endpoint, s.p256dh, s.auth_secret
  from public.notification_deliveries d
  join public.push_subscriptions s on s.person_id = d.person_id and s.organization_id = d.organization_id
  where d.id = p_delivery_id and d.channel = 'push'
    and s.disabled_at is null and private.push_endpoint_allowed(s.endpoint)
  order by s.updated_at desc, s.id;
end;
$$;

revoke all on function
  public.create_notifications(uuid, uuid[], text, text, text, text, text),
  public.worker_task_for_event(uuid),
  public.worker_notice_for_event(uuid),
  public.worker_notification_for_delivery(uuid),
  public.worker_email_for_delivery(uuid),
  public.worker_push_subscriptions_for_delivery(uuid)
from public, anon, authenticated;
grant execute on function
  public.create_notifications(uuid, uuid[], text, text, text, text, text),
  public.worker_task_for_event(uuid),
  public.worker_notice_for_event(uuid),
  public.worker_notification_for_delivery(uuid),
  public.worker_email_for_delivery(uuid),
  public.worker_push_subscriptions_for_delivery(uuid)
to service_role;

-- ===========================================================================
-- R15: may the caller resend this person's invite?
-- ===========================================================================
-- Same tier rule as can_manage_person_account; true only when the person has
-- an active account whose auth user has never confirmed an address and never
-- signed in. False (never an error) for anything else.
create function public.can_resend_person_invite(p_organization_id uuid, p_person_id uuid)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_user uuid;
begin
  if (select auth.uid()) is null or p_organization_id is null or p_person_id is null then
    return false;
  end if;
  if not exists (select 1 from public.people p
                 where p.id = p_person_id and p.organization_id = p_organization_id and p.archived_at is null) then
    return false;
  end if;
  if not (public.is_platform_admin() or p_person_id in (select private.visible_person_ids())) then
    return false;
  end if;
  select a.user_id into v_user from public.accounts a
  where a.person_id = p_person_id and a.organization_id = p_organization_id and a.disabled_at is null;
  if v_user is null then
    return false;
  end if;
  if not exists (select 1 from auth.users u
                 where u.id = v_user and u.email_confirmed_at is null and u.last_sign_in_at is null) then
    return false;
  end if;
  return coalesce(private.can_manage_person(p_organization_id, p_person_id), false);
end;
$$;
revoke all on function public.can_resend_person_invite(uuid, uuid) from public, anon, authenticated;
grant execute on function public.can_resend_person_invite(uuid, uuid) to authenticated, service_role;
