-- Phase 2 / auth hardening: consume_rate_limit (service_role only; fixed window; keys stored only as an HMAC),
-- the invite pre-check can_manage_person_account (full truth table), and the guard that every function
-- documented as service_role-only is out of reach for authenticated and anon and refuses a caller that
-- carries a user JWT.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(233);

-- BEGIN SHARED FIXTURE: byte-identical in every fixture-using test file (check: see supabase/tests/database/000_catalog_guards.test.sql header notes).
--   org A: locations A1, A2;  org B: location B1.
--   users: u_orgadmin_a (org-scope admin A), u_locadmin_a1 (admin @A1), u_manager_a1, u_staff_a1,
--          u_staff_a2 (staff @A2), u_orgadmin_b, u_platform (platform admin, no account),
--          u_noaccount (signed in, no account), u_disabled_a (disabled account, staff @A1).
--          u_staff_b1 (staff @B1).
--   person without an account: p_unassigned_a (no assignment).
-- Ids are fixed: pg_temp.id('name') is md5 of the name. Nothing here depends on seed.sql or on other files.
-- pgTAP runs while impersonating anon/authenticated. The real Supabase stack already allows that;
-- the plain-Postgres stand-in (scripts/db/test-local.sh) creates pgTAP after its shim, so grant here.
-- Rolled back with the rest of the transaction.
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
create function pg_temp.id(p_name text) returns uuid language sql immutable
as $$ select md5('rec-reports-test-fixture:' || p_name)::uuid $$;
grant execute on function pg_temp.id(text) to public;

create function pg_temp.sys_role(p_key text) returns uuid language sql stable security definer set search_path = ''
as $$ select id from public.roles where organization_id is null and key = p_key $$;
grant execute on function pg_temp.sys_role(text) to public;

-- Switch identity: act_as('u_staff_a1') = authenticated with that user's JWT at assurance level aal2
-- (a verified second factor, which the admin tier needs); act_as('u_orgadmin_a', 'aal1') = first factor
-- only; act_as('u_orgadmin_a', 'none') = a JWT with no aal claim (counts as aal1);
-- act_as('anon'); act_as('service_role') = the server key (no user); act_as('postgres') (or null) goes back to the owner.
-- act_as_service('u_staff_a1') = a service_role connection that carries a USER's JWT (what the worker functions must refuse).
create function pg_temp.act_as(p_who text, p_aal text default 'aal2') returns void language plpgsql as $$
begin
  if p_who is null or p_who = 'postgres' then
    perform set_config('role', 'none', true);
    perform set_config('request.jwt.claims', '', true);
  elsif p_who = 'service_role' then
    perform set_config('role', 'none', true); perform set_config('request.jwt.claims', '{"role":"service_role"}', true);
    perform set_config('role', 'service_role', true);
  elsif p_who = 'anon' then
    perform set_config('role', 'none', true);
    perform set_config('request.jwt.claims', '{"role":"anon"}', true);
    perform set_config('role', 'anon', true);
  else
    perform set_config('role', 'none', true);
    perform set_config('request.jwt.claims',
      (jsonb_build_object('sub', pg_temp.id(p_who), 'role', 'authenticated')
        || case when p_aal = 'none' then '{}'::jsonb else jsonb_build_object('aal', p_aal) end)::text, true);
    perform set_config('role', 'authenticated', true);
  end if;
end $$;
grant execute on function pg_temp.act_as(text, text) to public;
create function pg_temp.act_as_service(p_who text) returns void language plpgsql as $$
begin
  perform set_config('role', 'none', true);
  perform set_config('request.jwt.claims',
    jsonb_build_object('sub', pg_temp.id(p_who), 'role', 'service_role', 'aal', 'aal2')::text, true);
  perform set_config('role', 'service_role', true);
end $$;
grant execute on function pg_temp.act_as_service(text) to public;

-- Generic probes, all SECURITY INVOKER so RLS and grants apply to the current role.
-- cnt: rows visible in public.<table> matching a where clause; -1 if the role has no privilege.
create function pg_temp.cnt(p_table text, p_where text default 'true') returns bigint language plpgsql as $$
declare n bigint;
begin
  execute format('select count(*) from public.%I where %s', p_table, p_where) into n;
  return n;
exception when insufficient_privilege then return -1;
end $$;
-- affected: rows changed by an UPDATE/DELETE statement; -1 if the role has no privilege.
create function pg_temp.affected(p_sql text) returns bigint language plpgsql as $$
declare n bigint;
begin
  execute p_sql;
  get diagnostics n = row_count;
  return n;
exception when insufficient_privilege then return -1;
end $$;
-- try: 'ok' if the statement ran, else the SQLSTATE it failed with.
create function pg_temp.try(p_sql text) returns text language plpgsql as $$
begin
  execute p_sql;
  return 'ok';
exception when others then return sqlstate;
end $$;
grant execute on function pg_temp.cnt(text, text), pg_temp.affected(text), pg_temp.try(text) to public;

insert into auth.users (id, email) values
  (pg_temp.id('u_orgadmin_a'),  'orgadmin-a@test.invalid'),
  (pg_temp.id('u_locadmin_a1'), 'locadmin-a1@test.invalid'),
  (pg_temp.id('u_manager_a1'),  'manager-a1@test.invalid'),
  (pg_temp.id('u_staff_a1'),    'staff-a1@test.invalid'),
  (pg_temp.id('u_staff_a2'),    'staff-a2@test.invalid'),
  (pg_temp.id('u_orgadmin_b'),  'orgadmin-b@test.invalid'),
  (pg_temp.id('u_platform'),    'platform@test.invalid'),
  (pg_temp.id('u_noaccount'),   'noaccount@test.invalid'),
  (pg_temp.id('u_disabled_a'),  'disabled-a@test.invalid'),
  (pg_temp.id('u_staff_b1'),    'staff-b1@test.invalid');
insert into public.platform_admins (user_id, note) values (pg_temp.id('u_platform'), 'test fixture');

insert into public.organizations (id, name, slug) values
  (pg_temp.id('org_a'), 'Test Org A', 'test-org-a'), (pg_temp.id('org_b'), 'Test Org B', 'test-org-b');
insert into public.locations (id, organization_id, name, code, timezone) values
  (pg_temp.id('loc_a1'), pg_temp.id('org_a'), 'A1 Arena',  'A1', 'America/New_York'),
  (pg_temp.id('loc_a2'), pg_temp.id('org_a'), 'A2 Centre', 'A2', 'America/Chicago'),
  (pg_temp.id('loc_b1'), pg_temp.id('org_b'), 'B1 Pool',   'B1', 'America/Denver');
insert into public.job_titles (id, organization_id, name) values
  (pg_temp.id('jt_a'), pg_temp.id('org_a'), 'Lifeguard'), (pg_temp.id('jt_b'), pg_temp.id('org_b'), 'Lifeguard');
insert into public.roles (id, organization_id, key, name, rank) values
  (pg_temp.id('role_custom_a'), pg_temp.id('org_a'), 'lead', 'Lead', 30),
  (pg_temp.id('role_custom_b'), pg_temp.id('org_b'), 'lead', 'Lead', 30);
insert into public.role_default_permissions (id, role_id, module_key, level) values
  (pg_temp.id('rdp_a'), pg_temp.id('role_custom_a'), 'tasks', 'edit'),
  (pg_temp.id('rdp_b'), pg_temp.id('role_custom_b'), 'tasks', 'edit');

insert into public.spaces (id, organization_id, location_id, space_kind_id, name)
select pg_temp.id(v.sp), pg_temp.id(v.org), pg_temp.id(v.loc), k.id, v.nm
from (values ('space_a1', 'org_a', 'loc_a1', 'A1 Main Pool'), ('space_a2', 'org_a', 'loc_a2', 'A2 Gym'),
             ('space_b1', 'org_b', 'loc_b1', 'B1 Pool')) v (sp, org, loc, nm)
join public.space_kinds k on k.organization_id = pg_temp.id(v.org) and k.key = 'pool';
insert into public.spaces (id, organization_id, location_id, space_kind_id, parent_space_id, name)
select pg_temp.id('space_a1_lane'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), k.id, pg_temp.id('space_a1'), 'A1 Lane 1'
from public.space_kinds k where k.organization_id = pg_temp.id('org_a') and k.key = 'pool';
insert into public.space_hours (id, organization_id, location_id, space_id, day_of_week, opens_at, closes_at) values
  (pg_temp.id('hours_a1'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 1, '06:00', '22:00'),
  (pg_temp.id('hours_a2'), pg_temp.id('org_a'), pg_temp.id('loc_a2'), pg_temp.id('space_a2'), 1, '06:00', '22:00'),
  (pg_temp.id('hours_b1'), pg_temp.id('org_b'), pg_temp.id('loc_b1'), pg_temp.id('space_b1'), 1, '06:00', '22:00');
insert into public.space_closures (id, organization_id, location_id, space_id, starts_at, ends_at) values
  (pg_temp.id('closure_a1'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), '2030-01-01', '2030-01-02'),
  (pg_temp.id('closure_a2'), pg_temp.id('org_a'), pg_temp.id('loc_a2'), null,                   '2030-01-01', '2030-01-02'),
  (pg_temp.id('closure_b1'), pg_temp.id('org_b'), pg_temp.id('loc_b1'), pg_temp.id('space_b1'), '2030-01-01', '2030-01-02');

insert into public.people (id, organization_id, first_name, last_name) values
  (pg_temp.id('p_orgadmin_a'),  pg_temp.id('org_a'), 'Olive',  'OrgAdminA'),
  (pg_temp.id('p_locadmin_a1'), pg_temp.id('org_a'), 'Lou',    'LocAdminA1'),
  (pg_temp.id('p_manager_a1'),  pg_temp.id('org_a'), 'Mia',    'ManagerA1'),
  (pg_temp.id('p_staff_a1'),    pg_temp.id('org_a'), 'Sam',    'StaffA1'),
  (pg_temp.id('p_staff_a2'),    pg_temp.id('org_a'), 'Sue',    'StaffA2'),
  (pg_temp.id('p_disabled_a'),  pg_temp.id('org_a'), 'Dan',    'DisabledA'),
  (pg_temp.id('p_unassigned_a'),pg_temp.id('org_a'), 'Una',    'UnassignedA'),
  (pg_temp.id('p_orgadmin_b'),  pg_temp.id('org_b'), 'Bea',    'OrgAdminB'),
  (pg_temp.id('p_staff_b1'),    pg_temp.id('org_b'), 'Bo',     'StaffB1');
insert into public.accounts (id, organization_id, person_id, user_id, disabled_at)
select pg_temp.id('acct_' || v.k), pg_temp.id(v.org), pg_temp.id('p_' || v.k), pg_temp.id('u_' || v.k),
       case when v.k = 'disabled_a' then now() end
from (values ('orgadmin_a', 'org_a'), ('locadmin_a1', 'org_a'), ('manager_a1', 'org_a'), ('staff_a1', 'org_a'),
             ('staff_a2', 'org_a'), ('disabled_a', 'org_a'), ('orgadmin_b', 'org_b'), ('staff_b1', 'org_b')) v (k, org);
insert into public.role_assignments (id, organization_id, person_id, role_id, location_id) values
  (pg_temp.id('ra_orgadmin_a'),  pg_temp.id('org_a'), pg_temp.id('p_orgadmin_a'),  pg_temp.sys_role('admin'),   null),
  (pg_temp.id('ra_locadmin_a1'), pg_temp.id('org_a'), pg_temp.id('p_locadmin_a1'), pg_temp.sys_role('admin'),   pg_temp.id('loc_a1')),
  (pg_temp.id('ra_manager_a1'),  pg_temp.id('org_a'), pg_temp.id('p_manager_a1'),  pg_temp.sys_role('manager'), pg_temp.id('loc_a1')),
  (pg_temp.id('ra_staff_a1'),    pg_temp.id('org_a'), pg_temp.id('p_staff_a1'),    pg_temp.sys_role('staff'),   pg_temp.id('loc_a1')),
  (pg_temp.id('ra_staff_a2'),    pg_temp.id('org_a'), pg_temp.id('p_staff_a2'),    pg_temp.sys_role('staff'),   pg_temp.id('loc_a2')),
  (pg_temp.id('ra_disabled_a'),  pg_temp.id('org_a'), pg_temp.id('p_disabled_a'),  pg_temp.sys_role('staff'),   pg_temp.id('loc_a1')),
  (pg_temp.id('ra_orgadmin_b'),  pg_temp.id('org_b'), pg_temp.id('p_orgadmin_b'),  pg_temp.sys_role('admin'),   null),
  (pg_temp.id('ra_staff_b1'),    pg_temp.id('org_b'), pg_temp.id('p_staff_b1'),    pg_temp.sys_role('staff'),   pg_temp.id('loc_b1'));
insert into public.user_permissions (id, organization_id, person_id, location_id, module_key, level) values
  (pg_temp.id('up_a'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), null, 'reports', 'view'),
  (pg_temp.id('up_b'), pg_temp.id('org_b'), pg_temp.id('p_staff_b1'), null, 'reports', 'view');
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id) values
  (pg_temp.id('pjt_a'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('jt_a'), null),
  (pg_temp.id('pjt_b'), pg_temp.id('org_b'), pg_temp.id('p_staff_b1'), pg_temp.id('jt_b'), null);
-- END SHARED FIXTURE

-- BEGIN PHASE 2 ROWS: byte-identical in every file that uses it (020, 050).
-- Phase 2 rows: one row in each of the 15 Phase 2 tables, in both organizations, written
-- with the owner's rights because the API roles cannot write most of them (and they are what the
-- generated tests below are about). Org A: staff A1 sends a message to manager A1 and owns the
-- notification, push subscription and preference. Org B: staff B1 sends to staff B2 (a person with no
-- login), so org admin B is neither sender nor recipient.
insert into public.people (id, organization_id, first_name, last_name) values
  (pg_temp.id('p_staff_b2'), pg_temp.id('org_b'), 'Bao', 'StaffB2');
insert into public.outbox_events (id, organization_id, location_id, type, entity_table, entity_id, correlation_id, payload)
select pg_temp.id('ev_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), 'task.created', 'tasks', pg_temp.id('task_' || v.k),
       pg_temp.id('ev_' || v.k), jsonb_build_object('task_id', pg_temp.id('task_' || v.k))
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.outbox_event_handlers (event_id, handler, organization_id)
select pg_temp.id('ev_' || v.k), 'tasks', pg_temp.id(v.org) from (values ('a', 'org_a'), ('b', 'org_b')) v (k, org);
insert into public.task_templates (id, organization_id, location_id, title)
select pg_temp.id('tpl_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), 'Template ' || v.k
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.workflow_rules (id, organization_id, location_id, name, event_type, task_template_id)
select pg_temp.id('rule_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), 'Rule ' || v.k, 'booking.confirmed', pg_temp.id('tpl_' || v.k)
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.tasks (id, organization_id, location_id, title, assigned_person_id)
select pg_temp.id('task_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), 'Task ' || v.k, pg_temp.id(v.person)
from (values ('a', 'org_a', 'loc_a1', 'p_staff_a1'), ('b', 'org_b', 'loc_b1', 'p_staff_b1')) v (k, org, loc, person);
insert into public.task_events (organization_id, location_id, task_id, kind)
select pg_temp.id(v.org), pg_temp.id(v.loc), pg_temp.id('task_' || v.k), 'created'
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.notices (id, organization_id, location_id, title, body)
select pg_temp.id('notice_' || v.k), pg_temp.id(v.org), null, 'Notice ' || v.k, 'Body ' || v.k
from (values ('a', 'org_a'), ('b', 'org_b')) v (k, org);
insert into public.notice_audiences (id, organization_id, notice_id)
select pg_temp.id('aud_' || v.k), pg_temp.id(v.org), pg_temp.id('notice_' || v.k) from (values ('a', 'org_a'), ('b', 'org_b')) v (k, org);
insert into public.acknowledgments (organization_id, notice_id, person_id)
select pg_temp.id(v.org), pg_temp.id('notice_' || v.k), pg_temp.id(v.person)
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, person);
insert into public.messages (id, organization_id, sender_person_id, body)
select pg_temp.id('msg_' || v.k), pg_temp.id(v.org), pg_temp.id(v.sender), 'Private body ' || v.k
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, sender);
insert into public.message_recipients (organization_id, message_id, person_id)
select pg_temp.id(v.org), pg_temp.id('msg_' || v.k), pg_temp.id(v.rcpt)
from (values ('a', 'org_a', 'p_manager_a1'), ('b', 'org_b', 'p_staff_b2')) v (k, org, rcpt);
insert into public.notifications (id, organization_id, person_id, kind, title, source_event_id)
select pg_temp.id('notif_' || v.k), pg_temp.id(v.org), pg_temp.id(v.person), 'task.created', 'Notification ' || v.k, pg_temp.id('ev_' || v.k)
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, person);
insert into public.notification_deliveries (organization_id, notification_id, person_id, channel, status, sent_at)
select pg_temp.id(v.org), pg_temp.id('notif_' || v.k), pg_temp.id(v.person), 'in_app', 'sent', now()
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, person);
insert into public.push_subscriptions (organization_id, person_id, endpoint, p256dh, auth_secret)
select pg_temp.id(v.org), pg_temp.id(v.person), 'https://push.example.test/' || v.k, 'BPfixturefixturefixturefixture' || v.k, 'fixtureauth' || v.k
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, person);
insert into public.notification_preferences (organization_id, person_id, channel, enabled)
select pg_temp.id(v.org), pg_temp.id(v.person), 'email', false from (values ('org_a', 'p_staff_a1'), ('org_b', 'p_staff_b1')) v (org, person);

-- END PHASE 2 ROWS

create function pg_temp.val(p_expr text) returns text language plpgsql as $$
declare v text;
begin
  execute 'select (' || p_expr || ')::text' into v;
  return coalesce(v, 'null');
exception when others then return 'ERR ' || sqlstate;
end $$;
grant execute on function pg_temp.val(text) to public;

-- ===========================================================================
-- consume_rate_limit
-- ===========================================================================
select pg_temp.act_as('service_role');
select is(pg_temp.val($$public.consume_rate_limit('signin', 'Victim@Example.com', 3, 60)$$), 'true', 'rate limit: call 1 of 3 is allowed');
select is(pg_temp.val($$public.consume_rate_limit('signin', 'victim@example.com', 3, 60)$$), 'true', 'rate limit: call 2 of 3 is allowed (the key is case-insensitive)');
select is(pg_temp.val($$public.consume_rate_limit('signin', '  victim@example.com  ', 3, 60)$$), 'true', 'rate limit: call 3 of 3 is allowed (the key is trimmed)');
select is(pg_temp.val($$public.consume_rate_limit('signin', 'victim@example.com', 3, 60)$$), 'false', 'rate limit: call 4 is refused');
select is(pg_temp.val($$public.consume_rate_limit('signin', 'victim@example.com', 3, 60)$$), 'false', 'rate limit: call 5 is still refused');
select is(pg_temp.val($$public.consume_rate_limit('signin', 'other@example.com', 3, 60)$$), 'true', 'rate limit: another key has its own count');
select is(pg_temp.val($$public.consume_rate_limit('reset', 'victim@example.com', 3, 60)$$), 'true', 'rate limit: another bucket has its own count');
select is(pg_temp.val($$public.consume_rate_limit('signin', 'victim@example.com', 4, 60)$$), 'false', 'rate limit: a different max on the same key and window sees the same 5 hits, so 4 is still exceeded');
select is(pg_temp.val($$public.consume_rate_limit('onceonly', 'k', 1, 60)$$), 'true', 'rate limit: a limit of 1 allows the first hit');
select is(pg_temp.val($$public.consume_rate_limit('onceonly', 'k', 1, 60)$$), 'false', 'rate limit: and refuses the second');
select pg_temp.act_as('postgres');
select is((select hits from private.rate_limit_counters where bucket = 'signin' and key_hash = extensions.hmac(convert_to('signin', 'UTF8') || '\x00'::bytea || convert_to('victim@example.com', 'UTF8'), (select secret from private.rate_limit_secret), 'sha256')),
  6, 'rate limit: the counter holds every hit (6) under the HMAC of bucket + 0x00 + lower(trim(key))');
select is((select count(*) from private.rate_limit_counters where bucket = 'signin'), 2::bigint, 'rate limit: one row per key per window (two keys in signin)');
select ok((select bool_and(window_start <= now() and now() < window_end and window_end - window_start = interval '60 seconds') from private.rate_limit_counters where bucket = 'signin'),
  'rate limit: the window is the 60-second fixed window containing now');
select ok((select bool_and(window_start = to_timestamp(floor(extract(epoch from window_start) / 60) * 60)) from private.rate_limit_counters where bucket = 'signin'),
  'rate limit: windows are aligned to multiples of the window length');
-- no plain key anywhere
select is((select count(*) from private.rate_limit_counters c where c::text ilike '%victim%' or c::text ilike '%example.com%' or c::text ilike '%other@%'), 0::bigint,
  'rate limit: no counter row contains the key in clear');
select is((select count(*) from private.rate_limit_secret s where s::text ilike '%victim%'), 0::bigint, 'rate limit: the secret row does not contain the key either');
select is((select count(*) from private.rate_limit_counters where octet_length(key_hash) <> 32), 0::bigint, 'rate limit: every stored hash is 32 bytes (SHA-256)');
select is((select octet_length(secret) from private.rate_limit_secret), 32, 'rate limit: the per-database secret is 32 bytes');
select is((select count(*) from private.rate_limit_secret), 1::bigint, 'rate limit: exactly one secret row');
select is((select count(distinct key_hash) from private.rate_limit_counters where bucket in ('signin', 'reset')), 3::bigint,
  'rate limit: the same key in two buckets hashes differently (3 distinct hashes for 3 bucket/key pairs)');
select is((select count(*) from private.rate_limit_counters where key_hash = convert_to('victim@example.com', 'UTF8')), 0::bigint, 'rate limit: the hash is not just the key bytes');
-- an expired window starts again at 1, and the old row of that key is removed
update private.rate_limit_counters set window_start = window_start - interval '1 hour', window_end = window_end - interval '1 hour'
  where bucket = 'signin';
select pg_temp.act_as('service_role');
select is(pg_temp.val($$public.consume_rate_limit('signin', 'victim@example.com', 3, 60)$$), 'true', 'rate limit: after the window ended the key is allowed again');
select pg_temp.act_as('postgres');
select is((select count(*) from private.rate_limit_counters where bucket = 'signin' and key_hash = extensions.hmac(convert_to('signin', 'UTF8') || '\x00'::bytea || convert_to('victim@example.com', 'UTF8'), (select secret from private.rate_limit_secret), 'sha256')),
  1::bigint, 'rate limit: the expired row of that key was dropped, one fresh row remains');
select is((select hits from private.rate_limit_counters where bucket = 'signin' and window_end > now() and key_hash = extensions.hmac(convert_to('signin', 'UTF8') || '\x00'::bytea || convert_to('victim@example.com', 'UTF8'), (select secret from private.rate_limit_secret), 'sha256')),
  1, 'rate limit: the fresh window counts from 1');
select is((select count(*) from private.rate_limit_counters where bucket = 'signin' and window_end <= now()), 1::bigint,
  'rate limit: another key''s expired row is left for the purge job (consume only cleans its own key)');
-- purge
select pg_temp.act_as('service_role');
select is(pg_temp.val($$private.purge_rate_limit_counters()$$), '1', 'purge: removes the one expired row and returns 1');
select is(pg_temp.val($$private.purge_rate_limit_counters()$$), '0', 'purge: a second run removes nothing');
select pg_temp.act_as('postgres');
select is((select count(*) from private.rate_limit_counters where window_end > now()), 3::bigint, 'purge: live windows were kept (3 live counters)');
-- validation (the same refusal shape for every bad input)
select pg_temp.act_as('service_role');
select is(pg_temp.val($$public.consume_rate_limit('Signin', 'k', 3, 60)$$), 'ERR 22023', 'validation: bucket with an uppercase letter is refused');
select is(pg_temp.val($$public.consume_rate_limit('', 'k', 3, 60)$$), 'ERR 22023', 'validation: empty bucket is refused');
select is(pg_temp.val($$public.consume_rate_limit(null, 'k', 3, 60)$$), 'ERR 22023', 'validation: null bucket is refused');
select is(pg_temp.val($$public.consume_rate_limit('1abc', 'k', 3, 60)$$), 'ERR 22023', 'validation: bucket starting with a digit is refused');
select is(pg_temp.val($$public.consume_rate_limit('a b', 'k', 3, 60)$$), 'ERR 22023', 'validation: bucket with a space is refused');
select is(pg_temp.val($$public.consume_rate_limit(repeat('a', 64), 'k', 3, 60)$$), 'ERR 22023', 'validation: bucket of 64 characters is refused');
select is(pg_temp.val($$public.consume_rate_limit(repeat('a', 63), 'k', 3, 60)$$), 'true', 'validation: twin, a 63-character bucket is accepted');
select is(pg_temp.val($$public.consume_rate_limit('a:b.c_d-e', 'k', 3, 60)$$), 'true', 'validation: twin, a bucket with : . _ - is accepted');
select is(pg_temp.val($$public.consume_rate_limit('b', null, 3, 60)$$), 'ERR 22023', 'validation: null key is refused');
select is(pg_temp.val($$public.consume_rate_limit('b', '', 3, 60)$$), 'ERR 22023', 'validation: empty key is refused');
select is(pg_temp.val($$public.consume_rate_limit('b', '   ', 3, 60)$$), 'ERR 22023', 'validation: blank key is refused');
select is(pg_temp.val($$public.consume_rate_limit('b', repeat('k', 513), 3, 60)$$), 'ERR 22023', 'validation: a 513-character key is refused');
select is(pg_temp.val($$public.consume_rate_limit('b', repeat('k', 512), 3, 60)$$), 'true', 'validation: twin, a 512-character key is accepted');
select is(pg_temp.val($$public.consume_rate_limit('b', 'k', 0, 60)$$), 'ERR 22023', 'validation: max 0 is refused');
select is(pg_temp.val($$public.consume_rate_limit('b', 'k', null, 60)$$), 'ERR 22023', 'validation: null max is refused');
select is(pg_temp.val($$public.consume_rate_limit('b', 'k', 1000001, 60)$$), 'ERR 22023', 'validation: max above one million is refused');
select is(pg_temp.val($$public.consume_rate_limit('b', 'k', 3, 0)$$), 'ERR 22023', 'validation: window of 0 seconds is refused');
select is(pg_temp.val($$public.consume_rate_limit('b', 'k', 3, null)$$), 'ERR 22023', 'validation: null window is refused');
select is(pg_temp.val($$public.consume_rate_limit('b', 'k', 3, 86401)$$), 'ERR 22023', 'validation: window above one day is refused');
select is(pg_temp.val($$public.consume_rate_limit('b2', 'k', 3, 86400)$$), 'true', 'validation: twin, a window of exactly one day is accepted');
-- nobody but service_role (the grant is the only control: the function does not look at auth.uid())
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.val($$public.consume_rate_limit('x', 'k', 3, 60)$$), 'ERR 42501', 'deny: an org admin (authenticated) cannot call consume_rate_limit');
select is(pg_temp.val($$private.purge_rate_limit_counters()$$), 'ERR 42501', 'deny: an org admin cannot run the purge');
select pg_temp.act_as('u_platform');
select is(pg_temp.val($$public.consume_rate_limit('x', 'k', 3, 60)$$), 'ERR 42501', 'deny: a platform admin cannot call consume_rate_limit');
select pg_temp.act_as('anon');
select is(pg_temp.val($$public.consume_rate_limit('x', 'k', 3, 60)$$), 'ERR 42501', 'deny: anon cannot call consume_rate_limit');
select is(pg_temp.val($$private.purge_rate_limit_counters()$$), 'ERR 42501', 'deny: anon cannot run the purge');
-- the tables themselves: no role reads or writes them
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try('select * from private.rate_limit_counters'), '42501', 'deny: authenticated cannot read the counters');
select is(pg_temp.try('select * from private.rate_limit_secret'), '42501', 'deny: authenticated cannot read the HMAC secret');
select pg_temp.act_as('anon');
select is(pg_temp.try('select * from private.rate_limit_counters'), '42501', 'deny: anon cannot read the counters');
select is(pg_temp.try('select * from private.rate_limit_secret'), '42501', 'deny: anon cannot read the HMAC secret');
select pg_temp.act_as('service_role');
select is(pg_temp.try('select * from private.rate_limit_counters'), '42501', 'deny: not even service_role reads the counters directly (only the functions do)');
select is(pg_temp.try('select * from private.rate_limit_secret'), '42501', 'deny: not even service_role reads the HMAC secret');
select is(pg_temp.try('insert into private.rate_limit_counters (bucket, key_hash, window_start, window_end) values (''x'', ''\x00'', now(), now())'), '42501', 'deny: service_role cannot write counters directly');
select is(pg_temp.try('delete from private.rate_limit_counters'), '42501', 'deny: service_role cannot delete counters directly');
select pg_temp.act_as('postgres');
select ok((select bool_and(c.relrowsecurity) from pg_class c where c.relnamespace = 'private'::regnamespace and c.relname in ('rate_limit_counters', 'rate_limit_secret')),
  'both rate limit tables have RLS on');
select is((select count(*) from pg_policy p join pg_class c on c.oid = p.polrelid where c.relnamespace = 'private'::regnamespace and c.relname in ('rate_limit_counters', 'rate_limit_secret')), 0::bigint,
  'and no policy at all (deny by default)');
select is((select count(*) from public.audit_log where table_name like 'rate_limit%'), 0::bigint, 'the rate limit tables are not audited (no hashes copied into audit_log)');

-- ===========================================================================
-- can_manage_person_account: full truth table (aal2). Rows: person; columns: actor.
-- ===========================================================================
insert into public.people (id, organization_id, first_name, last_name, archived_at) values (pg_temp.id('p_archived_a'), pg_temp.id('org_a'), 'Ari', 'Archived', now());
insert into public.people (id, organization_id, first_name, last_name) values
  (pg_temp.id('p_noacct_staff_a1'),    pg_temp.id('org_a'), 'N', 'StaffA1'),
  (pg_temp.id('p_noacct_mgr_a1'),      pg_temp.id('org_a'), 'N', 'MgrA1'),
  (pg_temp.id('p_noacct_locadmin_a1'), pg_temp.id('org_a'), 'N', 'LocAdminA1'),
  (pg_temp.id('p_noacct_orgadmin_a'),  pg_temp.id('org_a'), 'N', 'OrgAdminA'),
  (pg_temp.id('p_noacct_staff_a2'),    pg_temp.id('org_a'), 'N', 'StaffA2');
insert into public.role_assignments (organization_id, person_id, role_id, location_id) values
  (pg_temp.id('org_a'), pg_temp.id('p_noacct_staff_a1'),    pg_temp.sys_role('staff'),   pg_temp.id('loc_a1')),
  (pg_temp.id('org_a'), pg_temp.id('p_noacct_mgr_a1'),      pg_temp.sys_role('manager'), pg_temp.id('loc_a1')),
  (pg_temp.id('org_a'), pg_temp.id('p_noacct_locadmin_a1'), pg_temp.sys_role('admin'),   pg_temp.id('loc_a1')),
  (pg_temp.id('org_a'), pg_temp.id('p_noacct_orgadmin_a'),  pg_temp.sys_role('admin'),   null),
  (pg_temp.id('org_a'), pg_temp.id('p_noacct_staff_a2'),    pg_temp.sys_role('staff'),   pg_temp.id('loc_a2'));

-- expected: 'org admin A, location admin A1, manager A1, staff A1, org admin B, platform, no account, disabled' as t/f
create temp table can_cases (subj text, expected text[]);
grant all on can_cases to public;
insert into can_cases values
  ('p_unassigned_a',       array['t','f','f','f','f','t','f','f']),  -- no login, no assignment: only org-wide admins and platform see them
  ('p_noacct_staff_a1',    array['t','t','f','f','f','t','f','f']),  -- staff at A1: org admin and A1 admin
  ('p_noacct_staff_a2',    array['t','f','f','f','f','t','f','f']),  -- staff at A2: only the org admin (A1 admin cannot reach A2)
  ('p_noacct_mgr_a1',      array['t','t','f','f','f','t','f','f']),  -- manager at A1: admin above manager
  ('p_noacct_locadmin_a1', array['t','f','f','f','f','t','f','f']),  -- admin at A1 (80): the A1 admin is not strictly above; the org admin (90) is
  ('p_noacct_orgadmin_a',  array['f','f','f','f','f','t','f','f']),  -- org admin (90): nobody but the platform is above
  ('p_archived_a',         array['f','f','f','f','f','f','f','f']),  -- archived: nobody
  ('p_staff_a1',           array['f','f','f','f','f','f','f','f']),  -- already has a login: nobody
  ('p_orgadmin_a',         array['f','f','f','f','f','f','f','f']);  -- already has a login (and is the actor themselves)
create temp table can_actors (n int, who text);
insert into can_actors values (1, 'u_orgadmin_a'), (2, 'u_locadmin_a1'), (3, 'u_manager_a1'), (4, 'u_staff_a1'), (5, 'u_orgadmin_b'), (6, 'u_platform'), (7, 'u_noaccount'), (8, 'u_disabled_a');
grant all on can_actors to public;
create temp table can_got (subj text, who text, got text);
grant all on can_got to public;
do $$
declare w record;
begin
  for w in select who from can_actors order by n loop
    perform pg_temp.act_as(w.who);
    insert into can_got select c.subj, w.who, public.can_manage_person_account(pg_temp.id('org_a'), pg_temp.id(c.subj))::text from can_cases c;
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select left(g.got, 1) from can_got g where g.subj = c.subj and g.who = a.who), c.expected[a.n],
  'can_manage_person_account(' || c.subj || ') as ' || a.who || ' = ' || c.expected[a.n])
from can_cases c cross join can_actors a order by c.subj, a.n;

-- other shapes
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.val($$public.can_manage_person_account(pg_temp.id('org_b'), pg_temp.id('p_unassigned_a'))$$), 'false', 'can_manage_person_account: the right person with the wrong organization -> false');
select is(pg_temp.val($$public.can_manage_person_account(pg_temp.id('org_b'), pg_temp.id('p_orgadmin_b'))$$), 'false', 'can_manage_person_account: another organization''s person -> false (no error, nothing revealed)');
select is(pg_temp.val($$public.can_manage_person_account(null, pg_temp.id('p_unassigned_a'))$$), 'false', 'can_manage_person_account: null organization -> false');
select is(pg_temp.val($$public.can_manage_person_account(pg_temp.id('org_a'), null)$$), 'false', 'can_manage_person_account: null person -> false');
select is(pg_temp.val($$public.can_manage_person_account(pg_temp.id('org_a'), gen_random_uuid())$$), 'false', 'can_manage_person_account: an unknown person -> false');
select is(pg_temp.val($$public.can_manage_person_account(gen_random_uuid(), gen_random_uuid())$$), 'false', 'can_manage_person_account: an unknown organization -> false');
select pg_temp.act_as('u_orgadmin_a', 'aal1');
select is(pg_temp.val($$public.can_manage_person_account(pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'))$$), 'false', 'can_manage_person_account: the org admin at aal1 -> false');
select pg_temp.act_as('u_orgadmin_a', 'aal2');
select is(pg_temp.val($$public.can_manage_person_account(pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'))$$), 'true', 'can_manage_person_account: twin, the org admin at aal2 -> true');
select pg_temp.act_as('anon');
select is(pg_temp.val($$public.can_manage_person_account(pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'))$$), 'ERR 42501', 'can_manage_person_account: anon cannot call it');
select pg_temp.act_as('service_role');
select is(pg_temp.val($$public.can_manage_person_account(pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'))$$), 'false', 'can_manage_person_account: the server key with no user -> false (identity comes from auth.uid() only)');
-- once the person has a login the answer flips
select pg_temp.act_as('postgres');
insert into auth.users (id, email) values (pg_temp.id('u_new_login'), 'new-login@test.invalid');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.val($$public.can_manage_person_account(pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'))$$), 'true', 'before the login exists: true');
select pg_temp.act_as('postgres');
insert into public.accounts (organization_id, person_id, user_id) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.id('u_new_login'));
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.val($$public.can_manage_person_account(pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'))$$), 'false', 'after the login exists: false');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- Service-only functions: out of reach for authenticated and anon, and they refuse a caller carrying a user JWT.
-- (The list is the one in 000_catalog_guards; consume_rate_limit and the purge are covered above: their only control is the grant.)
-- ===========================================================================
-- Fixtures the calls need: a matching event + enabled rule (match_workflow_rules), a pending delivery, a push subscription.
update public.workflow_rules set enabled = true where id = pg_temp.id('rule_a');
insert into public.outbox_events (id, organization_id, location_id, type, entity_table, entity_id, correlation_id, payload)
values (pg_temp.id('ev_book'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'booking.confirmed', 'bookings', pg_temp.id('booking_1'), pg_temp.id('ev_book'), '{"x":"1"}');
insert into public.notification_deliveries (id, organization_id, notification_id, person_id, channel, status)
values (pg_temp.id('del_a_email'), pg_temp.id('org_a'), pg_temp.id('notif_a'), pg_temp.id('p_staff_a1'), 'email', 'pending');
create temp table svc_calls (n int, fn text, expr text, is_set boolean);
grant all on svc_calls to public;
insert into svc_calls values
  (1,  'claim_outbox_events',            $$(select count(*) from public.claim_outbox_events('w1', 1, 60))$$, true),
  (2,  'complete_outbox_event',          $$public.complete_outbox_event(pg_temp.id('ev_a'), 'w1')$$, false),
  (3,  'fail_outbox_event',              $$public.fail_outbox_event(pg_temp.id('ev_a'), 'w1', 'boom')$$, false),
  (4,  'record_outbox_handler',          $$public.record_outbox_handler(pg_temp.id('ev_a'), 'newhandler')$$, false),
  (5,  'outbox_handlers_done',           $$(select count(*) from public.outbox_handlers_done(pg_temp.id('ev_a')))$$, true),
  (6,  'match_workflow_rules',           $$(select count(*) from public.match_workflow_rules(pg_temp.id('ev_book')))$$, true),
  (7,  'create_task_from_event',         $$public.create_task_from_event(pg_temp.id('ev_book'), pg_temp.id('rule_a'))$$, false),
  (8,  'emit_overdue_task_events',       $$public.emit_overdue_task_events(10)$$, false),
  (9,  'create_notification',            $$public.create_notification(pg_temp.id('ev_book'), pg_temp.id('p_staff_a1'), 'booking.confirmed', 'Hello')$$, false),
  (10, 'notice_audience_person_ids',     $$(select count(*) from public.notice_audience_person_ids(pg_temp.id('notice_a')))$$, true),
  (11, 'task_recipient_person_ids',      $$(select count(*) from public.task_recipient_person_ids(pg_temp.id('task_a')))$$, true),
  (12, 'claim_notification_deliveries',  $$(select count(*) from public.claim_notification_deliveries('w1', 5, 60))$$, true),
  (13, 'complete_notification_delivery', $$public.complete_notification_delivery(pg_temp.id('del_a_email'), 'w1')$$, false),
  (14, 'fail_notification_delivery',     $$public.fail_notification_delivery(pg_temp.id('del_a_email'), 'w1', 'boom')$$, false),
  (15, 'skip_notification_delivery',     $$public.skip_notification_delivery(pg_temp.id('del_a_email'), 'w1', 'nothing to send')$$, false),
  (16, 'disable_push_subscription',      $$public.disable_push_subscription((select id from public.push_subscriptions limit 1))$$, false);
-- every one of them is in the call list (the catalog list minus the two grant-only ones)
select is((select coalesce(string_agg(p.proname, ', ' order by p.proname), '') from pg_proc p
           where p.pronamespace = 'public'::regnamespace and has_function_privilege('service_role', p.oid, 'execute')
             and not has_function_privilege('authenticated', p.oid, 'execute') and p.proname <> 'consume_rate_limit'
             and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'i')
             and p.proname not in (select fn from svc_calls)),
  '', 'every service_role-only function in public is exercised below');

-- as an ordinary signed-in user (an org admin, so a missing grant is the only thing that can stop it): permission denied
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.val(c.expr), 'ERR 42501', 'authenticated (org admin A) cannot call ' || c.fn) from (select * from svc_calls order by n offset 0) c;
select pg_temp.act_as('u_platform');
select is(pg_temp.val(c.expr), 'ERR 42501', 'authenticated (platform admin) cannot call ' || c.fn) from (select * from svc_calls order by n offset 0) c;
select pg_temp.act_as('anon');
select is(pg_temp.val(c.expr), 'ERR 42501', 'anon cannot call ' || c.fn) from (select * from svc_calls order by n offset 0) c;

-- a service_role connection that carries a user's JWT: refused (an error, or nothing at all for the read-only helpers)
select pg_temp.act_as_service('u_orgadmin_a');
select is(pg_temp.val(c.expr),
          case when c.fn in ('outbox_handlers_done', 'match_workflow_rules', 'notice_audience_person_ids', 'task_recipient_person_ids') then '0' else 'ERR 42501' end,
  'service_role carrying a user JWT is refused by ' || c.fn) from (select * from svc_calls order by n offset 0) c;
-- twin: the same calls from the server key with no user are not refused; the read-only helpers return rows
select pg_temp.act_as('service_role');
select isnt(pg_temp.val(c.expr), 'ERR 42501', 'twin: the server key (no user) is allowed to call ' || c.fn) from (select * from svc_calls order by n offset 0) c;
select cmp_ok(pg_temp.val(c.expr)::bigint, '>', 0::bigint, 'twin: ' || c.fn || ' returns rows for the server key (so the "0" above is a refusal, not an empty table)')
  from (select * from svc_calls where is_set and fn <> 'claim_outbox_events' and fn <> 'claim_notification_deliveries' order by n offset 0) c;

select pg_temp.act_as('postgres');
select * from finish();
rollback;
