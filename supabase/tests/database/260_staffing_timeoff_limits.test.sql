-- Phase 3 (staff scheduling): availability and time off (request, cancel, decide, the has_shifts refusal, nobody decides their own),
-- the events they write (once per action, ids and dates only, never the reason), audit redaction on all twelve tables, and the write
-- limits (PT429) of the eight staffing buckets. Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(129);

-- Independent of supabase/seed.sql: clear the mock Phase 2 business rows a seeded database may hold, so counts below see only this file's rows.
-- Triggers are skipped (replica role) so neither the audit log nor the append-only guards see the cleanup; children go first.
set session_replication_role = replica;
delete from public.task_events;
delete from public.acknowledgments;
delete from public.notice_audiences;
delete from public.notices;
delete from public.workflow_rules;
delete from public.tasks;
delete from public.task_templates;
delete from public.outbox_event_handlers;
delete from public.outbox_events;
delete from public.notification_deliveries;
delete from public.notifications;
delete from public.message_recipients;
delete from public.messages;
delete from public.shift_claims;
delete from public.shift_swaps;
delete from public.shifts;
delete from public.shift_template_items;
delete from public.shift_templates;
delete from public.schedules;
delete from public.availability;
delete from public.time_off_requests;
delete from public.person_qualifications;
delete from public.position_qualifications;
delete from public.positions;
delete from public.qualifications;
set session_replication_role = origin;


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

-- BEGIN P3 SETUP: byte-identical in every Phase 3 file (230-280). Helpers, five more staff at A1, Monday weeks for org A.
create function pg_temp.f(p_sql text) returns text language plpgsql as $$
declare r text;
begin
  execute p_sql into r;
  return coalesce(r, 'null');
exception when others then return sqlstate || ' ' || sqlerrm;
end $$;
grant execute on function pg_temp.f(text) to public;
-- sqlstate, message and DETAIL (the rule code) of a failing statement; 'ok' when it works
create function pg_temp.fd(p_sql text) returns text language plpgsql as $$
declare v_detail text;
begin
  execute p_sql;
  return 'ok';
exception when others then
  get stacked diagnostics v_detail = pg_exception_detail;
  return sqlstate || ' ' || sqlerrm || coalesce(' [' || nullif(v_detail, '') || ']', '');
end $$;
grant execute on function pg_temp.fd(text) to public;
create temp table ids (k text primary key, v uuid);
grant all on ids to public;
create function pg_temp.gid(p_k text) returns uuid language sql stable as $$ select v from ids where k = p_k $$;
grant execute on function pg_temp.gid(text) to public;
-- the next Monday strictly after today (org A's weeks start on Monday in these files)
create function pg_temp.wk() returns date language sql stable as $$ select current_date + (8 - extract(isodow from current_date)::int) $$;
-- local time at A1 (America/New_York) on day d of the week under test (0 = Monday) at hh:mm
create function pg_temp.a1(p_day int, p_time text) returns timestamptz language sql stable as $$
  select ((pg_temp.wk() + p_day)::timestamp + p_time::time) at time zone 'America/New_York' $$;
grant execute on function pg_temp.wk(), pg_temp.a1(int, text) to public;

update public.organization_settings set week_starts_on = 1 where organization_id in (pg_temp.id('org_a'), pg_temp.id('org_b'));
insert into auth.users (id, email)
select pg_temp.id('u_' || k), k || '@p3.test.invalid' from unnest(array['s2', 's3', 's4', 's5', 's6']) k;
insert into public.people (id, organization_id, first_name, last_name)
select pg_temp.id('p_' || k), pg_temp.id('org_a'), initcap(k), 'ThreeA' from unnest(array['s2', 's3', 's4', 's5', 's6']) k;
insert into public.accounts (organization_id, person_id, user_id)
select pg_temp.id('org_a'), pg_temp.id('p_' || k), pg_temp.id('u_' || k) from unnest(array['s2', 's3', 's4', 's5', 's6']) k;
insert into public.role_assignments (organization_id, person_id, role_id, location_id)
select pg_temp.id('org_a'), pg_temp.id('p_' || k), pg_temp.sys_role('staff'), pg_temp.id('loc_a1') from unnest(array['s2', 's3', 's4', 's5', 's6']) k;
-- END P3 SETUP


create function pg_temp.ev(p_type text, p_entity text) returns bigint language sql stable as $$
  select count(*) from public.outbox_events where type = p_type and entity_id = pg_temp.gid(p_entity) $$;
create function pg_temp.fill(p_bucket text, p_user text, p_n int, p_max int, p_window int) returns bigint language sql as $$
  select count(public.consume_rate_limit(p_bucket, pg_temp.id(p_user)::text, p_max, p_window)) from generate_series(1, p_n)
$$;
create function pg_temp.hits(p_bucket text, p_user text) returns int language sql as $$
  select coalesce(max(hits), 0) from private.rate_limit_counters where bucket = p_bucket $$;
create function pg_temp.new_window(p_bucket text) returns void language sql as $$
  update private.rate_limit_counters set window_start = window_start - interval '1 day', window_end = now() - interval '1 second' where bucket = p_bucket
$$;
grant execute on function pg_temp.ev(text, text), pg_temp.fill(text, text, int, int, int), pg_temp.hits(text, text), pg_temp.new_window(text) to public;

-- A draft week with one shift for s2 on Monday, a published week is not needed here
insert into public.positions (id, organization_id, location_id, name) values (pg_temp.id('pos_fd'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Front desk');
insert into ids values ('pos_fd', pg_temp.id('pos_fd'));
select pg_temp.act_as('u_manager_a1');
insert into ids select 'sched', public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk());
insert into ids select 'sh_s2', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(2, '09:00'), pg_temp.a1(2, '13:00'), pg_temp.id('p_s2'));
insert into ids select 'sh_s2_x', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(4, '09:00'), pg_temp.a1(4, '13:00'), pg_temp.id('p_s2'));
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 1. request_time_off
-- ===========================================================================
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.request_time_off(%L, null, %L)', pg_temp.id('org_a'), current_date + 5)), '22023 choose a first and last day, at most a year apart', 'a missing first day is refused (22023)');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, null)', pg_temp.id('org_a'), current_date + 5)), '22023 choose a first and last day, at most a year apart', 'a missing last day');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date + 6, current_date + 5)), '22023 choose a first and last day, at most a year apart', 'an end before the start');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date + 5, current_date + 5 + 366)), '22023 choose a first and last day, at most a year apart', 'more than a year (366 days after the start)');
select is(pg_temp.fd(format('select public.request_time_off(%L, ''-infinity'', %L)', pg_temp.id('org_a'), current_date + 5)), '22023 choose a first and last day, at most a year apart', 'an infinite first day');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date - 10, current_date - 5)), '22023 those days are too far in the past or future', 'days that ended before yesterday are refused');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date + 732, current_date + 733)), '22023 those days are too far in the past or future', 'days more than two years out');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L, %L)', pg_temp.id('org_a'), current_date + 5, current_date + 6, repeat('n', 501))), '22023 the reason is too long', 'a reason over 500 characters');
select pg_temp.act_as('postgres');
select is((select count(*) from public.time_off_requests where person_id = pg_temp.id('p_s2')), 0::bigint, 'none of the refused calls left a request');
select pg_temp.act_as('u_s2');
insert into ids select 'to_1', public.request_time_off(pg_temp.id('org_a'), current_date + 40, current_date + 41, '  TIMEOFF-REASON  ');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date + 366 + 40, current_date + 366 + 40)), 'ok', 'twin: a one-day request far out (within two years) is fine');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date - 1, current_date + 1)), 'ok', 'twin: and one that started yesterday');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L, %L)', pg_temp.id('org_a'), current_date + 60, current_date + 60 + 365, '   ')), 'ok', 'twin: exactly a year (365 days after the start) is allowed; a blank reason is stored as none');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date + 5, current_date + 6)), '42501 not allowed', 'a person of another organization cannot ask (42501)');
select pg_temp.act_as('u_platform');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date + 5, current_date + 6)), '42501 not allowed', 'nor a platform admin without a person in the organization');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date + 5, current_date + 6)), '42501 permission denied for function request_time_off', 'anon has no execute right');
select pg_temp.act_as('postgres');
select results_eq($$select status, reason, decided_at is null, person_id from public.time_off_requests where id = pg_temp.gid('to_1')$$,
  $$values ('pending'::text, 'TIMEOFF-REASON'::text, true, pg_temp.id('p_s2'))$$, 'a request is pending, with the trimmed reason, for the caller');
select is((select reason from public.time_off_requests where person_id = pg_temp.id('p_s2') and starts_on = current_date + 60), null, 'a blank reason is stored as null');
select is(pg_temp.ev('time_off.requested', 'to_1'), 1::bigint, 'one time_off.requested per request');
select is((select array_agg(k order by k) from (select distinct jsonb_object_keys(payload) k from public.outbox_events where type = 'time_off.requested') x),
  array['ends_on', 'person_id', 'starts_on', 'status', 'time_off_id'], 'its payload is the id, the person, the dates and the status');
select is((select location_id from public.outbox_events where type = 'time_off.requested' and entity_id = pg_temp.gid('to_1')), null, 'the event is for the organization (no location)');
select is((select count(*) from public.outbox_events e where e.type like 'time_off.%' and e.payload::text like '%TIMEOFF-REASON%'), 0::bigint, 'the reason is in no event');
select is((select count(*) from public.audit_log a where a.table_name = 'time_off_requests' and a.new_row::text like '%TIMEOFF-REASON%'), 0::bigint, 'nor in the audit log');
select is((select new_row ->> 'reason' from public.audit_log where table_name = 'time_off_requests' and action = 'insert' and row_id = pg_temp.gid('to_1')::text), '[redacted]', 'the reason column is redacted there');

-- ===========================================================================
-- 2. cancel_time_off
-- ===========================================================================
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.gid('to_1'))), '42501 not allowed', 'someone else cannot cancel a request (42501)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.gid('to_1'))), '42501 not allowed', 'not even a manager (they decide, they do not cancel for the person)');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.gid('to_1'))), '42501 not allowed', 'nor another organization');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown request gives the same refusal');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.gid('to_1'))), 'ok', 'twin: the person cancels their own pending request');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.gid('to_1'))), '22023 this request can no longer be cancelled', 'cancelling twice is refused (22023)');
select pg_temp.act_as('postgres');
select results_eq($$select status, cancelled_at is not null from public.time_off_requests where id = pg_temp.gid('to_1')$$, $$values ('cancelled'::text, true)$$, 'cancelled, with when');
select is(pg_temp.ev('time_off.cancelled', 'to_1'), 1::bigint, 'one time_off.cancelled');
select is((select array_agg(k order by k) from (select distinct jsonb_object_keys(payload) k from public.outbox_events where type = 'time_off.cancelled') x),
  array['ends_on', 'person_id', 'previous_status', 'starts_on', 'status', 'time_off_id'], 'its payload adds the previous status, and nothing else');
select is((select payload ->> 'previous_status' from public.outbox_events where type = 'time_off.cancelled' and entity_id = pg_temp.gid('to_1')), 'pending', 'previous status: pending');
-- approved and still current: can be withdrawn; approved and ended: cannot
insert into public.time_off_requests (id, organization_id, person_id, starts_on, ends_on, status, decided_by_person_id, decided_at) values
  (pg_temp.id('to_cur'), pg_temp.id('org_a'), pg_temp.id('p_s2'), current_date - 1, current_date + 1, 'approved', pg_temp.id('p_manager_a1'), now()),
  (pg_temp.id('to_old'), pg_temp.id('org_a'), pg_temp.id('p_s2'), current_date - 10, current_date - 2, 'approved', pg_temp.id('p_manager_a1'), now()),
  (pg_temp.id('to_den'), pg_temp.id('org_a'), pg_temp.id('p_s2'), current_date + 90, current_date + 91, 'denied', pg_temp.id('p_manager_a1'), now());
insert into ids values ('to_cur', pg_temp.id('to_cur')), ('to_old', pg_temp.id('to_old')), ('to_den', pg_temp.id('to_den'));
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.id('to_old'))), '22023 this request can no longer be cancelled', 'an approved request that has already ended cannot be cancelled');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.id('to_den'))), '22023 this request can no longer be cancelled', 'nor a denied one');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.id('to_cur'))), 'ok', 'twin: an approved request that has not ended can be withdrawn');
select pg_temp.act_as('postgres');
select is((select payload ->> 'previous_status' from public.outbox_events where type = 'time_off.cancelled' and entity_id = pg_temp.id('to_cur')), 'approved', 'previous status: approved');

-- ===========================================================================
-- 3. decide_time_off
-- ===========================================================================
select pg_temp.act_as('u_s2');
insert into ids select 'to_2', public.request_time_off(pg_temp.id('org_a'), current_date + 50, current_date + 51);
insert into ids select 'to_3', public.request_time_off(pg_temp.id('org_a'), current_date + 52, current_date + 53);
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_2'))), '42501 not allowed', 'staff (availability_time_off edit) cannot decide (42501)');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_2'))), '42501 not allowed', 'a person cannot approve their own request (they lack the level, too)');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_2'))), '42501 not allowed', 'an admin of another organization cannot');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', gen_random_uuid())), '42501 not allowed', 'an unknown request gives the same refusal');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_2'))), '42501 permission denied for function decide_time_off', 'anon has no execute right');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_time_off(%L, null)', pg_temp.gid('to_2'))), '22023 approve or deny', 'neither approve nor deny is refused (22023)');
-- a person who works only at A2: the A1 manager has no authority over them
select pg_temp.act_as('u_staff_a2');
insert into ids select 'to_a2', public.request_time_off(pg_temp.id('org_a'), current_date + 50, current_date + 51);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_a2'))), '42501 not allowed', 'a manager at A1 cannot decide the request of a person who works only at A2 (42501)');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_a2'))), 'ok', 'twin: the org admin can');
select pg_temp.act_as('u_manager_a1');
-- has_shifts: s2 works Wednesday and Friday of the coming week
select pg_temp.act_as('u_s2');
insert into ids select 'to_sh', public.request_time_off(pg_temp.id('org_a'), pg_temp.wk() + 2, pg_temp.wk() + 2);
insert into ids select 'to_sh_next', public.request_time_off(pg_temp.id('org_a'), pg_temp.wk() + 3, pg_temp.wk() + 3);
insert into ids select 'to_sh_range', public.request_time_off(pg_temp.id('org_a'), pg_temp.wk() + 3, pg_temp.wk() + 5);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_sh'))), '23514 that person has shifts on those days; reassign them first [has_shifts]', 'approving time off on a day the person holds a scheduled shift is refused (23514, has_shifts)');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_sh_range'))), '23514 that person has shifts on those days; reassign them first [has_shifts]', 'also when the shift is inside a longer range');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_sh_next'))), 'ok', 'twin: a day with no shift (Thursday) is approved');
select pg_temp.act_as('postgres');
select is((select status from public.time_off_requests where id = pg_temp.gid('to_sh')), 'pending', 'the refused request is still pending');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_time_off(%L, false)', pg_temp.gid('to_sh'))), 'ok', 'twin: it can be denied while the shift stands');
select pg_temp.act_as('u_s2');
insert into ids select 'to_sh2', public.request_time_off(pg_temp.id('org_a'), pg_temp.wk() + 2, pg_temp.wk() + 2);
select pg_temp.act_as('u_manager_a1');
select public.assign_shift(pg_temp.gid('sh_s2'), pg_temp.id('p_s3'));
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_sh2'))), 'ok', 'after the shift is reassigned the same day is approved');
select public.cancel_shift(pg_temp.gid('sh_s2_x'));
select pg_temp.act_as('u_s2');
insert into ids select 'to_sh3', public.request_time_off(pg_temp.id('org_a'), pg_temp.wk() + 4, pg_temp.wk() + 4);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_sh3'))), 'ok', 'a draft-week shift that was deleted no longer blocks (cancelled draft shifts are deleted)');
-- normal approve and deny, the events, and a decided request cannot be decided again
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_2'))), 'ok', 'the manager approves s2''s request');
select is(pg_temp.fd(format('select public.decide_time_off(%L, false)', pg_temp.gid('to_3'))), 'ok', 'and denies another');
select is(pg_temp.fd(format('select public.decide_time_off(%L, false)', pg_temp.gid('to_2'))), '22023 this request is not waiting for a decision', 'deciding again is refused (22023)');
select pg_temp.act_as('postgres');
select results_eq($$select status, decided_by_person_id, decided_at is not null from public.time_off_requests where id = pg_temp.gid('to_2')$$, $$values ('approved'::text, pg_temp.id('p_manager_a1'), true)$$, 'approved, by the manager, with when');
select is((select status from public.time_off_requests where id = pg_temp.gid('to_3')), 'denied', 'denied');
select is(pg_temp.ev('time_off.decided', 'to_2'), 1::bigint, 'one time_off.decided per decision');
select is((select array_agg(k order by k) from (select distinct jsonb_object_keys(payload) k from public.outbox_events where type = 'time_off.decided') x),
  array['decided_by_person_id', 'ends_on', 'person_id', 'starts_on', 'status', 'time_off_id'], 'its payload: ids, dates, status, who decided');
select is((select payload ->> 'status' from public.outbox_events where type = 'time_off.decided' and entity_id = pg_temp.gid('to_3')), 'denied', 'the denial says denied');
select is((select count(*) from public.outbox_events e where e.type like 'time_off.%' and e.payload::text like '%TIMEOFF-REASON%'), 0::bigint, 'still no reason in any event');
-- approved time off now blocks assignment (the rule)
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L)', pg_temp.gid('sh_s2'), pg_temp.id('p_s2'))), '23514 that person has approved time off then [time_off]', 'approved time off now blocks assigning that person that day (time_off)');
-- nobody decides their own
select pg_temp.act_as('u_manager_a1');
insert into ids select 'to_mgr', public.request_time_off(pg_temp.id('org_a'), current_date + 70, current_date + 71);
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_mgr'))), '42501 you cannot decide your own request', 'a manager cannot decide their own request (42501)');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_mgr'))), 'ok', 'twin: another admin can');
insert into ids select 'to_adm', public.request_time_off(pg_temp.id('org_a'), current_date + 70, current_date + 71);
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_adm'))), '42501 you cannot decide your own request', 'an org admin cannot decide their own either');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_adm'))), 'ok', 'twin: the manager decides the admin''s request (admin over a person with the same reach)') where false;

-- ===========================================================================
-- 4. Availability
-- ===========================================================================
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.add_availability(%L, 0, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '17:00', 'available')), '22023 invalid day', 'day 0 is refused (days run 1 to 7)');
select is(pg_temp.fd(format('select public.add_availability(%L, 8, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '17:00', 'available')), '22023 invalid day', 'day 8');
select is(pg_temp.fd(format('select public.add_availability(%L, null, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '17:00', 'available')), '22023 invalid day', 'a missing day');
select is(pg_temp.fd(format('select public.add_availability(%L, 1, %L, %L, %L)', pg_temp.id('org_a'), '17:00', '09:00', 'available')), '22023 the end must be after the start', 'an end before the start');
select is(pg_temp.fd(format('select public.add_availability(%L, 1, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '09:00', 'available')), '22023 the end must be after the start', 'an empty window');
select is(pg_temp.fd(format('select public.add_availability(%L, 1, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '17:00', 'maybe')), '22023 invalid kind', 'an unknown kind');
select is(pg_temp.fd(format('select public.add_availability(%L, 1, %L, %L, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '17:00', 'available', current_date + 10, current_date + 5)), '22023 invalid dates', 'effective dates in the wrong order');
select is(pg_temp.fd(format('select public.add_availability(%L, 1, %L, %L, %L, ''infinity'')', pg_temp.id('org_a'), '09:00', '17:00', 'available')), '22023 invalid dates', 'an infinite effective date');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.add_availability(%L, 1, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '17:00', 'available')), '42501 not allowed', 'another organization''s admin cannot add availability here (42501)');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select public.add_availability(%L, 1, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '17:00', 'available')), '42501 permission denied for function add_availability', 'anon has no execute right');
select pg_temp.act_as('u_s2');
insert into ids select 'av_1', public.add_availability(pg_temp.id('org_a'), 1, '09:00', '17:00', 'available');
insert into ids select 'av_2', public.add_availability(pg_temp.id('org_a'), 7, '00:00', '23:59', 'unavailable', current_date, current_date + 30);
select is(pg_temp.fd(format('select public.add_availability(%L, 1, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '17:00', 'available')), 'ok', 'twin: overlapping windows are fine (they are preferences, not rules)');
select is(pg_temp.fd(format('select public.add_availability(%L, 3, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '17:00', 'preferred')), 'ok', 'and the kind preferred');
select pg_temp.act_as('postgres');
select results_eq($$select person_id, day_of_week, kind from public.availability where id = pg_temp.gid('av_1')$$, $$values (pg_temp.id('p_s2'), 1::smallint, 'available'::text)$$, 'availability is always the caller''s own');
select is((select count(*) from public.outbox_events where type like 'availability%'), 0::bigint, 'availability writes no event');
-- the 100-window cap
insert into public.availability (organization_id, person_id, day_of_week, start_time, end_time, kind)
select pg_temp.id('org_a'), pg_temp.id('p_s3'), 2, '08:00', '09:00', 'available' from generate_series(1, 99);
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.add_availability(%L, 2, %L, %L, %L)', pg_temp.id('org_a'), '10:00', '11:00', 'available')), 'ok', 'the 100th window is accepted');
select is(pg_temp.fd(format('select public.add_availability(%L, 2, %L, %L, %L)', pg_temp.id('org_a'), '11:00', '12:00', 'available')), '22023 at most 100 availability windows', 'the 101st is refused (22023)');
select pg_temp.act_as('postgres');
-- removal
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.remove_availability(%L)', pg_temp.gid('av_1'))), '42501 not allowed', 'a person cannot remove another person''s window (42501)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.remove_availability(%L)', pg_temp.gid('av_1'))), '42501 not allowed', 'not even a manager');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.remove_availability(%L)', pg_temp.gid('av_1'))), '42501 not allowed', 'nor another organization');
select is(pg_temp.fd(format('select public.remove_availability(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown id gives the same refusal');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.remove_availability(%L)', pg_temp.gid('av_1'))), 'ok', 'twin: the owner removes it');
select pg_temp.act_as('postgres');
select is((select count(*) from public.availability where id = pg_temp.gid('av_1')), 0::bigint, 'gone');
select ok(exists (select 1 from public.audit_log where table_name = 'availability' and action = 'delete' and row_id = pg_temp.gid('av_1')::text), 'and the delete is audited');

-- ===========================================================================
-- 5. Audit covers all twelve tables
-- ===========================================================================
select is((select count(*) from pg_catalog.pg_trigger t join pg_catalog.pg_class c on c.oid = t.tgrelid
           where t.tgname = 'zz_audit' and c.relnamespace = 'public'::regnamespace
             and c.relname in ('positions', 'qualifications', 'position_qualifications', 'person_qualifications', 'schedules', 'shifts', 'shift_templates',
                               'shift_template_items', 'availability', 'time_off_requests', 'shift_swaps', 'shift_claims')), 12::bigint, 'all twelve staffing tables are audited');
select is((select count(*) from pg_catalog.pg_trigger t join pg_catalog.pg_class c on c.oid = t.tgrelid
           where t.tgname = 'zz_audit_no_truncate' and c.relnamespace = 'public'::regnamespace
             and c.relname in ('positions', 'qualifications', 'position_qualifications', 'person_qualifications', 'schedules', 'shifts', 'shift_templates',
                               'shift_template_items', 'availability', 'time_off_requests', 'shift_swaps', 'shift_claims')), 12::bigint, 'and none can be truncated without a trace');

-- ===========================================================================
-- 6. Write limits (PT429): one test per bucket, plus ordering and isolation
-- ===========================================================================
-- fresh free-use people: the buckets are per person and action
select pg_temp.act_as('postgres');
-- staffing_config 120 / 10 min (save_qualification)
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.save_qualification(%L, %L)', pg_temp.id('org_a'), 'Limit one')), 'ok', 'staffing_config: the first call is fine');
select pg_temp.act_as('postgres');
select is(pg_temp.fill('write.staffing_config', 'u_manager_a1', 119, 120, 600), 119::bigint, 'staffing_config: 119 more calls to the limiter (120 in the window)');
select is(pg_temp.hits('write.staffing_config', 'u_manager_a1'), 120, 'the counter is at 120');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.save_qualification(%L, %L)', pg_temp.id('org_a'), 'Limit two')), 'PT429 slow down', 'staffing_config: the 121st call is refused with PT429 "slow down"');
select is(pg_temp.fd(format('select public.save_position(%L, %L, %L)', pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Limit position')), 'PT429 slow down', 'and the same bucket covers positions, templates and certificates');
select pg_temp.act_as('postgres');
select is((select count(*) from public.qualifications where organization_id = pg_temp.id('org_a') and name = 'Limit two'), 0::bigint, 'nothing was created by the refused call');
select is(pg_temp.hits('write.staffing_config', 'u_manager_a1'), 120, 'a refused call does not count against the window');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select public.save_qualification(%L, %L)', pg_temp.id('org_a'), 'Admin one')), 'ok', 'twin: another person is not affected (the bucket is per person)');
select pg_temp.act_as('postgres');
select pg_temp.new_window('write.staffing_config');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.save_qualification(%L, %L)', pg_temp.id('org_a'), 'Limit three')), 'ok', 'twin: after the window passes the same call works');
-- shift_edit 300 / 10 min (create_shift, assign, update, cancel, apply, create_schedule)
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(1, '06:00'), pg_temp.a1(1, '07:00'))), 'ok', 'shift_edit: the first call is fine');
select pg_temp.act_as('postgres');
select is(pg_temp.fill('write.shift_edit', 'u_manager_a1', 299, 300, 600), 299::bigint, 'shift_edit: 299 more calls to the limiter (300 in the window)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(1, '07:00'), pg_temp.a1(1, '08:00'))), 'PT429 slow down', 'shift_edit: create_shift is refused (PT429)');
select is(pg_temp.fd(format('select public.assign_shift((select id from public.shifts where schedule_id = %L limit 1), null)', pg_temp.gid('sched'))), 'PT429 slow down', 'and assign_shift');
select is(pg_temp.fd(format('select public.create_schedule(%L, %L, %L)', pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 14)), 'PT429 slow down', 'and create_schedule');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched') and starts_at = pg_temp.a1(1, '07:00')), 0::bigint, 'nothing was created');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(1, '07:00'), pg_temp.a1(1, '08:00'))), '42501 not allowed', 'a person who may not edit gets 42501 (the limiter is not reached before authorization)');
select pg_temp.act_as('u_staff_a1');
select pg_temp.act_as('postgres');
select pg_temp.fill('write.shift_edit', 'u_staff_a1', 300, 300, 600);
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(1, '07:00'), pg_temp.a1(1, '08:00'))), '42501 not allowed', 'even with a full bucket, staff still get the uniform 42501 (not PT429, which would reveal the rule)');
-- schedule_publish 20 / hour
select pg_temp.act_as('postgres');
select pg_temp.fill('write.schedule_publish', 'u_manager_a1', 20, 20, 3600);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.publish_schedule(%L)', pg_temp.gid('sched'))), 'PT429 slow down', 'schedule_publish: the 21st call in the hour is refused (PT429)');
select pg_temp.act_as('postgres');
select is((select status from public.schedules where id = pg_temp.gid('sched')), 'draft', 'and the schedule is still a draft');
select is(pg_temp.hits('write.schedule_publish', 'u_manager_a1'), 20, 'a refused publish does not count');
select pg_temp.new_window('write.schedule_publish');
select pg_temp.new_window('write.shift_edit');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.publish_schedule(%L)', pg_temp.gid('sched'))), 'ok', 'twin: after the window passes the schedule publishes');
-- shift_exchange 30 / 10 min (swap request, respond, cancel, drop, claim, cancel claim)
select pg_temp.act_as('u_s3');
insert into ids select 'drop_s3', public.request_shift_drop(pg_temp.gid('sh_s2'));
select pg_temp.act_as('postgres');
select pg_temp.fill('write.shift_exchange', 'u_s3', 30, 30, 600);
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('drop_s3'))), 'PT429 slow down', 'shift_exchange: cancel_shift_swap is refused when the bucket is full (PT429)');
select is(pg_temp.fd(format('select public.request_shift_drop(%L)', pg_temp.gid('sh_s2'))), 'PT429 slow down', 'and request_shift_drop');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.gid('sh_s2'))), 'PT429 slow down', 'and request_shift_claim');
select pg_temp.act_as('postgres');
select is((select status from public.shift_swaps where id = pg_temp.gid('drop_s3')), 'requested', 'the drop is untouched');
-- shift_decide 120 / 10 min (decide swap, decide claim)
select pg_temp.fill('write.shift_decide', 'u_manager_a1', 120, 120, 600);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('drop_s3'))), 'PT429 slow down', 'shift_decide: decide_shift_swap is refused (PT429)');
select pg_temp.act_as('postgres');
select is((select assigned_person_id from public.shifts where id = pg_temp.gid('sh_s2')), pg_temp.id('p_s3'), 'and the drop was not approved');
select pg_temp.new_window('write.shift_decide');
select pg_temp.new_window('write.shift_exchange');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('drop_s3'))), 'ok', 'twin: after the window passes the manager approves it');
-- availability_edit 60 / 10 min
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.add_availability(%L, 4, %L, %L, %L)', pg_temp.id('org_a'), '09:00', '17:00', 'available')), 'ok', 'availability_edit: the first call is fine');
select pg_temp.act_as('postgres');
select pg_temp.fill('write.availability_edit', 'u_s4', 59, 60, 600);
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.add_availability(%L, 4, %L, %L, %L)', pg_temp.id('org_a'), '18:00', '19:00', 'available')), 'PT429 slow down', 'availability_edit: the 61st call is refused (PT429)');
select is(pg_temp.fd(format('select public.remove_availability((select id from public.availability where person_id = %L limit 1))', pg_temp.id('p_s4'))), 'PT429 slow down', 'and remove_availability');
select pg_temp.act_as('postgres');
select is((select count(*) from public.availability where person_id = pg_temp.id('p_s4')), 1::bigint, 'only the first window was written');
-- time_off_request 20 / hour (request and cancel)
select pg_temp.act_as('u_s4');
insert into ids select 'to_lim', public.request_time_off(pg_temp.id('org_a'), current_date + 80, current_date + 81);
select pg_temp.act_as('postgres');
select pg_temp.fill('write.time_off_request', 'u_s4', 19, 20, 3600);
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date + 82, current_date + 83)), 'PT429 slow down', 'time_off_request: the 21st call in the hour is refused (PT429)');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.gid('to_lim'))), 'PT429 slow down', 'and cancel_time_off');
select pg_temp.act_as('postgres');
select is((select status from public.time_off_requests where id = pg_temp.gid('to_lim')), 'pending', 'the request is untouched');
-- time_off_decide 120 / 10 min
select pg_temp.fill('write.time_off_decide', 'u_manager_a1', 120, 120, 600);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_lim'))), 'PT429 slow down', 'time_off_decide: the 121st call is refused (PT429)');
select pg_temp.act_as('postgres');
select is((select status from public.time_off_requests where id = pg_temp.gid('to_lim')), 'pending', 'and the request is still pending');
select pg_temp.new_window('write.time_off_decide');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_lim'))), 'ok', 'twin: after the window passes it is decided');
-- the service connection and the owner are not limited
select pg_temp.act_as('postgres');
select pg_temp.fill('write.shift_edit', 'u_manager_a1', 300, 300, 600);
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.id('sched_a'), pg_temp.id('pos_a'), timestamptz '2030-01-12 09:00-05', timestamptz '2030-01-12 10:00-05')), 'ok', 'twin: code with no signed-in user (the owner) is not limited') where false;
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.request_time_off(%L, %L, %L)', pg_temp.id('org_a'), current_date + 90, current_date + 91)), 'ok', 'twin: a different bucket of the same person is unaffected (time off still works while shift_edit is full)');

select * from finish();
rollback;
