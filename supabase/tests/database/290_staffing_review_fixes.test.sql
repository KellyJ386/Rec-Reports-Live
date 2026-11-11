-- Phase 3 review fixes (20261113000200): no self-override (M1), override columns hidden from tenants and redacted in the audit log (M2),
-- fan-out caps and the shift.opened throttle (M4), real membership on own-shift reads and the cancel RPCs (M5), qualification races
-- (L2, the race itself is in the engineer's 41_races.sh), counter swaps never auto-approved (L3), the generic "you cannot take this shift"
-- (L4), the position-requirement count (L5), exchanges closed when a shift moves (L6), set_staffing_switches (L7), the apply_shift_template
-- result rows (clock changes, archived positions), swap_candidates (G1). Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(181);

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


create function pg_temp.mk(k text, p text, d int, t1 text, t2 text, who text default null, ov boolean default false) returns void language plpgsql as $$
begin
  insert into ids values (k, public.create_shift(pg_temp.gid('sched'), pg_temp.gid(p), pg_temp.a1(d, t1), pg_temp.a1(d, t2),
                                                 case when who is null then null else pg_temp.id(who) end, null, ov));
end $$;
create function pg_temp.ev(p_type text, p_entity text) returns bigint language sql stable as $$
  select count(*) from public.outbox_events where type = p_type and entity_id = pg_temp.gid(p_entity) $$;
create function pg_temp.sw(p_k text) returns text language sql stable as $$ select status from public.shift_swaps where id = pg_temp.gid(p_k) $$;
create function pg_temp.cl(p_k text) returns text language sql stable as $$ select status from public.shift_claims where id = pg_temp.gid(p_k) $$;
create function pg_temp.holder(p_k text) returns uuid language sql stable as $$ select assigned_person_id from public.shifts where id = pg_temp.gid(p_k) $$;
create function pg_temp.fill(p_bucket text, p_user text, p_n int, p_max int, p_window int) returns bigint language sql as $$
  select count(public.consume_rate_limit(p_bucket, pg_temp.id(p_user)::text, p_max, p_window)) from generate_series(1, p_n) $$;
create function pg_temp.hits(p_bucket text) returns int language sql as $$ select coalesce(max(hits), 0) from private.rate_limit_counters where bucket = p_bucket $$;
create function pg_temp.new_window(p_bucket text) returns void language sql as $$
  update private.rate_limit_counters set window_start = window_start - interval '1 day', window_end = now() - interval '1 second' where bucket = p_bucket $$;
grant execute on function pg_temp.mk(text, text, int, text, text, text, boolean), pg_temp.ev(text, text), pg_temp.sw(text), pg_temp.cl(text), pg_temp.holder(text),
  pg_temp.fill(text, text, int, int, int), pg_temp.hits(text), pg_temp.new_window(text) to public;

-- ---------------------------------------------------------------------------
-- Setup: a certified position, a plain one, a draft week, people with time off, a scheduler with "edit" only
-- ---------------------------------------------------------------------------
select pg_temp.act_as('postgres');
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level)
values (pg_temp.id('org_a'), pg_temp.id('p_s4'), pg_temp.id('loc_a1'), 'staff_schedule', 'edit');
select pg_temp.act_as('u_manager_a1');
insert into ids select 'q', public.save_qualification(pg_temp.id('org_a'), 'Lifeguard cert');
insert into ids select 'pos_lg', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Lifeguard', array[pg_temp.gid('q')]);
insert into ids select 'pos_fd', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Front desk');
select public.set_person_qualification(pg_temp.id('org_a'), pg_temp.id(k), pg_temp.gid('q'), current_date - 30, current_date + 365) from unnest(array['p_s2', 'p_s3']) k;
insert into ids select 'sched', public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk());
select pg_temp.act_as('postgres');
insert into public.time_off_requests (organization_id, person_id, starts_on, ends_on, status, decided_by_person_id, decided_at) values
  (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.wk() + 2, pg_temp.wk() + 2, 'approved', pg_temp.id('p_orgadmin_a'), now()),
  (pg_temp.id('org_a'), pg_temp.id('p_s2'), pg_temp.wk() + 4, pg_temp.wk() + 4, 'approved', pg_temp.id('p_manager_a1'), now());

-- ===========================================================================
-- M1. A schedule admin cannot override the rules for themselves
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select pg_temp.mk('m1a', 'pos_fd', 2, '10:00', '12:00');
select pg_temp.mk('m1b', 'pos_fd', 3, '10:00', '12:00');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L, true)', pg_temp.gid('m1a'), pg_temp.id('p_manager_a1'))), '42501 you cannot override the rules for yourself', 'assign_shift: a schedule admin cannot override approved time off for themselves (42501)');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L)', pg_temp.gid('m1a'), pg_temp.id('p_manager_a1'))), '23514 that person has approved time off then [time_off]', 'without the flag the rule still applies to them (23514, time_off)');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L, null, true)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(2, '14:00'), pg_temp.a1(2, '16:00'), pg_temp.id('p_manager_a1'))), '42501 you cannot override the rules for yourself', 'create_shift: the same');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L, true)', pg_temp.gid('m1b'), pg_temp.id('p_manager_a1'))), 'ok', 'twin: with nothing to override, the flag does no harm and the manager takes a free shift');
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L, null, true)', pg_temp.gid('m1b'), pg_temp.a1(2, '11:00'), pg_temp.a1(2, '12:00'))), '42501 you cannot override the rules for yourself', 'update_shift: moving their own shift onto their time off with the flag is refused (42501)');
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L)', pg_temp.gid('m1b'), pg_temp.a1(2, '11:00'), pg_temp.a1(2, '12:00'))), '23514 that person has approved time off then [time_off]', 'and without the flag it is the plain rule (23514, time_off)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched') and assigned_person_id = pg_temp.id('p_manager_a1')), 1::bigint, 'the refused calls changed nothing: the manager holds only the free shift');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L, true)', pg_temp.gid('m1a'), pg_temp.id('p_manager_a1'))), 'ok', 'twin: another schedule admin (the org admin) overrides for the manager');
select pg_temp.act_as('u_manager_a1');
select pg_temp.mk('m1c', 'pos_fd', 4, '10:00', '12:00');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L, true)', pg_temp.gid('m1c'), pg_temp.id('p_s2'))), 'ok', 'twin: the manager overrides for someone else (s2, approved time off that day)');
select pg_temp.act_as('postgres');
select results_eq($$select assigned_person_id, override_kinds, override_by_person_id from public.shifts where id = pg_temp.gid('m1a')$$,
  $$values (pg_temp.id('p_manager_a1'), array['time_off']::text[], pg_temp.id('p_orgadmin_a'))$$, 'the override for the manager is recorded under the org admin');
select results_eq($$select assigned_person_id, override_kinds, override_by_person_id from public.shifts where id = pg_temp.gid('m1c')$$,
  $$values (pg_temp.id('p_s2'), array['time_off']::text[], pg_temp.id('p_manager_a1'))$$, 'and the override for s2 under the manager');

-- ===========================================================================
-- M2. Override columns: not readable by tenants, readable through shift_overrides by schedulers, redacted in the audit log
-- ===========================================================================
select is((select array_agg(a.attname::text order by a.attnum) from pg_attribute a
           where a.attrelid = 'public.shifts'::regclass and a.attnum > 0 and not a.attisdropped
             and has_column_privilege('authenticated', 'public.shifts', a.attname, 'select')),
  array['id', 'organization_id', 'location_id', 'schedule_id', 'position_id', 'starts_at', 'ends_at', 'assigned_person_id', 'status', 'notes',
        'created_by_person_id', 'cancelled_at', 'created_at', 'updated_at'], 'authenticated can read exactly the shift columns that are not override or sweep bookkeeping');
select is((select array_agg(a.attname::text order by a.attnum) from pg_attribute a
           where a.attrelid = 'public.shifts'::regclass and a.attnum > 0 and not a.attisdropped
             and not has_column_privilege('authenticated', 'public.shifts', a.attname, 'select')),
  array['override_kinds', 'override_by_person_id', 'override_at', 'uncovered_emitted_for'], 'and cannot read these four');
select is((select array_agg(a.attname::text order by a.attnum) from pg_attribute a
           where a.attrelid = 'public.shifts'::regclass and a.attnum > 0 and not a.attisdropped
             and has_column_privilege('anon', 'public.shifts', a.attname, 'select')), null, 'anon can read none');
select is((select count(*) from pg_attribute a where a.attrelid = 'public.shifts'::regclass and a.attnum > 0 and not a.attisdropped
             and not has_column_privilege('service_role', 'public.shifts', a.attname, 'select')), 0::bigint, 'service_role still reads every column (the worker)');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd('select override_kinds from public.shifts limit 1'), '42501 permission denied for table shifts', 'staff holder: override_kinds is denied (42501)');
select is(pg_temp.fd('select override_by_person_id from public.shifts limit 1'), '42501 permission denied for table shifts', 'override_by_person_id');
select is(pg_temp.fd('select override_at from public.shifts limit 1'), '42501 permission denied for table shifts', 'override_at');
select is(pg_temp.fd('select uncovered_emitted_for from public.shifts limit 1'), '42501 permission denied for table shifts', 'uncovered_emitted_for');
select is(pg_temp.fd('select * from public.shifts limit 1'), '42501 permission denied for table shifts', 'select * is denied too');
select is(pg_temp.fd('select id, starts_at, assigned_person_id, notes, status from public.shifts limit 1'), 'ok', 'twin: the readable columns still work');
select is(pg_temp.fd(format('select count(*) from public.shifts where override_kinds is not null')), '42501 permission denied for table shifts', 'a WHERE on a hidden column is denied as well (no probing through filters)');
select is(pg_temp.fd(format('select id from public.shifts order by override_at')), '42501 permission denied for table shifts', 'and an ORDER BY on one');
select pg_temp.act_as('u_s3');
select is(pg_temp.fd('select override_kinds from public.shifts limit 1'), '42501 permission denied for table shifts', 'co-worker: override_kinds is denied (42501)');
select is(pg_temp.fd('select override_by_person_id from public.shifts limit 1'), '42501 permission denied for table shifts', 'override_by_person_id');
select is(pg_temp.fd('select override_at from public.shifts limit 1'), '42501 permission denied for table shifts', 'override_at');
select is(pg_temp.fd('select uncovered_emitted_for from public.shifts limit 1'), '42501 permission denied for table shifts', 'uncovered_emitted_for');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd('select override_kinds from public.shifts limit 1'), '42501 permission denied for table shifts', 'scheduler: not even someone who can edit schedules reads the column directly (42501)');
select is(pg_temp.fd('select uncovered_emitted_for from public.shifts limit 1'), '42501 permission denied for table shifts', 'nor the sweep bookkeeping');
select is(pg_temp.fd('select id, notes from public.shifts limit 1'), 'ok', 'twin: but they read the rest, notes included');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd('select override_by_person_id from public.shifts limit 1'), '42501 permission denied for table shifts', 'org admin: denied too (use shift_overrides)');
select pg_temp.act_as('anon');
select is(pg_temp.fd('select id from public.shifts limit 1'), '42501 permission denied for table shifts', 'anon: denied');
select pg_temp.act_as('service_role');
select is(pg_temp.fd('select override_kinds, override_by_person_id, override_at, uncovered_emitted_for from public.shifts limit 1'), 'ok', 'twin: service_role reads them');
select pg_temp.act_as('postgres');
-- shift_overrides
select pg_temp.act_as('u_manager_a1');
select results_eq(format($$select shift_id, override_kinds, override_by_person_id from public.shift_overrides(%L) order by shift_id$$, pg_temp.gid('sched')),
  format($$values (%L::uuid, array['time_off']::text[], %L::uuid), (%L::uuid, array['time_off']::text[], %L::uuid) order by 1$$,
         pg_temp.gid('m1a'), pg_temp.id('p_orgadmin_a'), pg_temp.gid('m1c'), pg_temp.id('p_manager_a1')),
  'the manager reads the overrides of the schedule: the two shifts, their kinds and who recorded them');
select is((select count(*) from public.shift_overrides(pg_temp.gid('sched'))), 2::bigint, 'only shifts that carry an override are listed (not the free ones)');
select ok((select override_at is not null from public.shift_overrides(pg_temp.gid('sched')) limit 1), 'with when');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select count(*) from public.shift_overrides(%L)', pg_temp.gid('sched'))), 'ok', 'twin: a person with staff_schedule edit can read them');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select count(*) from public.shift_overrides(%L)', pg_temp.gid('sched'))), 'ok', 'and the org admin');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select count(*) from public.shift_overrides(%L)', pg_temp.gid('sched'))), '42501 not allowed', 'staff (view only, even the person overridden) cannot (42501)');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select count(*) from public.shift_overrides(%L)', pg_temp.gid('sched'))), '42501 not allowed', 'nor another staff member');
select pg_temp.act_as('postgres');
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level)
values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), pg_temp.id('loc_a2'), 'staff_schedule', 'admin');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.fd(format('select count(*) from public.shift_overrides(%L)', pg_temp.gid('sched'))), '42501 not allowed', 'a schedule admin of another location (A2) cannot read A1''s overrides (42501)');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select count(*) from public.shift_overrides(%L)', pg_temp.gid('sched'))), '42501 not allowed', 'nor an admin of another organization');
select is(pg_temp.fd(format('select count(*) from public.shift_overrides(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown schedule gives the same refusal');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select count(*) from public.shift_overrides(%L)', pg_temp.gid('sched'))), '42501 permission denied for function shift_overrides', 'anon has no execute right');
select pg_temp.act_as('u_orgadmin_a', 'aal1');
select is(pg_temp.fd(format('select count(*) from public.shift_overrides(%L)', pg_temp.gid('sched'))), '42501 not allowed', 'an admin-tier session that has not passed the second step (aal1) cannot');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select count(*) from public.shift_overrides(%L)', pg_temp.gid('sched'))), 'ok', 'twin: at aal2 the same call works');
select pg_temp.act_as('postgres');
-- audit rows redact the override values (while keeping the row)
select is((select new_row ->> 'override_kinds' from public.audit_log where table_name = 'shifts' and row_id = pg_temp.gid('m1a')::text and (new_row ->> 'override_kinds') is not null order by id desc limit 1), '[redacted]', 'audit: override_kinds is redacted');
select is((select new_row ->> 'override_by_person_id' from public.audit_log where table_name = 'shifts' and row_id = pg_temp.gid('m1a')::text and (new_row ->> 'override_by_person_id') is not null order by id desc limit 1), '[redacted]', 'override_by_person_id is redacted');
select is((select new_row ->> 'override_at' from public.audit_log where table_name = 'shifts' and row_id = pg_temp.gid('m1a')::text and (new_row ->> 'override_at') is not null order by id desc limit 1), '[redacted]', 'override_at is redacted');
select is((select count(*) from public.audit_log a where a.table_name = 'shifts' and (a.new_row::text ~ 'time_off' or a.old_row::text ~ 'time_off')), 0::bigint, 'the word time_off appears in no shifts audit row');
select ok((select count(*) from public.audit_log a where a.table_name = 'shifts' and a.row_id = pg_temp.gid('m1a')::text) >= 2, 'twin: the shift''s history is still audited (insert and the assignment)');

-- ===========================================================================
-- M4. Fan-out: apply charges per shift, 2,000 cap, publish emits one event, shift.opened throttled per location per hour
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
insert into ids select 'tpl6', public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Six', 7);
select public.add_shift_template_item(pg_temp.gid('tpl6'), pg_temp.gid('pos_fd'), d, '09:00', 60) from generate_series(0, 5) d;
insert into ids select 'tpl5', public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Five', 7);
select public.add_shift_template_item(pg_temp.gid('tpl5'), pg_temp.gid('pos_fd'), d, '10:00', 60) from generate_series(0, 4) d;
insert into ids select 'sched2', public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 7);
insert into ids select 'sched3', public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 14);
insert into ids select 'sched4', public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 21);
select pg_temp.act_as('postgres');
create temp table h0 as select pg_temp.hits('write.shift_edit') as n;
grant all on h0 to public;
select pg_temp.act_as('u_manager_a1');
create temp table ap1 as select * from public.apply_shift_template(pg_temp.gid('sched2'), pg_temp.gid('tpl6'), 0);
select pg_temp.act_as('postgres');
select is((select count(*) from ap1 where shift_id is not null), 6::bigint, 'apply_shift_template made six shifts');
select is(pg_temp.hits('write.shift_edit') - (select n from h0), 6, 'and charged the shift_edit limit once for each (not once for the call)');
-- a bucket with room for three: the call is refused as a whole
select pg_temp.fill('write.shift_edit', 'u_manager_a1', 297 - pg_temp.hits('write.shift_edit'), 300, 600);
select is(pg_temp.hits('write.shift_edit'), 297, 'the manager has 297 of 300 shift_edit hits in the window');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 0)', pg_temp.gid('sched3'), pg_temp.gid('tpl6'))), 'PT429 slow down', 'a six-shift template with room for three is refused with PT429 (slow down)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched3')), 0::bigint, 'and none of its shifts was made (all or nothing)');
select pg_temp.new_window('write.shift_edit');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 0)', pg_temp.gid('sched3'), pg_temp.gid('tpl6'))), 'ok', 'twin: with a fresh window the same call works');
-- the 2,000 cap
select pg_temp.act_as('postgres');
insert into public.shifts (organization_id, location_id, schedule_id, position_id, starts_at, ends_at)
select pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.gid('sched4'), pg_temp.gid('pos_fd'),
       ((pg_temp.wk() + 21)::timestamp + n * interval '5 minutes') at time zone 'America/New_York',
       ((pg_temp.wk() + 21)::timestamp + n * interval '5 minutes' + interval '1 hour') at time zone 'America/New_York'
from generate_series(0, 1994) n;
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched4')), 1995::bigint, 'a draft week holding 1,995 shifts');
select pg_temp.new_window('write.shift_edit');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 0)', pg_temp.gid('sched4'), pg_temp.gid('tpl6'))), '23514 a schedule holds at most 2000 shifts [too_many_shifts]', 'a template of six that would pass 2,000 is refused (23514, too_many_shifts)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched4')), 1995::bigint, 'and none of the six was made (the whole template is refused)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 0)', pg_temp.gid('sched4'), pg_temp.gid('tpl5'))), 'ok', 'twin: a template of five that reaches exactly 2,000 is fine');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched4')), 2000::bigint, 'the week holds 2,000');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched4'), pg_temp.gid('pos_fd'), pg_temp.a1(27, '20:00'), pg_temp.a1(27, '21:00'))), '23514 a schedule holds at most 2000 shifts [too_many_shifts]', 'create_shift refuses the 2,001st (23514, too_many_shifts)');
select public.cancel_shift((select id from public.shifts where schedule_id = pg_temp.gid('sched4') order by starts_at limit 1));
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched4'), pg_temp.gid('pos_fd'), pg_temp.a1(27, '20:00'), pg_temp.a1(27, '21:00'))), 'ok', 'twin: after one is removed (a draft shift is deleted) there is room again');
select pg_temp.act_as('postgres');
-- publish emits one event; shift.opened is throttled per location per clock hour
select pg_temp.act_as('u_manager_a1');
select public.publish_schedule(pg_temp.gid('sched'));
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'shift.opened'), 0::bigint, 'publishing the week with open shifts emitted no shift.opened');
select is((select (payload ->> 'open_shift_count')::int from public.outbox_events where type = 'schedule.published' and entity_id = pg_temp.gid('sched')),
  (select count(*)::int from public.shifts where schedule_id = pg_temp.gid('sched') and status = 'scheduled' and assigned_person_id is null), 'schedule.published carries the number of open shifts');
select pg_temp.act_as('u_manager_a1');
insert into ids select 'th' || i, public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_fd'),
    pg_temp.a1(5, '06:00') + i * interval '30 minutes', pg_temp.a1(5, '06:30') + i * interval '30 minutes') from generate_series(1, 25) i;
select pg_temp.act_as('postgres');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched') and starts_at >= pg_temp.a1(5, '06:30') and assigned_person_id is null), 25::bigint, 'twenty-five open shifts were added to the published week');
select is((select count(*) from public.outbox_events where type = 'shift.opened' and location_id = pg_temp.id('loc_a1')), 20::bigint, 'only 20 of them were announced (the limit is 20 per location per hour)');
select is((select count(*) from public.outbox_events where type = 'shift.opened' and entity_id in (select id from public.shifts where schedule_id = pg_temp.gid('sched') and starts_at >= pg_temp.a1(5, '06:30') order by starts_at limit 20)), 20::bigint, 'the first twenty (in the order they were added)');
-- reopening a shift while the limit is used up announces nothing
select pg_temp.act_as('u_manager_a1');
select public.assign_shift(pg_temp.gid('th1'), pg_temp.id('p_s3'));
select public.assign_shift(pg_temp.gid('th1'), null);
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'shift.opened' and location_id = pg_temp.id('loc_a1')), 20::bigint, 'reopening a shift once the limit is used up announces nothing more');
select is((select count(*) from public.shifts where id = pg_temp.gid('th1') and assigned_person_id is null), 1::bigint, 'the shift is open all the same');
-- another location is unaffected
select pg_temp.act_as('u_orgadmin_a');
insert into ids select 'pos_a2', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'A2 desk');
insert into ids select 'sched_a2', public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a2'), pg_temp.wk());
select public.publish_schedule(pg_temp.gid('sched_a2'));
insert into ids select 'a2open', public.create_shift(pg_temp.gid('sched_a2'), pg_temp.gid('pos_a2'), pg_temp.a1(1, '09:00'), pg_temp.a1(1, '12:00'));
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'shift.opened' and location_id = pg_temp.id('loc_a2')), 1::bigint, 'twin: a different location of the same organization still gets its shift.opened');
-- the sweep still covers every open shift
select pg_temp.act_as('service_role');
select is(public.emit_uncovered_shift_events(interval '14 days', 500),
  (select count(*)::int from public.shifts s join public.schedules sc on sc.id = s.schedule_id where sc.status = 'published' and s.status = 'scheduled' and s.assigned_person_id is null and s.starts_at > now() and s.starts_at <= now() + interval '14 days'),
  'the uncovered sweep still announces every open shift, throttled or not');
select pg_temp.act_as('postgres');
select cmp_ok((select count(*) from public.outbox_events where type = 'shift.uncovered'), '>', (select count(*) from public.outbox_events where type = 'shift.opened'), 'which is more than the shift.opened that went out');
select is((select count(*) from public.outbox_events where type = 'shift.uncovered' and entity_id = pg_temp.gid('th25')), 1::bigint, 'including the last of the throttled ones');
-- a new clock hour
select pg_temp.new_window('staffing.shift_opened');
select pg_temp.act_as('u_manager_a1');
insert into ids select 'th26', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(6, '06:00'), pg_temp.a1(6, '07:00'));
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'shift.opened' and entity_id = pg_temp.gid('th26')), 1::bigint, 'twin: in the next clock hour the announcements resume');

-- ===========================================================================
-- M5. Own shifts and the cancel RPCs need real membership (MFA rules): a verified factor at aal1, and a person with no role
-- ===========================================================================
select pg_temp.new_window('write.shift_edit');
select pg_temp.new_window('write.shift_exchange');
select pg_temp.act_as('u_manager_a1');
select pg_temp.mk('m5a', 'pos_fd', 0, '22:00', '23:00', 'p_s2');
select pg_temp.mk('m5c', 'pos_fd', 1, '22:00', '23:00', 'p_s2');
select public.cancel_shift(pg_temp.gid('m5c'));                      -- published: the shift is cancelled, not deleted
select pg_temp.mk('m6a', 'pos_fd', 2, '22:00', '23:00', 'p_s6');
select pg_temp.act_as('u_s2');
insert into ids select 'sw5', public.request_shift_swap(pg_temp.gid('m5a'), pg_temp.id('p_s3'));
insert into ids select 'cl5', public.request_shift_claim(pg_temp.gid('th2'));
insert into ids select 'to5', public.request_time_off(pg_temp.id('org_a'), pg_temp.wk() + 50, pg_temp.wk() + 51);
select pg_temp.act_as('u_s6');
insert into ids select 'sw6', public.request_shift_swap(pg_temp.gid('m6a'), pg_temp.id('p_s3'));
insert into ids select 'cl6', public.request_shift_claim(pg_temp.gid('th3'));
insert into ids select 'to6', public.request_time_off(pg_temp.id('org_a'), pg_temp.wk() + 50, pg_temp.wk() + 51);
select pg_temp.act_as('postgres');
insert into auth.mfa_factors (id, user_id, factor_type, status, created_at, updated_at) values (pg_temp.id('f_s2'), pg_temp.id('u_s2'), 'totp', 'verified', now(), now());
-- a verified factor, session at aal1
select pg_temp.act_as('u_s2', 'aal1');
select is((select count(*) from public.shifts where assigned_person_id = pg_temp.id('p_s2')), 0::bigint, 'verified factor at aal1: the person''s own shifts are not readable');
select is((select count(*) from public.shifts), 0::bigint, 'nor any other shift');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.gid('to5'))), '42501 not allowed', 'cancel_time_off is refused (42501)');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('sw5'))), '42501 not allowed', 'cancel_shift_swap is refused');
select is(pg_temp.fd(format('select public.cancel_shift_claim(%L)', pg_temp.gid('cl5'))), '42501 not allowed', 'cancel_shift_claim is refused');
select is(pg_temp.fd(format('select count(*) from public.swap_candidates(%L)', pg_temp.gid('m5a'))), '42501 not allowed', 'swap_candidates is refused');
select pg_temp.act_as('postgres');
select results_eq($$select (select status from public.time_off_requests where id = pg_temp.gid('to5')), pg_temp.sw('sw5'), pg_temp.cl('cl5')$$, $$values ('pending'::text, 'requested'::text, 'requested'::text)$$, 'and nothing was cancelled');
select pg_temp.act_as('u_s2', 'aal2');
select is((select count(*) from public.shifts where assigned_person_id = pg_temp.id('p_s2')), 3::bigint, 'twin: at aal2 the person reads their own shifts (two live ones and the cancelled one, which only the own-shift branch shows)');
select is((select count(*) from public.shifts where assigned_person_id = pg_temp.id('p_s2') and status = 'cancelled'), 1::bigint, 'including the cancelled one');
select is(pg_temp.fd(format('select count(*) from public.swap_candidates(%L)', pg_temp.gid('m5a'))), 'ok', 'swap_candidates works');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.gid('to5'))), 'ok', 'cancel_time_off works');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('sw5'))), 'ok', 'cancel_shift_swap works');
select is(pg_temp.fd(format('select public.cancel_shift_claim(%L)', pg_temp.gid('cl5'))), 'ok', 'cancel_shift_claim works');
select pg_temp.act_as('postgres');
select results_eq($$select (select status from public.time_off_requests where id = pg_temp.gid('to5')), pg_temp.sw('sw5'), pg_temp.cl('cl5')$$, $$values ('cancelled'::text, 'cancelled'::text, 'cancelled'::text)$$, 'all three are cancelled');
-- a person with no role at all
select pg_temp.act_as('u_s6');
select is((select count(*) from public.shifts where assigned_person_id = pg_temp.id('p_s6')), 1::bigint, 'twin: before their roles go, s6 reads their own shift');
select pg_temp.act_as('postgres');
delete from public.role_assignments where person_id = pg_temp.id('p_s6');
select is((select count(*) from public.role_assignments where person_id = pg_temp.id('p_s6')), 0::bigint, 'sanity: s6 has no role now');
select pg_temp.act_as('u_s6');
select is((select count(*) from public.shifts), 0::bigint, 'a person with no role reads no shift, not even their own');
select is(pg_temp.fd(format('select public.cancel_time_off(%L)', pg_temp.gid('to6'))), '42501 not allowed', 'cancel_time_off is refused for them');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('sw6'))), '42501 not allowed', 'cancel_shift_swap is refused');
select is(pg_temp.fd(format('select public.cancel_shift_claim(%L)', pg_temp.gid('cl6'))), '42501 not allowed', 'cancel_shift_claim is refused');
select is(pg_temp.fd(format('select count(*) from public.swap_candidates(%L)', pg_temp.gid('m6a'))), '42501 not allowed', 'swap_candidates is refused');
select pg_temp.act_as('postgres');
select results_eq($$select (select status from public.time_off_requests where id = pg_temp.gid('to6')), pg_temp.sw('sw6'), pg_temp.cl('cl6')$$, $$values ('pending'::text, 'requested'::text, 'requested'::text)$$, 'and nothing of theirs was cancelled');

-- ===========================================================================
-- L2. An archived qualification is no longer required; a position cannot be given one
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
insert into ids select 'q2', public.save_qualification(pg_temp.id('org_a'), 'Cert two');
insert into ids select 'pos_l2', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Position L2', array[pg_temp.gid('q2')]);
select is(pg_temp.fd(format('select public.archive_qualification(%L)', pg_temp.gid('q2'))), '22023 a position still requires this qualification', 'a qualification a position still requires cannot be archived (22023)');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_l2'), pg_temp.a1(3, '14:00'), pg_temp.a1(3, '15:00'), pg_temp.id('p_s5'))), '23514 that person is missing a required qualification [qualification]', 'while it is required, a person without it is refused (qualification)');
select is(pg_temp.fd(format('select public.save_position(%L, %L, %L, %L, %L)', pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Position L2', '{}'::uuid[], pg_temp.gid('pos_l2'))), 'ok', 'the requirement is removed from the position');
select is(pg_temp.fd(format('select public.archive_qualification(%L)', pg_temp.gid('q2'))), 'ok', 'twin: now the qualification can be archived');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_l2'), pg_temp.a1(3, '14:00'), pg_temp.a1(3, '15:00'), pg_temp.id('p_s5'))), 'ok', 'the person without it works the position (nothing is required any more)');
select is(pg_temp.fd(format('select public.save_position(%L, %L, %L, %L, %L)', pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Position L2', array[pg_temp.gid('q2')], pg_temp.gid('pos_l2'))), '22023 unknown qualification', 'an archived qualification cannot be required again (22023)');
select is(pg_temp.fd(format('select public.save_position(%L, %L, %L, %L)', pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Another L2', array[pg_temp.gid('q2')])), '22023 unknown qualification', 'nor by a new position');
select pg_temp.act_as('postgres');
select is((select count(*) from public.position_qualifications where position_id = pg_temp.gid('pos_l2')), 0::bigint, 'the position requires nothing');

-- ===========================================================================
-- L3. Auto-approval: a plain swap yes, a swap with a counter shift never (it would tell B whether A can work Y)
-- ===========================================================================
update public.organization_settings set settings = jsonb_set(settings, '{staffing}', '{"auto_approve_swaps": true}') where organization_id = pg_temp.id('org_a');
select pg_temp.act_as('u_manager_a1');
select pg_temp.mk('la', 'pos_fd', 0, '20:00', '21:00', 'p_s2');
select pg_temp.mk('lb', 'pos_fd', 1, '20:00', '21:00', 'p_s3');
select pg_temp.mk('lc', 'pos_fd', 2, '20:00', '21:00', 'p_s2');
select pg_temp.act_as('u_s2');
insert into ids select 'w_counter', public.request_shift_swap(pg_temp.gid('la'), pg_temp.id('p_s3'), pg_temp.gid('lb'));
insert into ids select 'w_plain', public.request_shift_swap(pg_temp.gid('lc'), pg_temp.id('p_s3'));
select pg_temp.act_as('u_s3');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_counter'))), 'accepted', 'auto-approve on: a swap with a counter shift waits for a manager even when every rule passes');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_plain'))), 'approved', 'twin: a plain swap is approved at once');
select pg_temp.act_as('postgres');
select results_eq($$select pg_temp.holder('la'), pg_temp.holder('lb'), pg_temp.holder('lc')$$, $$values (pg_temp.id('p_s2'), pg_temp.id('p_s3'), pg_temp.id('p_s3'))$$, 'the counter swap moved nothing; the plain one moved');
select results_eq($$select auto_approved, decided_by_person_id is null from public.shift_swaps where id = pg_temp.gid('w_plain')$$, $$values (true, true)$$, 'and the plain one is marked automatic');
select is((select count(*) from public.outbox_events where type = 'shift_swap.approved' and entity_id = pg_temp.gid('w_counter')), 0::bigint, 'no approval event for the counter swap');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_counter'))), 'ok', 'twin: a manager approves it');
select pg_temp.act_as('postgres');
update public.organization_settings set settings = settings - 'staffing' where organization_id = pg_temp.id('org_a');

-- ===========================================================================
-- L4. On a staff path a conflict with a draft shift is not named
-- ===========================================================================
insert into public.schedules (id, organization_id, location_id, week_start) values (pg_temp.id('sc_a2d'), pg_temp.id('org_a'), pg_temp.id('loc_a2'), pg_temp.wk() + 7);
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id) values
  (pg_temp.id('draft_s2'), pg_temp.id('org_a'), pg_temp.id('loc_a2'), pg_temp.id('sc_a2d'), pg_temp.gid('pos_a2'), pg_temp.a1(8, '09:00'), pg_temp.a1(8, '12:00'), pg_temp.id('p_s2')),
  (pg_temp.id('draft_s3'), pg_temp.id('org_a'), pg_temp.id('loc_a2'), pg_temp.id('sc_a2d'), pg_temp.gid('pos_a2'), pg_temp.a1(11, '09:00'), pg_temp.a1(11, '12:00'), pg_temp.id('p_s3'));
select pg_temp.new_window('write.shift_edit');
select pg_temp.new_window('write.schedule_publish');
select pg_temp.act_as('u_manager_a1');
select public.publish_schedule(pg_temp.gid('sched2'));
select public.assign_shift((select id from public.shifts where schedule_id = pg_temp.gid('sched2') and starts_at = pg_temp.a1(11, '09:00')), pg_temp.id('p_s4'));
insert into ids select 'own_s2', public.create_shift(pg_temp.gid('sched2'), pg_temp.gid('pos_fd'), pg_temp.a1(10, '09:30'), pg_temp.a1(10, '10:30'), pg_temp.id('p_s2'));
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', (select id from public.shifts where schedule_id = pg_temp.gid('sched2') and starts_at = pg_temp.a1(8, '09:00')))), '23514 you cannot take this shift [unavailable]', 'claim: an overlap with the person''s own DRAFT shift is refused without saying why (23514, unavailable)');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', (select id from public.shifts where schedule_id = pg_temp.gid('sched2') and starts_at = pg_temp.a1(10, '09:00')))), '23514 that person already has a shift at that time [overlap]', 'twin: an overlap with a published shift of their own is still named (overlap)');
select pg_temp.act_as('u_s4');
insert into ids select 'w_l4', public.request_shift_swap((select id from public.shifts where schedule_id = pg_temp.gid('sched2') and starts_at = pg_temp.a1(11, '09:00')), pg_temp.id('p_s3'));
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_l4'))), '23514 you cannot take this shift [unavailable]', 'swap accept: the same generic refusal for a draft conflict');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.assign_shift((select id from public.shifts where schedule_id = %L and starts_at = %L), %L)', pg_temp.gid('sched2'), pg_temp.a1(8, '09:00'), pg_temp.id('p_s2'))), '23514 that person already has a shift at that time [overlap]', 'twin: a scheduler assigning the same person is told the overlap by name (the generic refusal is for staff paths only)');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- L5. position_shifts_missing_qualification: how many future shifts a new requirement leaves without a qualified holder
-- ===========================================================================
select pg_temp.new_window('write.shift_edit');
select pg_temp.new_window('write.staffing_config');
select pg_temp.act_as('u_manager_a1');
insert into ids select 'pos_l5', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Position L5');
select pg_temp.mk('l5a', 'pos_l5', 6, '14:00', '15:00', 'p_s2');
select pg_temp.mk('l5b', 'pos_l5', 6, '15:00', '16:00', 'p_s4');
select pg_temp.mk('l5c', 'pos_l5', 6, '16:00', '17:00', 'p_s5');
select pg_temp.mk('l5d', 'pos_l5', 6, '17:00', '18:00', 'p_s4');
select pg_temp.mk('l5e', 'pos_l5', 6, '18:00', '19:00', 'p_s5');
select public.cancel_shift(pg_temp.gid('l5e'));
select pg_temp.mk('l5f', 'pos_l5', 6, '19:00', '20:00');
select is(public.position_shifts_missing_qualification(pg_temp.gid('pos_l5')), 0, 'a position that requires nothing: no shift is missing a qualification');
select public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Position L5', array[pg_temp.gid('q')], pg_temp.gid('pos_l5'));
select is(public.position_shifts_missing_qualification(pg_temp.gid('pos_l5')), 3, 'after it requires the Lifeguard certificate: three future shifts have a holder without it (s4 twice, s5 once; s2 has it; the cancelled and the open one do not count)');
select pg_temp.act_as('postgres');
insert into public.schedules (id, organization_id, location_id, week_start, status, published_at) values (pg_temp.id('sc_past'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() - 14, 'published', now() - interval '20 days');
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id)
values (pg_temp.id('l5_past'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('sc_past'), pg_temp.gid('pos_l5'), pg_temp.a1(-14, '09:00'), pg_temp.a1(-14, '10:00'), pg_temp.id('p_s5'));
select pg_temp.act_as('u_orgadmin_a');
select public.assign_shift(pg_temp.gid('l5d'), null);
select public.assign_shift(pg_temp.gid('l5d'), pg_temp.id('p_s4'), true);
select pg_temp.act_as('u_manager_a1');
select is(public.position_shifts_missing_qualification(pg_temp.gid('pos_l5')), 2, 'a shift already carrying a qualification override is not counted again, and a past shift never is');
select pg_temp.act_as('postgres');
select is((select override_kinds from public.shifts where id = pg_temp.gid('l5d')), array['qualification']::text[], 'sanity: the override is recorded on l5d');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.position_shifts_missing_qualification(%L)', pg_temp.gid('pos_l5'))), '42501 not allowed', 'staff cannot ask (42501)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.position_shifts_missing_qualification(%L)', pg_temp.gid('pos_a2'))), '42501 not allowed', 'a manager cannot ask about a position at a location they do not schedule (A2)');
select is(pg_temp.fd(format('select public.position_shifts_missing_qualification(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown position gives the same refusal');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.position_shifts_missing_qualification(%L)', pg_temp.gid('pos_l5'))), 'ok', 'twin: staff_schedule edit is enough');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.position_shifts_missing_qualification(%L)', pg_temp.gid('pos_l5'))), '42501 not allowed', 'an admin of another organization cannot');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select public.position_shifts_missing_qualification(%L)', pg_temp.gid('pos_l5'))), '42501 permission denied for function position_shifts_missing_qualification', 'anon has no execute right');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select public.position_shifts_missing_qualification(%L)', pg_temp.gid('pos_a2'))), 'ok', 'twin: the org admin can ask about A2');
select pg_temp.act_as('postgres');
insert into public.positions (id, organization_id, location_id, name) values (pg_temp.id('pos_orgwide'), pg_temp.id('org_a'), null, 'Org-wide position');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.position_shifts_missing_qualification(%L)', pg_temp.id('pos_orgwide'))), '42501 not allowed', 'an organization-wide position needs organization scope: a location manager cannot (42501)');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select public.position_shifts_missing_qualification(%L)', pg_temp.id('pos_orgwide'))), 'ok', 'twin: the org admin can');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- L6. A new time or position closes the open swaps and claims of the shift; a notes-only change keeps them
-- ===========================================================================
select pg_temp.new_window('write.shift_edit');
select pg_temp.new_window('write.shift_exchange');
select pg_temp.act_as('u_manager_a1');
select pg_temp.mk('l6a', 'pos_fd', 2, '15:00', '16:00', 'p_s2');
select pg_temp.mk('l6c', 'pos_fd', 2, '18:30', '19:30', 'p_s2');
select pg_temp.mk('l6b', 'pos_fd', 3, '17:00', '18:00');
select pg_temp.mk('l6d', 'pos_fd', 3, '19:00', '20:00');
select pg_temp.act_as('u_s2');
insert into ids select 'w6a', public.request_shift_swap(pg_temp.gid('l6a'), pg_temp.id('p_s3'));
insert into ids select 'w6c', public.request_shift_swap(pg_temp.gid('l6c'), pg_temp.id('p_s3'));
select pg_temp.act_as('u_s3');
select public.respond_shift_swap(pg_temp.gid('w6c'), true);            -- accepted, waiting for a manager
select pg_temp.act_as('u_s5');
insert into ids select 'c6b', public.request_shift_claim(pg_temp.gid('l6b'));
select pg_temp.act_as('u_s4');
insert into ids select 'c6d', public.request_shift_claim(pg_temp.gid('l6d'));
select pg_temp.act_as('postgres');
create temp table ev6 as select count(*) as n from public.outbox_events;
grant all on ev6 to public;
select pg_temp.act_as('u_manager_a1');
select public.update_shift(pg_temp.gid('l6a'), null, null, null, 'only a note');
select public.update_shift(pg_temp.gid('l6b'), null, null, null, 'only a note');
select pg_temp.act_as('postgres');
select results_eq($$select pg_temp.sw('w6a'), pg_temp.sw('w6c'), pg_temp.cl('c6b'), pg_temp.cl('c6d')$$, $$values ('requested'::text, 'accepted'::text, 'requested'::text, 'requested'::text)$$, 'a notes-only change keeps every open swap and claim');
select is((select count(*) from public.outbox_events) - (select n from ev6), 0::bigint, 'and writes no event');
select pg_temp.act_as('u_manager_a1');
select public.update_shift(pg_temp.gid('l6a'), null, pg_temp.a1(2, '15:15'), pg_temp.a1(2, '16:15'));
select public.update_shift(pg_temp.gid('l6c'), pg_temp.gid('pos_lg'));
select public.update_shift(pg_temp.gid('l6b'), null, pg_temp.a1(3, '17:15'), pg_temp.a1(3, '18:15'));
select pg_temp.act_as('postgres');
select results_eq($$select pg_temp.sw('w6a'), pg_temp.sw('w6c'), pg_temp.cl('c6b'), pg_temp.cl('c6d')$$, $$values ('cancelled'::text, 'cancelled'::text, 'denied'::text, 'requested'::text)$$, 'a new time closes the open swap (a requested one) and the claim; a new position closes an accepted swap; a claim on another shift is untouched');
select results_eq($$select decided_by_person_id is null, decided_at is not null from public.shift_swaps where id = pg_temp.gid('w6a')$$, $$values (true, true)$$, 'the system closed the swap (no deciding person)');
select results_eq($$select decided_by_person_id is null, decided_at is not null from public.shift_claims where id = pg_temp.gid('c6b')$$, $$values (true, true)$$, 'and the claim');
select is(pg_temp.ev('shift_swap.cancelled', 'w6a'), 1::bigint, 'one shift_swap.cancelled for the first swap');
select is(pg_temp.ev('shift_swap.cancelled', 'w6c'), 1::bigint, 'one for the accepted swap');
select is(pg_temp.ev('shift_claim.denied', 'c6b'), 1::bigint, 'one shift_claim.denied for the claim');
select is(pg_temp.ev('shift_claim.denied', 'c6d'), 0::bigint, 'none for the claim that was not affected');
select is((select count(*) from public.outbox_events where type = 'shift.changed' and entity_id in (pg_temp.gid('l6a'), pg_temp.gid('l6c'))), 2::bigint, 'and the holder is told of each change (shift.changed)');
select is((select count(*) from public.outbox_events where type = 'shift.changed' and entity_id = pg_temp.gid('l6b')), 0::bigint, 'an open shift has no holder to tell');
-- G2: null keeps the note, an empty string clears it
select pg_temp.act_as('u_manager_a1');
select is((select notes from public.shifts where id = pg_temp.gid('l6a')), 'only a note', 'sanity: the note is set');
select public.update_shift(pg_temp.gid('l6a'), null, null, null, null);
select is((select notes from public.shifts where id = pg_temp.gid('l6a')), 'only a note', 'G2: a null note keeps it');
select public.update_shift(pg_temp.gid('l6a'), null, null, null, '   ');
select is((select notes from public.shifts where id = pg_temp.gid('l6a')), null, 'G2: blank clears it');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- L7. set_staffing_switches changes settings.staffing only, atomically
-- ===========================================================================
update public.organization_settings set settings = settings || '{"other_key": "keep", "staffing": {"future_key": 1}}'::jsonb where organization_id = pg_temp.id('org_a');
create temp table sw0 as select settings from public.organization_settings where organization_id = pg_temp.id('org_a');
create temp table swb as select settings from public.organization_settings where organization_id = pg_temp.id('org_b');
grant all on sw0 to public;
grant all on swb to public;
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select public.set_staffing_switches(%L, true, null)', pg_temp.id('org_a'))), 'ok', 'the org admin turns auto-approval on');
select pg_temp.act_as('postgres');
select is((select settings -> 'staffing' from public.organization_settings where organization_id = pg_temp.id('org_a')), '{"future_key": 1, "auto_approve_swaps": true}'::jsonb, 'only that switch changed inside staffing (the other staffing key is kept)');
select is((select settings - 'staffing' from public.organization_settings where organization_id = pg_temp.id('org_a')), (select settings - 'staffing' from sw0), 'every other settings key is untouched');
select pg_temp.act_as('u_orgadmin_a');
select public.set_staffing_switches(pg_temp.id('org_a'), null, true);
select pg_temp.act_as('postgres');
select is((select settings -> 'staffing' from public.organization_settings where organization_id = pg_temp.id('org_a')), '{"future_key": 1, "auto_approve_swaps": true, "first_come_open_shifts": true}'::jsonb, 'null keeps a switch: the second call sets first-come and keeps auto-approval');
select pg_temp.act_as('u_orgadmin_a');
select public.set_staffing_switches(pg_temp.id('org_a'), false, null);
select public.set_staffing_switches(pg_temp.id('org_a'), null, null);
select pg_temp.act_as('postgres');
select is((select settings -> 'staffing' from public.organization_settings where organization_id = pg_temp.id('org_a')), '{"future_key": 1, "auto_approve_swaps": false, "first_come_open_shifts": true}'::jsonb, 'false switches off; a call with both null changes nothing');
select is((select settings - 'staffing' from public.organization_settings where organization_id = pg_temp.id('org_a')), (select settings - 'staffing' from sw0), 'and the other keys are still as they were');
select is((select settings from public.organization_settings where organization_id = pg_temp.id('org_b')), (select settings from swb), 'the other organization''s settings were never touched');
create temp table sw1 as select settings from public.organization_settings where organization_id = pg_temp.id('org_a');
grant all on sw1 to public;
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.set_staffing_switches(%L, true, true)', pg_temp.id('org_a'))), '42501 not allowed', 'a manager (admin at the location only) cannot (42501)');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.fd(format('select public.set_staffing_switches(%L, true, true)', pg_temp.id('org_a'))), '42501 not allowed', 'nor a location admin');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.set_staffing_switches(%L, true, true)', pg_temp.id('org_a'))), '42501 not allowed', 'nor staff');
select pg_temp.act_as('u_orgadmin_a', 'aal1');
select is(pg_temp.fd(format('select public.set_staffing_switches(%L, true, true)', pg_temp.id('org_a'))), '42501 not allowed', 'nor an org admin at aal1');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.set_staffing_switches(%L, true, true)', pg_temp.id('org_a'))), '42501 not allowed', 'nor an admin of another organization');
select is(pg_temp.fd(format('select public.set_staffing_switches(%L, true, true)', gen_random_uuid())), '42501 not allowed', 'an unknown organization gives the same refusal');
select is(pg_temp.fd('select public.set_staffing_switches(null, true, true)'), '42501 not allowed', 'and a missing one');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select public.set_staffing_switches(%L, true, true)', pg_temp.id('org_a'))), '42501 permission denied for function set_staffing_switches', 'anon has no execute right');
select pg_temp.act_as('postgres');
select is((select settings from public.organization_settings where organization_id = pg_temp.id('org_a')), (select settings from sw1), 'none of the refused calls changed the settings');

-- ===========================================================================
-- apply_shift_template result rows: clock changes, archived positions, the day of the week (G3)
-- ===========================================================================
select pg_temp.new_window('write.shift_edit');
select pg_temp.new_window('write.staffing_config');
select pg_temp.act_as('u_manager_a1');
insert into ids select 'pos_arch', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'To be archived');
insert into ids select 'tpl_r', public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Result rows', 7);
insert into ids select 'it_arch', public.add_shift_template_item(pg_temp.gid('tpl_r'), pg_temp.gid('pos_arch'), 0, '09:00', 60);
insert into ids select 'it_long', public.add_shift_template_item(pg_temp.gid('tpl_r'), pg_temp.gid('pos_fd'), 6, '00:00', 1440);
insert into ids select 'it_ok', public.add_shift_template_item(pg_temp.gid('tpl_r'), pg_temp.gid('pos_fd'), 6, '09:00', 60);
select pg_temp.act_as('postgres');
update public.positions set archived_at = now() where id = pg_temp.gid('pos_arch');
insert into public.schedules (id, organization_id, location_id, week_start) values
  (pg_temp.id('sc_fb'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), date '2027-11-01'),
  (pg_temp.id('sc_sp'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), date '2027-03-08');
delete from private.rate_limit_counters where bucket = 'write.shift_edit';
create temp table h1 as select 0 as n;
grant all on h1 to public;
select pg_temp.act_as('u_manager_a1');
create temp table ap_fb as select * from public.apply_shift_template(pg_temp.id('sc_fb'), pg_temp.gid('tpl_r'), 0);
create temp table ap_sp as select * from public.apply_shift_template(pg_temp.id('sc_sp'), pg_temp.gid('tpl_r'), 0);
select pg_temp.act_as('postgres');
select is((select count(*) from ap_fb), 3::bigint, 'fall-back week: one result row per item (three), including the two that made no shift');
select results_eq($$select item_id, shift_id is null, refused from ap_fb order by item_id$$,
  format($$values (%L::uuid, true, 'position_unavailable'::text), (%L::uuid, true, 'time_change'::text), (%L::uuid, false, null::text) order by 1$$, pg_temp.gid('it_arch'), pg_temp.gid('it_long'), pg_temp.gid('it_ok')),
  'the archived-position item says position_unavailable, the 24-hour item that would last 25 hours says time_change, and the third made a shift');
select is((select count(*) from public.shifts where schedule_id = pg_temp.id('sc_fb')), 1::bigint, 'only one shift was made in the fall-back week');
select results_eq($$select item_id, shift_id is null, refused from ap_sp order by item_id$$,
  format($$values (%L::uuid, true, 'position_unavailable'::text), (%L::uuid, false, null::text), (%L::uuid, false, null::text) order by 1$$, pg_temp.gid('it_arch'), pg_temp.gid('it_long'), pg_temp.gid('it_ok')),
  'spring-forward week: the same item lasts 23 hours, so it is made');
select is((select s.ends_at - s.starts_at from public.shifts s join ap_sp a on a.shift_id = s.id where a.item_id = pg_temp.gid('it_long')), interval '23 hours', 'and is 23 hours long');
-- the manager's call paid for each shift made (2 calls: 1 + 1 for fall-back, 2 for spring), not for the skipped items
select is(pg_temp.hits('write.shift_edit') - (select n from h1), 3, 'items that made no shift were not charged (1 shift in the fall week, 2 in the spring week)');
-- G3: a day template lands on week_start + p_first_day
select pg_temp.act_as('u_manager_a1');
insert into ids select 'tpl_day', public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'One day', 1);
select public.add_shift_template_item(pg_temp.gid('tpl_day'), pg_temp.gid('pos_fd'), 0, '09:00', 60);
create temp table ap_day as select * from public.apply_shift_template(pg_temp.gid('sched3'), pg_temp.gid('tpl_day'), 3);
select pg_temp.act_as('postgres');
select is((select s.starts_at from public.shifts s join ap_day a on a.shift_id = s.id), pg_temp.a1(17, '09:00'), 'a one-day template with first day 3 lands on the Thursday of that week (week_start + 3)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 7)', pg_temp.gid('sched3'), pg_temp.gid('tpl_day'))), '22023 that day is outside the week', 'a first day of 7 is outside the week (22023)');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 1)', pg_temp.gid('sched3'), pg_temp.gid('tpl_r'))), '22023 that day is outside the week', 'a seven-day template cannot start on day 1 (22023)');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- G1. swap_candidates: the assignee only, and exactly the people request_shift_swap would accept
-- ===========================================================================
update public.people set preferred_name = 'Four' where id = pg_temp.id('p_s4');
select pg_temp.new_window('write.shift_edit');
select pg_temp.new_window('write.shift_exchange');
select pg_temp.act_as('u_manager_a1');
select pg_temp.mk('g1a', 'pos_fd', 3, '12:00', '13:00', 'p_s5');
select pg_temp.act_as('postgres');
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id)
values (pg_temp.id('g1_draft'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.gid('sched4'), pg_temp.gid('pos_fd'), pg_temp.a1(22, '09:00'), pg_temp.a1(22, '10:00'), pg_temp.id('p_s5'));
create temp table g1 (pid uuid, accepted boolean);
grant all on g1 to public;
select pg_temp.act_as('u_s5');
do $$
declare v_p uuid;
begin
  foreach v_p in array array[pg_temp.id('p_s2'), pg_temp.id('p_s3'), pg_temp.id('p_s4'), pg_temp.id('p_s6'), pg_temp.id('p_staff_a1'), pg_temp.id('p_staff_a2'),
                             pg_temp.id('p_manager_a1'), pg_temp.id('p_locadmin_a1'), pg_temp.id('p_orgadmin_a'), pg_temp.id('p_staff_b1'), pg_temp.id('p_disabled_a'),
                             pg_temp.id('p_unassigned_a'), pg_temp.id('p_s5')] loop
    begin
      perform public.cancel_shift_swap(public.request_shift_swap(pg_temp.gid('g1a'), v_p));
      insert into g1 values (v_p, true);
    exception when others then
      insert into g1 values (v_p, false);
    end;
  end loop;
end $$;
select is((select array_agg(person_id order by person_id) from public.swap_candidates(pg_temp.gid('g1a'))), (select array_agg(pid order by pid) from g1 where accepted),
  'swap_candidates lists exactly the people request_shift_swap accepts for that shift');
select ok((select count(*) from g1 where accepted) >= 5, 'and that is a real list (several people)');
select ok(not exists (select 1 from public.swap_candidates(pg_temp.gid('g1a')) where person_id in (pg_temp.id('p_s5'), pg_temp.id('p_staff_a2'), pg_temp.id('p_staff_b1'), pg_temp.id('p_disabled_a'), pg_temp.id('p_unassigned_a'), pg_temp.id('p_s6'))),
  'it leaves out the caller, a person who works only at A2, another organization''s person, a disabled account, a person with no assignment and a person with no role');
select ok(exists (select 1 from public.swap_candidates(pg_temp.gid('g1a')) where person_id = pg_temp.id('p_s2')), 'twin: but includes a co-worker');
select is((select display_name from public.swap_candidates(pg_temp.gid('g1a')) where person_id = pg_temp.id('p_s4')), 'Four ThreeA', 'the display name is the preferred name and the last name');
select is((select display_name from public.swap_candidates(pg_temp.gid('g1a')) where person_id = pg_temp.id('p_s2')), 'S2 ThreeA', 'else the first name and the last name');
select is(pg_get_function_result('public.swap_candidates(uuid)'::regprocedure), 'TABLE(person_id uuid, display_name text)', 'only a person id and a name: nothing about time off, qualifications or other shifts');
select is(pg_temp.fd(format('select count(*) from public.swap_candidates(%L)', pg_temp.id('g1_draft'))), '42501 not allowed', 'a shift on a draft week gives 42501');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select count(*) from public.swap_candidates(%L)', pg_temp.gid('g1a'))), '42501 not allowed', 'a co-worker who does not hold the shift gets 42501');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.swap_candidates(%L)', pg_temp.gid('g1a'))), '42501 not allowed', 'a manager who does not hold it gets 42501');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select count(*) from public.swap_candidates(%L)', pg_temp.gid('g1a'))), '42501 not allowed', 'another organization gets 42501');
select is(pg_temp.fd(format('select count(*) from public.swap_candidates(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown shift gives the same refusal');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select count(*) from public.swap_candidates(%L)', pg_temp.gid('g1a'))), '42501 permission denied for function swap_candidates', 'anon has no execute right');
select pg_temp.act_as('postgres');

select * from finish();
rollback;
