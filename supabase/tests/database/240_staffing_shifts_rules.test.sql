-- Phase 3 (staff scheduling): schedules, shifts, the four assignment rules on the manager paths (create_shift, assign_shift, update_shift,
-- apply_shift_template), the schedule-admin override (recorded and audited; overlap and membership never overridable), the publish lock and
-- the events written after publish (exactly once per action, ids and times only). Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(137);

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


-- ---------------------------------------------------------------------------
-- Setup: a qualification, two positions, certificates, one archived person, approved time off, a scheduler who only has "edit"
-- ---------------------------------------------------------------------------
insert into public.people (id, organization_id, first_name, last_name, archived_at) values (pg_temp.id('p_s7'), pg_temp.id('org_a'), 'S7', 'Archived', now());
insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_s7'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'));
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_s4'), pg_temp.id('loc_a1'), 'staff_schedule', 'edit');
select pg_temp.act_as('u_manager_a1');
insert into ids select 'q', public.save_qualification(pg_temp.id('org_a'), 'Lifeguard cert');
insert into ids select 'pos_lg', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Lifeguard', array[pg_temp.gid('q')]);
insert into ids select 'pos_fd', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Front desk');
select public.set_person_qualification(pg_temp.id('org_a'), pg_temp.id(k), pg_temp.gid('q'), current_date - 30, current_date + 365) from unnest(array['p_staff_a1', 'p_s2', 'p_s3', 'p_s4']) k;
select public.set_person_qualification(pg_temp.id('org_a'), pg_temp.id('p_s5'), pg_temp.gid('q'), current_date - 400, pg_temp.wk() - 1);
select pg_temp.act_as('postgres');
-- approved time off: s3 on Wednesday, s5 on Thursday (owner-written approved rows; the RPC path is in 260)
insert into public.time_off_requests (organization_id, person_id, starts_on, ends_on, status, decided_by_person_id, decided_at) values
  (pg_temp.id('org_a'), pg_temp.id('p_s3'), pg_temp.wk() + 2, pg_temp.wk() + 2, 'approved', pg_temp.id('p_manager_a1'), now()),
  (pg_temp.id('org_a'), pg_temp.id('p_s5'), pg_temp.wk() + 3, pg_temp.wk() + 3, 'approved', pg_temp.id('p_manager_a1'), now());

-- ===========================================================================
-- 1. Schedules
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd($$select public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 1)$$), '22023 a week must start on the organization''s first day of the week', 'a week must start on the first weekday (Monday here)');
select is(pg_temp.fd($$select public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), '-infinity')$$), '22023 invalid week', 'an infinite week is refused');
select is(pg_temp.fd($$select public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), date '2099-01-05')$$), '22023 invalid week', 'a week far in the future is refused');
select is(pg_temp.fd($$select public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a2'), pg_temp.wk())$$), '42501 not allowed', 'a manager cannot create a schedule at A2');
insert into ids select 'sched', public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk());
select is(public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk()), pg_temp.gid('sched'), 'twin: creating the same week again returns the same schedule');
select is((select count(*) from public.schedules where location_id = pg_temp.id('loc_a1') and week_start = pg_temp.wk()), 1::bigint, 'and there is one');
select results_eq($$select status, published_at is null, created_by_person_id from public.schedules where id = pg_temp.gid('sched')$$, $$values ('draft'::text, true, pg_temp.id('p_manager_a1'))$$, 'a new schedule is a draft created by the manager');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd($$select public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 7)$$), '42501 not allowed', 'staff cannot create a schedule');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd($$select public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 7)$$), '42501 not allowed', 'an admin of another organization cannot');
select is(pg_temp.fd(format('select public.publish_schedule(%L)', pg_temp.gid('sched'))), '42501 not allowed', 'nor publish it');
select is(pg_temp.fd(format('select public.publish_schedule(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown schedule gives the same refusal');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select public.publish_schedule(%L)', pg_temp.gid('sched'))), '42501 permission denied for function publish_schedule', 'anon has no execute right');
select pg_temp.act_as('postgres');
-- weeks of one location never overlap, even when the first weekday changes
update public.organization_settings set week_starts_on = 0 where organization_id = pg_temp.id('org_a');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.create_schedule(pg_temp.id(%L), pg_temp.id(%L), %L)', 'org_a', 'loc_a1', pg_temp.wk() - 1)), '23514 another schedule already covers part of that week', 'a Sunday week overlapping the Monday week is refused (23514)');
select pg_temp.act_as('postgres');
update public.organization_settings set week_starts_on = 1 where organization_id = pg_temp.id('org_a');

-- ===========================================================================
-- 2. Shift input checks and the draft
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(0, '17:00'), pg_temp.a1(0, '09:00'))), '22023 a shift ends after it starts and lasts at most 24 hours', 'a shift that ends before it starts is refused');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(0, '09:00'), pg_temp.a1(0, '09:00') + interval '24 hours 1 minute')), '22023 a shift ends after it starts and lasts at most 24 hours', 'and one longer than 24 hours');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, null)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(0, '09:00'))), '22023 a shift needs a start and an end', 'a missing end is refused');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(7, '09:00'), pg_temp.a1(7, '17:00'))), '22023 the shift must start during the schedule week', 'a shift in the next week is refused');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.id('pos_a'), pg_temp.a1(0, '09:00'), pg_temp.a1(0, '17:00'))) ~ '^22023', true, 'a position of another organization is refused (22023)');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, null, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(0, '09:00'), pg_temp.a1(0, '17:00'), repeat('n', 1001))), '22023 notes are too long', 'notes over 1000 characters are refused');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), 'infinity', pg_temp.a1(0, '17:00'))) ~ '^22023', true, 'an infinite start is refused (22023)');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched')), 0::bigint, 'none of the refused calls created a shift');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(0, '09:00'), pg_temp.a1(0, '17:00'))), '42501 not allowed', 'staff cannot create a shift');
select pg_temp.act_as('u_s4');
select is(pg_temp.f(format('select public.create_shift(%L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(0, '06:00'), pg_temp.a1(0, '07:00'))) ~ '^[0-9a-f-]{36}$', true, 'twin: a scheduler with staff_schedule edit can');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L, null, true)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(0, '07:00'), pg_temp.a1(0, '08:00'), pg_temp.id('p_s6'))), '42501 only a schedule admin can override', 'but asking to override with an assignee needs staff_schedule admin (42501, even when nothing needs overriding)');
select pg_temp.act_as('u_manager_a1');
-- an open draft shift and notes
insert into ids select 'open1', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_lg'), pg_temp.a1(1, '09:00'), pg_temp.a1(1, '17:00'), null, 'NOTE-OPEN');
insert into ids select 'open_wed', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_lg'), pg_temp.a1(2, '10:00'), pg_temp.a1(2, '14:00'));
select results_eq($$select assigned_person_id is null, status, notes from public.shifts where id = pg_temp.gid('open1')$$, $$values (true, 'scheduled'::text, 'NOTE-OPEN'::text)$$, 'an open draft shift');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type like 'shift%' or type like 'schedule%'), 0::bigint, 'no shift events while the schedule is a draft (drafts are audited, not announced)');
select cmp_ok((select count(*) from public.audit_log where table_name = 'shifts' and action = 'insert'), '>', 0::bigint, 'twin: the drafts are audited');

-- ===========================================================================
-- 3. The four rules, on every manager path
-- ===========================================================================
-- s2 already holds Monday 09:00-17:00
select pg_temp.act_as('u_manager_a1');
insert into ids select 'mon_s2', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_lg'), pg_temp.a1(0, '09:00'), pg_temp.a1(0, '17:00'), pg_temp.id('p_s2'));
select pg_temp.act_as('postgres');
create temp table rl (n int, who text, rule text, note text);
insert into rl values
  (1, 'p_s5',          'qualification', 'expired certificate'),
  (2, 'p_s6',          'qualification', 'no certificate'),
  (3, 'p_staff_a2',    'not_member',    'a person assigned at A2 only'),
  (4, 'p_staff_b1',    'not_member',    'a person of another organization'),
  (5, 'p_disabled_a',  'not_member',    'a disabled account'),
  (6, 'p_unassigned_a','not_member',    'a person with no assignment'),
  (7, 'p_s7',          'not_member',    'an archived person'),
  (8, 'p_s3',          'time_off',      'approved time off that day (Wednesday)');
grant all on rl to public;
create temp table rm (rule text, msg text);
insert into rm values ('not_member', 'that person cannot work at this location'), ('overlap', 'that person already has a shift at that time'),
  ('time_off', 'that person has approved time off then'), ('qualification', 'that person is missing a required qualification');
grant all on rm to public;
create temp table rl_got (n int, path text, got text);
grant all on rl_got to public;
select pg_temp.act_as('u_manager_a1');
do $$
declare r record; v_day int;
begin
  for r in select * from rl order by n loop
    v_day := case when r.who = 'p_s3' then 2 else 1 end;
    insert into rl_got values (r.n, 'create_shift', pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_lg'),
        pg_temp.a1(v_day, '10:00'), pg_temp.a1(v_day, '14:00'), pg_temp.id(r.who))));
    insert into rl_got values (r.n, 'assign_shift', pg_temp.fd(format('select public.assign_shift(%L, %L)', case when r.who = 'p_s3' then pg_temp.gid('open_wed') else pg_temp.gid('open1') end, pg_temp.id(r.who))));
  end loop;
end $$;
select is((select g.got from rl_got g where g.n = r.n and g.path = 'create_shift'),
          '23514 ' || (select msg from rm where rule = r.rule) || ' [' || r.rule || ']', 'create_shift refuses ' || r.note || ' (' || r.rule || ')') from rl r order by r.n;
select is((select g.got from rl_got g where g.n = r.n and g.path = 'assign_shift'),
          '23514 ' || (select msg from rm where rule = r.rule) || ' [' || r.rule || ']', 'assign_shift refuses ' || r.note || ' (' || r.rule || ')') from rl r order by r.n;
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_lg'), pg_temp.a1(0, '12:00'), pg_temp.a1(0, '18:00'), pg_temp.id('p_s2'))),
  '23514 that person already has a shift at that time [overlap]', 'create_shift refuses an overlap (s2 holds Monday 09:00-17:00)');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L)', (select public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_lg'), pg_temp.a1(0, '16:00'), pg_temp.a1(0, '20:00'))), pg_temp.id('p_s2'))),
  '23514 that person already has a shift at that time [overlap]', 'assign_shift refuses the same overlap');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L, null, true)', pg_temp.gid('sched'), pg_temp.gid('pos_lg'), pg_temp.a1(0, '12:00'), pg_temp.a1(0, '18:00'), pg_temp.id('p_s2'))),
  '23514 that person already has a shift at that time [overlap]', 'an overlap cannot be overridden, even by a schedule admin');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L, null, true)', pg_temp.gid('sched'), pg_temp.gid('pos_lg'), pg_temp.a1(1, '10:00'), pg_temp.a1(1, '14:00'), pg_temp.id('p_staff_a2'))),
  '23514 that person cannot work at this location [not_member]', 'nor can membership (not_member) be overridden');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(0, '17:00'), pg_temp.a1(0, '20:00'), pg_temp.id('p_s2'))), 'ok', 'twin: an adjacent shift (ends 17:00, next starts 17:00) is not an overlap');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(2, '10:00'), pg_temp.a1(2, '14:00'), pg_temp.id('p_s3'))), '23514 that person has approved time off then [time_off]', 'time off applies to every position, not only the certified one');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(1, '10:00'), pg_temp.a1(1, '14:00'), pg_temp.id('p_s6'))), 'ok', 'twin: s6 (no certificate) can work the uncertified Front desk');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_lg'), pg_temp.a1(1, '19:00'), pg_temp.a1(1, '21:00'), pg_temp.id('p_s4'))), 'ok', 'twin: a certified, free, local person works the Lifeguard shift');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched') and assigned_person_id in (pg_temp.id('p_s5'), pg_temp.id('p_staff_a2'), pg_temp.id('p_staff_b1'), pg_temp.id('p_disabled_a'), pg_temp.id('p_unassigned_a'), pg_temp.id('p_s7'))), 0::bigint, 'no refused call left an assignment');
-- update_shift re-checks the assignee for a new time or position
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L)', pg_temp.gid('mon_s2'), pg_temp.a1(2, '09:00'), pg_temp.a1(2, '17:00'))), 'ok', 'twin: s2''s shift moves to Wednesday (s2 is free then)');
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L)', pg_temp.gid('mon_s2'), pg_temp.a1(1, '19:30'), pg_temp.a1(1, '20:30'))), 'ok', 'and to Tuesday evening');
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L)', pg_temp.gid('mon_s2'), pg_temp.a1(1, '20:00'), pg_temp.a1(1, '22:00'))), 'ok', 'moving a shift onto its own earlier slot is not an overlap with itself');
insert into ids select 'tue_s4', id from public.shifts where assigned_person_id = pg_temp.id('p_s4') and starts_at = pg_temp.a1(1, '19:00');
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L)', pg_temp.gid('mon_s2'), pg_temp.a1(1, '20:00'), pg_temp.a1(1, '21:30'))), 'ok', 'shorter, still fine (s2 and s4 are different people)');
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L)', pg_temp.gid('tue_s4'), pg_temp.a1(1, '09:00'), pg_temp.a1(1, '17:00')))
  , 'ok', 'twin: s4 moves to Tuesday 09-17 (free)');
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L)', pg_temp.gid('mon_s2'), pg_temp.a1(1, '10:00'), pg_temp.a1(1, '12:00'))), 'ok', 's2 is free Tuesday morning');
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L)', pg_temp.gid('tue_s4'), pg_temp.a1(1, '09:00'), pg_temp.a1(1, '17:00'))), 'ok', 'twin: an unchanged time is accepted');
-- overlap through update: put s2's second shift onto a time s2 already holds
insert into ids select 'tue_s2b', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(3, '09:00'), pg_temp.a1(3, '12:00'), pg_temp.id('p_s2'));
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L)', pg_temp.gid('tue_s2b'), pg_temp.a1(1, '11:00'), pg_temp.a1(1, '13:00'))), '23514 that person already has a shift at that time [overlap]', 'update_shift: a new time that overlaps the assignee''s other shift is refused');
select is(pg_temp.fd(format('select public.update_shift(%L, null, %L, %L, null, true)', pg_temp.gid('tue_s2b'), pg_temp.a1(1, '11:00'), pg_temp.a1(1, '13:00'))), '23514 that person already has a shift at that time [overlap]', 'even with the override flag');
select is(pg_temp.fd(format('select public.update_shift(%L, %L)', pg_temp.gid('tue_s2b'), pg_temp.gid('pos_lg'))), 'ok', 'update_shift: a new position the assignee qualifies for is fine (s2 holds the certificate)');
-- the certificate of s6 is missing: put s6's Front desk shift onto the Lifeguard position
insert into ids select 'tue_s6', id from public.shifts where assigned_person_id = pg_temp.id('p_s6') and schedule_id = pg_temp.gid('sched');
select is(pg_temp.fd(format('select public.update_shift(%L, %L)', pg_temp.gid('tue_s6'), pg_temp.gid('pos_lg'))), '23514 that person is missing a required qualification [qualification]', 'update_shift: a new position the assignee lacks the certificate for is refused');
select is(pg_temp.fd(format('select public.update_shift(%L)', pg_temp.gid('tue_s6'))), 'ok', 'update_shift with nothing to change does nothing');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L)', pg_temp.gid('tue_s6'), pg_temp.id('p_s6'))), '22023 nothing to change', 'assign_shift to the person who already holds it is refused (22023)');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 4. Override: schedule admins only, recorded, audited, cleared when the assignee changes
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
insert into ids select 'ov1', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_lg'), pg_temp.a1(4, '09:00'), pg_temp.a1(4, '17:00'), pg_temp.id('p_s5'), null, true);
insert into ids select 'ov2', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_lg'), pg_temp.a1(3, '13:00'), pg_temp.a1(3, '15:00'), pg_temp.id('p_s5'), null, true);
insert into ids select 'ov3', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(2, '15:00'), pg_temp.a1(2, '17:00'), pg_temp.id('p_s3'), null, true);
select pg_temp.act_as('postgres');
select results_eq($$select override_kinds, override_by_person_id, override_at is not null from public.shifts where id = pg_temp.gid('ov1')$$,
  $$values (array['qualification']::text[], pg_temp.id('p_manager_a1'), true)$$, 'an override of the expired certificate is recorded on the shift (kind, who, when)');
select results_eq($$select override_kinds, override_by_person_id from public.shifts where id = pg_temp.gid('ov2')$$,
  $$values (array['qualification', 'time_off']::text[], pg_temp.id('p_manager_a1'))$$, 'both rules overridden at once (expired certificate and time off that Thursday) are both recorded') where false;
select ok((select override_kinds @> array['qualification', 'time_off'] and override_kinds <@ array['qualification', 'time_off'] from public.shifts where id = pg_temp.gid('ov2')), 'time off and the expired certificate overridden together are both recorded');
select results_eq($$select override_kinds from public.shifts where id = pg_temp.gid('ov3')$$, $$values (array['time_off']::text[])$$, 'an override that was only needed for time off records just that');
select is((select override_kinds from public.shifts where id = pg_temp.gid('mon_s2')), null, 'a shift that needed no override records none');
select ok((select count(*) from public.audit_log where table_name = 'shifts' and row_id = pg_temp.gid('ov1')::text and 'override_kinds' = any (changed_columns) or (new_row ->> 'override_kinds') is not null and row_id = pg_temp.gid('ov1')::text) >= 1, 'the override is audited (override_kinds in the audit row)');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L, true)', pg_temp.gid('open1'), pg_temp.id('p_s5'))), '42501 only a schedule admin can override', 'a scheduler with only edit cannot override (42501)');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L)', pg_temp.gid('open1'), pg_temp.id('p_s5'))), '23514 that person is missing a required qualification [qualification]', 'and without the flag the rule applies to them as to anyone');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L)', pg_temp.gid('ov1'), pg_temp.id('p_s2'))), 'ok', 'reassigning the overridden shift to a qualified person');
select pg_temp.act_as('postgres');
select results_eq($$select override_kinds is null, override_by_person_id is null, override_at is null, assigned_person_id from public.shifts where id = pg_temp.gid('ov1')$$,
  $$values (true, true, true, pg_temp.id('p_s2'))$$, 'the override record is cleared when the assignee changes');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L, true)', pg_temp.gid('open1'), pg_temp.id('p_s5'))), 'ok', 'twin: the org admin (staff_schedule admin) can override too');
select pg_temp.act_as('postgres');
select is((select override_by_person_id from public.shifts where id = pg_temp.gid('open1')), pg_temp.id('p_orgadmin_a'), 'recorded under the org admin');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.assign_shift(%L, null)', pg_temp.gid('open1'))), 'ok', 'opening the shift clears it');
select pg_temp.act_as('postgres');
select is((select override_kinds is null and override_at is null and assigned_person_id is null from public.shifts where id = pg_temp.gid('open1')), true, 'no override on an open shift (the table CHECK needs an assignee)');

-- ===========================================================================
-- 5. Shift templates stamped onto a draft week
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
insert into ids select 'tpl', public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Standard', 7);
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_lg'), 4, '06:00', 120, pg_temp.id('p_s4'));
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_lg'), 4, '07:00', 60, pg_temp.id('p_s4'));
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 5, '09:00', 480, null, 'TEMPLATE-NOTE');
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_lg'), 5, '10:00', 480, pg_temp.id('p_s5'));
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 5, '22:00', 600, pg_temp.id('p_s6'));
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 6, '09:00', 60, pg_temp.id('p_s3'));
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 2, '22:00', 120, pg_temp.id('p_s3'));
create temp table stamp as select * from public.apply_shift_template(pg_temp.gid('sched'), pg_temp.gid('tpl'), 0);
select pg_temp.act_as('postgres');
select is((select count(*) from stamp), 7::bigint, 'the template stamped 7 shifts (one per item)');
select is((select refused from stamp s join public.shifts x on x.id = s.shift_id where x.starts_at = pg_temp.a1(5, '10:00')), 'qualification', 'the item for s5 (expired certificate) became an open shift and names the rule: qualification');
select is((select refused from stamp s join public.shifts x on x.id = s.shift_id where x.starts_at = pg_temp.a1(4, '07:00')), 'overlap', 'the second item for s4 overlapping the first is open, naming overlap');
select is((select x.assigned_person_id from stamp s join public.shifts x on x.id = s.shift_id where x.starts_at = pg_temp.a1(4, '06:00')), pg_temp.id('p_s4'), 'the first s4 item was assigned');
select is((select count(*) from stamp where refused is null), 4::bigint, 'four stamped without a refusal (assigned or open by design)');
select is((select ends_at - starts_at from public.shifts where starts_at = pg_temp.a1(5, '22:00')), interval '10 hours', 'a 600 minute item at 22:00 ends at 08:00 the next day');
select is((select notes from public.shifts where starts_at = pg_temp.a1(5, '09:00') and schedule_id = pg_temp.gid('sched')), 'TEMPLATE-NOTE', 'item notes are copied to the shift');
select is((select refused from stamp s join public.shifts x on x.id = s.shift_id where x.starts_at = pg_temp.a1(2, '22:00')), 'time_off', 'the item for s3 on Wednesday became open, naming time_off (a template never overrides)');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched') and override_kinds is not null and starts_at in (pg_temp.a1(2, '22:00'), pg_temp.a1(5, '10:00'))), 0::bigint, 'and nothing was overridden');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 0)', pg_temp.gid('sched'), pg_temp.gid('tpl'))) , 'ok', 'twin: stamping again adds more shifts (it is not idempotent by design; a person cannot be double booked though)');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched') and starts_at = pg_temp.a1(4, '06:00') and assigned_person_id is not null), 1::bigint, 'the second stamp could not assign s4 again (overlap): one assigned copy only');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 7)', pg_temp.gid('sched'), pg_temp.gid('tpl'))) ~ '^22023', true, 'a first day outside the week is refused (22023)');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, -1)', pg_temp.gid('sched'), pg_temp.gid('tpl'))) ~ '^22023', true, 'and a negative one');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 0)', pg_temp.gid('sched'), pg_temp.gid('tpl'))), '42501 not allowed', 'staff cannot stamp a template');
select pg_temp.act_as('u_manager_a1');
select public.archive_shift_template(pg_temp.gid('tpl'));
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 0)', pg_temp.gid('sched'), pg_temp.gid('tpl'))), '22023 that template is archived', 'an archived template cannot be stamped');
insert into ids select 'tpl_a2', public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Other', 1);
select pg_temp.act_as('postgres');
update public.shift_templates set location_id = location_id where id = pg_temp.gid('tpl_a2');
-- a template of another location: use org admin to create one at A2
select pg_temp.act_as('u_orgadmin_a');
insert into ids select 'tpl_loc2', public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'At A2', 7);
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 0)', pg_temp.gid('sched'), pg_temp.gid('tpl_loc2'))), '22023 that template belongs to another location', 'a template of another location cannot be stamped here');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 6. Publish lock and the events after publish
-- ===========================================================================
select is((select count(*) from public.outbox_events where type like 'shift%' or type like 'schedule%'), 0::bigint, 'sanity: still no shift event');
create temp table before_pub as
  select (select count(*) from public.shifts where schedule_id = pg_temp.gid('sched') and assigned_person_id is null and status = 'scheduled') as n_open,
         (select count(*) from public.shifts where schedule_id = pg_temp.gid('sched') and assigned_person_id is not null and status = 'scheduled') as n_assigned;
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.publish_schedule(%L)', pg_temp.gid('sched'))), 'ok', 'the manager publishes the week');
select is(pg_temp.fd(format('select public.publish_schedule(%L)', pg_temp.gid('sched'))), '22023 this schedule is already published', 'publishing twice is refused (22023)');
select pg_temp.act_as('postgres');
select results_eq($$select status, published_at is not null, published_by_person_id from public.schedules where id = pg_temp.gid('sched')$$, $$values ('published'::text, true, pg_temp.id('p_manager_a1'))$$, 'published, with when and by whom');
select is((select count(*) from public.outbox_events where type = 'schedule.published' and entity_id = pg_temp.gid('sched')), 1::bigint, 'one schedule.published event');
select is((select count(*) from public.outbox_events where type = 'shift.opened'), 0::bigint, 'publishing announces no shift.opened (one event per schedule, not one per open shift: 20261113000200 M4)');
select is((select (payload ->> 'open_shift_count')::int from public.outbox_events where type = 'schedule.published'), (select n_open from before_pub)::int, 'schedule.published carries the number of open shifts instead');
select is((select count(*) from public.outbox_events where type like 'shift.%' and type <> 'shift.opened'), 0::bigint, 'publishing announces no assignment (people hear of their shifts from schedule.published)');
select is((select (payload ->> 'shift_count')::int from public.outbox_events where type = 'schedule.published'), ((select n_open + n_assigned from before_pub))::int, 'schedule.published counts every scheduled shift');
select is((select array_agg(k order by k) from (select distinct jsonb_object_keys(payload) k from public.outbox_events where type = 'schedule.published') x),
  array['actor_person_id', 'location_id', 'open_shift_count', 'schedule_id', 'shift_count', 'week_start'], 'its payload is exactly ids, the week, two counts and the actor');
select is((select count(*) from public.outbox_events e where e.type like 'shift%' and (e.payload::text like '%NOTE%' or e.payload::text like '%TEMPLATE-NOTE%')), 0::bigint, 'no notes in any payload');
select pg_temp.act_as('u_s2');
select cmp_ok((select count(*) from public.shifts), '>', 0::bigint, 'twin: staff now read the published shifts');
select pg_temp.act_as('u_manager_a1');
-- the lock: apply on published, and what changes on a published schedule is announced once each
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 0)', pg_temp.gid('sched'), pg_temp.gid('tpl_a2'))), '22023 a template can only be added to a draft schedule', 'a template can only be added to a draft schedule');
create temp table ev0 as select count(*) as n from public.outbox_events where type like 'shift%';
grant all on ev0 to public;
-- new open shift on a published schedule: shift.opened (via manager)
insert into ids select 'pub_open', public.create_shift(pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(6, '09:00'), pg_temp.a1(6, '12:00'));
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'shift.opened' and entity_id = pg_temp.gid('pub_open') and payload ->> 'via' = 'manager'), 1::bigint, 'a new open shift on a published week: one shift.opened (via manager)');
select is((select array_agg(k order by k) from (select distinct jsonb_object_keys(payload) k from public.outbox_events where type = 'shift.opened') x),
  array['actor_person_id', 'anchor_at', 'ends_at', 'location_id', 'person_id', 'position_id', 'schedule_id', 'shift_id', 'starts_at', 'via'], 'the shift.opened payload: ids, times, via and the actor, no notes');
select pg_temp.act_as('u_manager_a1');
select public.assign_shift(pg_temp.gid('pub_open'), pg_temp.id('p_s6'));
select pg_temp.act_as('postgres');
select results_eq($$select type, payload ->> 'person_id', payload ->> 'via', payload ->> 'override', payload ->> 'previous_person_id' from public.outbox_events where entity_id = pg_temp.gid('pub_open') and type = 'shift.assigned'$$,
  $$values ('shift.assigned'::text, pg_temp.id('p_s6')::text, 'manager'::text, 'false'::text, null::text)$$, 'assigning it: one shift.assigned for s6 (via manager, no override, no previous person)');
select is((select count(*) from public.outbox_events where entity_id = pg_temp.gid('pub_open') and type = 'shift.unassigned'), 0::bigint, 'and no shift.unassigned (nobody lost it)');
select pg_temp.act_as('u_manager_a1');
select public.assign_shift(pg_temp.gid('pub_open'), pg_temp.id('p_s2'));
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where entity_id = pg_temp.gid('pub_open') and type = 'shift.unassigned' and payload ->> 'person_id' = pg_temp.id('p_s6')::text and payload ->> 'new_person_id' = pg_temp.id('p_s2')::text), 1::bigint, 'reassigning: s6 gets shift.unassigned naming s2');
select is((select count(*) from public.outbox_events where entity_id = pg_temp.gid('pub_open') and type = 'shift.assigned' and payload ->> 'person_id' = pg_temp.id('p_s2')::text and payload ->> 'previous_person_id' = pg_temp.id('p_s6')::text), 1::bigint, 'and s2 gets shift.assigned naming s6 as the previous holder');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L)', pg_temp.gid('pub_open'), pg_temp.id('p_s2'))), '22023 nothing to change', 'assigning the same person again is refused');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where entity_id = pg_temp.gid('pub_open') and type like 'shift.%' and type <> 'shift.opened'), 3::bigint, 'and emits nothing new (3 events in all: assigned, unassigned, assigned)');
select pg_temp.act_as('u_manager_a1');
select public.assign_shift(pg_temp.gid('pub_open'), null);
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where entity_id = pg_temp.gid('pub_open') and type = 'shift.unassigned' and payload ->> 'person_id' = pg_temp.id('p_s2')::text and (payload ->> 'new_person_id') is null), 1::bigint, 'opening it: s2 gets shift.unassigned with no new person');
select is((select count(*) from public.outbox_events where entity_id = pg_temp.gid('pub_open') and type = 'shift.opened'), 2::bigint, 'and the shift is announced as open again (2 shift.opened in all)');
-- time change on an assigned published shift: shift.changed with the previous values
select pg_temp.act_as('u_manager_a1');
select public.update_shift(pg_temp.gid('mon_s2'), null, pg_temp.a1(1, '09:30'), pg_temp.a1(1, '11:30'));
select pg_temp.act_as('postgres');
select results_eq($$select payload ->> 'person_id', (payload ->> 'previous_starts_at')::timestamptz, (payload ->> 'starts_at')::timestamptz from public.outbox_events where entity_id = pg_temp.gid('mon_s2') and type = 'shift.changed'$$,
  $$values (pg_temp.id('p_s2')::text, (select starts_at from public.shifts where id = pg_temp.gid('mon_s2') and false) , null::timestamptz)$$, 'x') where false;
select is((select count(*) from public.outbox_events where entity_id = pg_temp.gid('mon_s2') and type = 'shift.changed' and payload ->> 'person_id' = pg_temp.id('p_s2')::text and payload ? 'previous_starts_at' and payload ? 'previous_ends_at' and payload ? 'previous_position_id'), 1::bigint, 'a time change on an assigned published shift: one shift.changed for the holder with the previous time and position');
select pg_temp.act_as('u_manager_a1');
select public.update_shift(pg_temp.gid('mon_s2'), null, null, null, 'only the notes');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where entity_id = pg_temp.gid('mon_s2') and type = 'shift.changed'), 1::bigint, 'a notes-only edit announces nothing');
select pg_temp.act_as('u_manager_a1');
select public.update_shift(pg_temp.gid('pub_open'), null, pg_temp.a1(6, '10:00'), pg_temp.a1(6, '12:00'));
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where entity_id = pg_temp.gid('pub_open') and type = 'shift.changed'), 0::bigint, 'changing an open shift emits no shift.changed (nobody holds it)');
-- cancel
select pg_temp.act_as('u_manager_a1');
select public.cancel_shift(pg_temp.gid('mon_s2'));
select is(pg_temp.fd(format('select public.cancel_shift(%L)', pg_temp.gid('mon_s2'))), '22023 this shift is already cancelled', 'cancelling twice is refused (22023)');
select is(pg_temp.fd(format('select public.update_shift(%L, null, null, null, %L)', pg_temp.gid('mon_s2'), 'late note')), '22023 a cancelled shift cannot be changed', 'a cancelled shift cannot be changed');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L)', pg_temp.gid('mon_s2'), pg_temp.id('p_s4'))), '22023 a cancelled shift cannot be assigned', 'nor assigned');
select pg_temp.act_as('postgres');
select results_eq($$select type, payload ->> 'person_id' from public.outbox_events where entity_id = pg_temp.gid('mon_s2') and type = 'shift.cancelled'$$, $$values ('shift.cancelled'::text, pg_temp.id('p_s2')::text)$$, 'one shift.cancelled naming the person who held it');
select is((select status from public.shifts where id = pg_temp.gid('mon_s2')), 'cancelled', 'the shift is cancelled, not deleted (it is published)');
select pg_temp.act_as('u_manager_a1');
-- a cancelled shift frees its holder's time
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(1, '09:30'), pg_temp.a1(1, '11:30'), pg_temp.id('p_s2'))), 'ok', 'twin: a cancelled shift no longer blocks its holder (no overlap with it)');
select pg_temp.act_as('postgres');
-- a draft shift is deleted on cancel, with no event
insert into public.schedules (id, organization_id, location_id, week_start) values (pg_temp.id('sched_next'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 7);
select pg_temp.act_as('u_manager_a1');
insert into ids select 'dshift', public.create_shift(pg_temp.id('sched_next'), pg_temp.gid('pos_fd'), pg_temp.a1(7, '09:00'), pg_temp.a1(7, '12:00'), pg_temp.id('p_s2'));
select public.cancel_shift(pg_temp.gid('dshift'));
select pg_temp.act_as('postgres');
select is((select count(*) from public.shifts where id = pg_temp.gid('dshift')), 0::bigint, 'cancelling a draft shift deletes it');
select is((select count(*) from public.outbox_events where entity_id = pg_temp.gid('dshift')), 0::bigint, 'with no event');
select ok(exists (select 1 from public.audit_log where table_name = 'shifts' and row_id = pg_temp.gid('dshift')::text and action = 'delete'), 'and the delete is audited');
select is((select count(*) from public.outbox_events e where e.type like 'shift%' and e.entity_table <> 'shifts'), 0::bigint, 'every shift.* event is about a shift');
select is((select count(*) from public.outbox_events e, jsonb_object_keys(e.payload) k where e.type like 'shift%' and k in ('notes', 'note', 'reason', 'name', 'title')), 0::bigint, 'no free-text key in any shift payload');
select ok(not exists (select 1 from public.outbox_events e where (e.type like 'shift%' or e.type like 'schedule%') and not private.validate_event_payload(e.payload)), 'every shift and schedule payload passes the id-only payload check');

-- audit redaction
select is((select new_row ->> 'notes' from public.audit_log where table_name = 'shifts' and action = 'insert' and row_id = pg_temp.gid('open1')::text), '[redacted]', 'shift notes are redacted in the audit log');
select is((select count(*) from public.audit_log a where a.table_name in ('shifts', 'shift_template_items') and (a.new_row::text like '%NOTE-OPEN%' or a.new_row::text like '%TEMPLATE-NOTE%' or a.old_row::text like '%NOTE-OPEN%')), 0::bigint, 'and the note text appears nowhere in the audit log');
select is((select new_row ->> 'name' from public.audit_log where table_name = 'positions' and action = 'insert' limit 1), '[redacted]', 'position names are redacted');
select is((select new_row ->> 'name' from public.audit_log where table_name = 'qualifications' and action = 'insert' limit 1), '[redacted]', 'qualification names are redacted');
select is((select new_row ->> 'name' from public.audit_log where table_name = 'shift_templates' and action = 'insert' limit 1), '[redacted]', 'template names are redacted');

select * from finish();
rollback;
