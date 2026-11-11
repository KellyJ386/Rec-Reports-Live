-- Phase 3 (staff scheduling, 20261113000100): tenant isolation and location scoping for the 12 staffing tables, no direct writes for any
-- role, and the configuration RPCs (qualifications, positions, who holds what, shift templates). Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(152);

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

-- BEGIN PHASE 3 ROWS: byte-identical in every file that uses it (020, 050, 090, 100).
-- Phase 3 rows: one row in each of the 12 staffing tables, in both organizations, written with the
-- owner's rights (the API roles cannot write these tables; every write is an RPC). Far-future fixed week
-- (Monday 2030-01-07). Org A at A1: staff A1 holds a published shift and asked to drop it, and asked for the
-- open shift; org B at B1: the same for staff B1.
insert into public.qualifications (id, organization_id, name)
select pg_temp.id('q_' || v.k), pg_temp.id(v.org), 'Qualification ' || v.k from (values ('a', 'org_a'), ('b', 'org_b')) v (k, org);
insert into public.positions (id, organization_id, location_id, name)
select pg_temp.id('pos_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), 'Position ' || v.k
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.position_qualifications (organization_id, position_id, qualification_id)
select pg_temp.id(v.org), pg_temp.id('pos_' || v.k), pg_temp.id('q_' || v.k) from (values ('a', 'org_a'), ('b', 'org_b')) v (k, org);
insert into public.person_qualifications (organization_id, person_id, qualification_id, valid_from, expires_on)
select pg_temp.id(v.org), pg_temp.id(v.person), pg_temp.id('q_' || v.k), date '2029-01-01', date '2031-01-01'
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, person);
insert into public.schedules (id, organization_id, location_id, week_start, status, published_at)
select pg_temp.id('sched_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), date '2030-01-07', 'published', now()
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id)
select pg_temp.id('shift_' || v.k || v.n), pg_temp.id(v.org), pg_temp.id(v.loc), pg_temp.id('sched_' || v.k), pg_temp.id('pos_' || v.k),
       v.s::timestamptz, v.e::timestamptz, case when v.n = '1' then pg_temp.id(v.person) end
from (values ('a', '1', 'org_a', 'loc_a1', 'p_staff_a1', '2030-01-08 09:00-05', '2030-01-08 17:00-05'),
             ('a', '2', 'org_a', 'loc_a1', 'p_staff_a1', '2030-01-09 09:00-05', '2030-01-09 17:00-05'),
             ('b', '1', 'org_b', 'loc_b1', 'p_staff_b1', '2030-01-08 09:00-07', '2030-01-08 17:00-07'),
             ('b', '2', 'org_b', 'loc_b1', 'p_staff_b1', '2030-01-09 09:00-07', '2030-01-09 17:00-07')) v (k, n, org, loc, person, s, e);
insert into public.shift_templates (id, organization_id, location_id, name)
select pg_temp.id('stpl_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), 'Week ' || v.k
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.shift_template_items (organization_id, location_id, template_id, position_id, day_offset, start_time, duration_minutes)
select pg_temp.id(v.org), pg_temp.id(v.loc), pg_temp.id('stpl_' || v.k), pg_temp.id('pos_' || v.k), 0, time '09:00', 480
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.availability (organization_id, person_id, day_of_week, start_time, end_time, kind)
select pg_temp.id(v.org), pg_temp.id(v.person), 1, time '09:00', time '17:00', 'available'
from (values ('org_a', 'p_staff_a1'), ('org_b', 'p_staff_b1')) v (org, person);
insert into public.time_off_requests (organization_id, person_id, starts_on, ends_on, reason)
select pg_temp.id(v.org), pg_temp.id(v.person), date '2030-02-01', date '2030-02-02', 'Reason ' || v.person
from (values ('org_a', 'p_staff_a1'), ('org_b', 'p_staff_b1')) v (org, person);
insert into public.shift_swaps (organization_id, location_id, kind, shift_id, from_person_id)
select pg_temp.id(v.org), pg_temp.id(v.loc), 'drop', pg_temp.id('shift_' || v.k || '1'), pg_temp.id(v.person)
from (values ('a', 'org_a', 'loc_a1', 'p_staff_a1'), ('b', 'org_b', 'loc_b1', 'p_staff_b1')) v (k, org, loc, person);
insert into public.shift_claims (organization_id, location_id, shift_id, person_id)
select pg_temp.id(v.org), pg_temp.id(v.loc), pg_temp.id('shift_' || v.k || '2'), pg_temp.id(v.person)
from (values ('a', 'org_a', 'loc_a1', 'p_staff_a1'), ('b', 'org_b', 'loc_b1', 'p_staff_b1')) v (k, org, loc, person);

-- END PHASE 3 ROWS


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


-- ===========================================================================
-- 1. No role can write the staffing tables directly; RLS is on
-- ===========================================================================
create temp table st (t text);
insert into st values ('positions'), ('qualifications'), ('position_qualifications'), ('person_qualifications'), ('schedules'), ('shifts'),
  ('shift_templates'), ('shift_template_items'), ('availability'), ('time_off_requests'), ('shift_swaps'), ('shift_claims');
grant all on st to public;
select ok(c.relrowsecurity, st.t || ': row level security is on') from st join pg_class c on c.oid = ('public.' || st.t)::regclass order by st.t;
select is((select string_agg(r.rolname, ',' order by r.rolname) from pg_roles r where r.rolname in ('anon', 'authenticated', 'service_role')
            and has_table_privilege(r.rolname, 'public.' || st.t, 'insert,update,delete,truncate,references,trigger')), null,
  st.t || ': no API role has any write privilege') from st order by st.t;
-- (service_role still has SELECT on every table, like the Phase 1 and 2 tables: the known open item "revoke service_role direct reads")
select is((select string_agg(r.rolname, ',' order by r.rolname) from pg_roles r where r.rolname in ('anon', 'authenticated', 'service_role')
            and has_table_privilege(r.rolname, 'public.' || st.t, 'select')), 'authenticated,service_role', st.t || ': readable by authenticated (through RLS) and service_role, never by anon') from st order by st.t;
-- direct writes are refused for a real user (42501), whatever the row
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd($$insert into public.availability (organization_id, person_id, day_of_week, start_time, end_time, kind) values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), 2, '09:00', '10:00', 'available')$$),
  '42501 permission denied for table availability', 'a user cannot insert an availability row directly (use add_availability)');
select is(pg_temp.fd($$update public.shifts set notes = 'x'$$), '42501 permission denied for table shifts', 'a user cannot update a shift directly');
select is(pg_temp.fd($$delete from public.shifts$$), '42501 permission denied for table shifts', 'a user cannot delete a shift directly');
select is(pg_temp.fd($$update public.shift_swaps set status = 'approved'$$), '42501 permission denied for table shift_swaps', 'a user cannot approve a swap directly');
select is(pg_temp.fd($$update public.time_off_requests set status = 'approved'$$), '42501 permission denied for table time_off_requests', 'a manager cannot approve time off directly');
select pg_temp.act_as('service_role');
select is(pg_temp.fd($$update public.shifts set assigned_person_id = null$$), '42501 permission denied for table shifts', 'the server key cannot write a shift directly either');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 2. Read matrix: org A / org B rows seen by each reader (the Phase 3 fixture rows)
-- ===========================================================================
create temp table rd (who text, aal text, note text, expect text);
-- expect: 12 table results as "a/b" per table in this order: positions, qualifications, position_qualifications, person_qualifications,
-- schedules, shifts, shift_templates, shift_template_items, availability, time_off_requests, shift_swaps, shift_claims
insert into rd values
  ('u_orgadmin_a',  'aal2', 'org admin A: everything of A, nothing of B',                   '1/0 1/0 1/0 1/0 1/0 2/0 1/0 1/0 1/0 1/0 1/0 1/0'),
  ('u_manager_a1',  'aal2', 'manager A1 (admin of the three staffing modules at A1)',       '1/0 1/0 1/0 1/0 1/0 2/0 1/0 1/0 1/0 1/0 1/0 1/0'),
  ('u_locadmin_a1', 'aal2', 'location admin A1',                                            '1/0 1/0 1/0 1/0 1/0 2/0 1/0 1/0 1/0 1/0 1/0 1/0'),
  ('u_staff_a1',    'aal2', 'staff A1 (owns the rows; no template access)',                 '1/0 1/0 1/0 1/0 1/0 2/0 0/0 0/0 1/0 1/0 1/0 1/0'),
  ('u_s2',          'aal2', 'another staff member at A1: the published schedule only',      '1/0 1/0 1/0 0/0 1/0 2/0 0/0 0/0 0/0 0/0 0/0 0/0'),
  ('u_staff_a2',    'aal2', 'staff at A2: configuration names only, no A1 schedule or rows', '1/0 1/0 1/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0'),
  ('u_orgadmin_b',  'aal2', 'org admin B: nothing of A',                                    '0/1 0/1 0/1 0/1 0/1 0/2 0/1 0/1 0/1 0/1 0/1 0/1'),
  ('u_platform',    'aal2', 'platform admin: both organizations',                           '1/1 1/1 1/1 1/1 1/1 2/2 1/1 1/1 1/1 1/1 1/1 1/1'),
  ('u_orgadmin_a',  'aal1', 'org admin A at aal1 (a non-member)',                           '0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0'),
  ('u_noaccount',   'aal2', 'a user with no account',                                       '0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0 0/0'),
  ('anon',          'aal2', 'anon (no privilege)',                                          '-1/-1 -1/-1 -1/-1 -1/-1 -1/-1 -1/-1 -1/-1 -1/-1 -1/-1 -1/-1 -1/-1 -1/-1');
grant all on rd to public;
create temp table rd_got (who text, aal text, got text);
grant all on rd_got to public;
do $$
declare r record; t text; v text;
begin
  for r in select * from rd loop
    perform pg_temp.act_as(r.who, r.aal);
    v := '';
    for t in select x.t from (values (1, 'positions'), (2, 'qualifications'), (3, 'position_qualifications'), (4, 'person_qualifications'), (5, 'schedules'), (6, 'shifts'),
                                     (7, 'shift_templates'), (8, 'shift_template_items'), (9, 'availability'), (10, 'time_off_requests'), (11, 'shift_swaps'), (12, 'shift_claims')) x (n, t) order by x.n loop
      v := v || case when v = '' then '' else ' ' end ||
           pg_temp.cnt(t, format('organization_id = %L', pg_temp.id('org_a'))) || '/' || pg_temp.cnt(t, format('organization_id = %L', pg_temp.id('org_b')));
    end loop;
    insert into rd_got values (r.who, r.aal, v);
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select g.got from rd_got g where g.who = r.who and g.aal = r.aal), r.expect, 'reads of the 12 staffing tables: ' || r.note) from rd r;
-- location scoping of the other location: a draft schedule at A1 is invisible to staff, visible to the manager; staff at A2 never see A1 rows
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.f($$select public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk())$$) ~ '^[0-9a-f-]{36}$', true, 'manager A1 creates a draft schedule for next week');
insert into ids select 'draft_sched', id from public.schedules where location_id = pg_temp.id('loc_a1') and week_start = pg_temp.wk();
select pg_temp.act_as('postgres');
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id, notes)
values (pg_temp.id('draft_shift'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.gid('draft_sched'), pg_temp.id('pos_a'), pg_temp.a1(1, '09:00'), pg_temp.a1(1, '17:00'), pg_temp.id('p_staff_a1'), 'DRAFT-NOTES');
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.schedules where id = pg_temp.gid('draft_sched')), 0::bigint, 'staff A1 cannot see the draft schedule');
select is((select count(*) from public.shifts where id = pg_temp.id('draft_shift')), 0::bigint, 'nor their own draft shift');
select pg_temp.act_as('u_manager_a1');
select is((select count(*) from public.schedules where id = pg_temp.gid('draft_sched')), 1::bigint, 'twin: the manager sees the draft schedule');
select is((select notes from public.shifts where id = pg_temp.id('draft_shift')), 'DRAFT-NOTES', 'and the draft shift with its notes');
select pg_temp.act_as('u_staff_a2');
select is((select count(*) from public.shifts where location_id = pg_temp.id('loc_a1')), 0::bigint, 'staff at A2 see no shift of A1');
select pg_temp.act_as('u_orgadmin_b');
select is((select count(*) from public.schedules where id = pg_temp.gid('draft_sched')), 0::bigint, 'org B admin cannot see org A''s draft either');
select pg_temp.act_as('postgres');

-- cancelled published shifts: staff see only their own
update public.shifts set status = 'cancelled', cancelled_at = now() where id = pg_temp.id('shift_a2');
update public.shifts set status = 'cancelled', cancelled_at = now() where id = pg_temp.id('shift_a1');
select pg_temp.act_as('u_s2');
select is((select count(*) from public.shifts where id in (pg_temp.id('shift_a1'), pg_temp.id('shift_a2'))), 0::bigint, 'a cancelled shift is hidden from other staff');
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.shifts where id in (pg_temp.id('shift_a1'), pg_temp.id('shift_a2'))), 1::bigint, 'twin: staff A1 still sees their own cancelled shift (not the open one)');
select pg_temp.act_as('u_manager_a1');
select is((select count(*) from public.shifts where id in (pg_temp.id('shift_a1'), pg_temp.id('shift_a2'))), 2::bigint, 'and the manager sees both');
select pg_temp.act_as('postgres');
update public.shifts set status = 'scheduled', cancelled_at = null where id in (pg_temp.id('shift_a1'), pg_temp.id('shift_a2'));

-- another person's time off reason and availability
select pg_temp.act_as('u_s2');
select is((select count(*) from public.time_off_requests), 0::bigint, 'staff s2 cannot read staff A1''s time off (or its reason)');
select is((select count(*) from public.availability), 0::bigint, 'nor their availability');
select pg_temp.act_as('u_staff_a1');
select is((select reason from public.time_off_requests), 'Reason p_staff_a1', 'twin: staff A1 reads their own reason');
select pg_temp.act_as('u_locadmin_a1');
select is((select reason from public.time_off_requests), 'Reason p_staff_a1', 'and the A1 admin (availability_time_off admin over them) reads it');
select pg_temp.act_as('u_staff_a2');
select is((select count(*) from public.time_off_requests), 0::bigint, 'an admin of nobody here: staff at A2 read none');
select pg_temp.act_as('postgres');
-- a location admin at A1 does not reach people at A2: give staff A2 a request and look from A1
insert into public.time_off_requests (id, organization_id, person_id, starts_on, ends_on, reason) values
  (pg_temp.id('to_a2'), pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), date '2030-03-01', date '2030-03-02', 'A2 reason');
select pg_temp.act_as('u_locadmin_a1');
select is((select count(*) from public.time_off_requests where id = pg_temp.id('to_a2')), 0::bigint, 'a location admin at A1 cannot read time off of someone assigned only at A2');
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.time_off_requests where id = pg_temp.id('to_a2')), 1::bigint, 'twin: the org admin can');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 3. Qualifications and positions
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.f($$select public.save_qualification(pg_temp.id('org_a'), 'Lifeguard cert')$$) ~ '^[0-9a-f-]{36}$', true, 'manager A1 (staff_schedule admin at A1) creates a qualification');
insert into ids select 'q', id from public.qualifications where name = 'Lifeguard cert';
select is(pg_temp.fd($$select public.save_qualification(pg_temp.id('org_a'), '  lifeguard CERT ')$$), '22023 a qualification with that name already exists', 'a duplicate name (any case, trimmed) is refused');
select is(pg_temp.fd($$select public.save_qualification(pg_temp.id('org_a'), '   ')$$), '22023 a name needs 1 to 100 characters', 'a blank name is refused');
select is(pg_temp.fd(format('select public.save_qualification(pg_temp.id(%L), %L)', 'org_a', repeat('x', 101))), '22023 a name needs 1 to 100 characters', 'a 101 character name is refused');
select is(pg_temp.fd(format('select public.save_qualification(pg_temp.id(%L), %L, %L)', 'org_a', 'Lifeguard cert 2', pg_temp.gid('q'))), 'ok', 'twin: renaming it works');
select is(pg_temp.fd(format('select public.save_qualification(pg_temp.id(%L), %L, %L)', 'org_a', 'Lifeguard cert', pg_temp.gid('q'))), 'ok', 'and back');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd($$select public.save_qualification(pg_temp.id('org_a'), 'Staff cert')$$), '42501 not allowed', 'staff cannot create a qualification');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd($$select public.save_qualification(pg_temp.id('org_a'), 'B cert')$$), '42501 not allowed', 'an admin of another organization cannot');
select pg_temp.act_as('anon');
select is(pg_temp.fd($$select public.save_qualification(pg_temp.id('org_a'), 'Anon cert')$$), '42501 permission denied for function save_qualification', 'anon has no execute right');
select pg_temp.act_as('postgres');
select is((select count(*) from public.qualifications where name in ('Staff cert', 'B cert', 'Anon cert')), 0::bigint, 'none of the refused ones exist');

select pg_temp.act_as('u_manager_a1');
select is(pg_temp.f(format('select public.save_position(pg_temp.id(%L), pg_temp.id(%L), %L, array[%L]::uuid[])', 'org_a', 'loc_a1', 'Lifeguard', pg_temp.gid('q'))) ~ '^[0-9a-f-]{36}$', true, 'manager A1 creates the position Lifeguard at A1 requiring the certificate');
insert into ids select 'pos_lg', id from public.positions where name = 'Lifeguard' and organization_id = pg_temp.id('org_a');
select is(pg_temp.f($$select public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Front desk')$$) ~ '^[0-9a-f-]{36}$', true, 'and Front desk with no requirement');
insert into ids select 'pos_fd', id from public.positions where name = 'Front desk' and organization_id = pg_temp.id('org_a');
select is((select count(*) from public.position_qualifications where position_id = pg_temp.gid('pos_lg')), 1::bigint, 'Lifeguard requires the certificate');
select is(pg_temp.fd(format('select public.save_position(pg_temp.id(%L), null, %L)', 'org_a', 'Org wide')), '42501 not allowed', 'a manager cannot create an organization-wide position (needs org scope)');
select is(pg_temp.fd($$select public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'At A2')$$), '42501 not allowed', 'nor one at a location they do not run (A2)');
select is(pg_temp.fd($$select public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'LIFEGUARD')$$), '22023 a position with that name already exists', 'a duplicate position name at the same location is refused');
select is(pg_temp.fd(format('select public.save_position(pg_temp.id(%L), pg_temp.id(%L), %L, array[%L]::uuid[])', 'org_a', 'loc_a1', 'Bad requirement', gen_random_uuid())), '22023 unknown qualification', 'an unknown qualification is refused');
select is(pg_temp.fd(format('select public.save_position(pg_temp.id(%L), pg_temp.id(%L), %L, null, %L)', 'org_a', 'loc_a2', 'Moved', pg_temp.gid('pos_fd'))), '22023 the location of a position cannot change', 'a position cannot move to another location');
select is(pg_temp.fd(format('select public.save_position(pg_temp.id(%L), pg_temp.id(%L), %L, array[]::uuid[], %L)', 'org_a', 'loc_a1', 'Front desk', pg_temp.gid('pos_fd'))), 'ok', 'twin: saving it again with an empty list keeps it with no requirements');
select is(pg_temp.fd(format('select public.save_position(pg_temp.id(%L), pg_temp.id(%L), %L, null, %L)', 'org_a', 'loc_a1', 'Lifeguard', pg_temp.gid('pos_lg'))), 'ok', 'a null list keeps the requirements');
select is((select count(*) from public.position_qualifications where position_id = pg_temp.gid('pos_lg')), 1::bigint, 'and they are still there');
select is(pg_temp.fd(format('select public.archive_qualification(%L)', pg_temp.gid('q'))), '22023 a position still requires this qualification', 'a qualification a position requires cannot be archived');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.f($$select public.save_position(pg_temp.id('org_a'), null, 'Org wide')$$) ~ '^[0-9a-f-]{36}$', true, 'twin: the org admin creates an organization-wide position');
insert into ids select 'pos_ow', id from public.positions where name = 'Org wide';
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.positions where id = pg_temp.gid('pos_ow')), 1::bigint, 'and staff read it (it serves every location)');
select is(pg_temp.fd(format('select public.archive_position(%L)', pg_temp.gid('pos_lg'))), '42501 not allowed', 'staff cannot archive a position');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.archive_position(%L)', pg_temp.gid('pos_ow'))), '42501 not allowed', 'a manager cannot archive the organization-wide one');
select is(pg_temp.fd(format('select public.archive_position(%L)', pg_temp.gid('pos_fd'))), 'ok', 'twin: but can archive their own location''s');
select is((select archived_at is not null from public.positions where id = pg_temp.gid('pos_fd')), true, 'it is archived');
select is(pg_temp.fd(format('select public.archive_position(%L, false)', pg_temp.gid('pos_fd'))), 'ok', 'and can be brought back');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.archive_position(%L)', pg_temp.gid('pos_lg'))), '42501 not allowed', 'org B admin cannot archive org A''s position');
select is(pg_temp.fd(format('select public.archive_position(%L)', gen_random_uuid())), '42501 not allowed', 'and an unknown id gives the very same refusal');
select pg_temp.act_as('u_manager_a1');
-- more than 20 requirements
insert into ids select 'many_q' || g, public.save_qualification(pg_temp.id('org_a'), 'Extra cert ' || g) from generate_series(1, 21) g;
select is(pg_temp.fd(format('select public.save_position(pg_temp.id(%L), pg_temp.id(%L), %L, (select array_agg(v) from ids where k like %L))', 'org_a', 'loc_a1', 'Too many', 'many_q%')), '22023 at most 20 qualifications', 'a position takes at most 20 qualifications');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 4. Who holds what
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.f(format('select public.set_person_qualification(pg_temp.id(%L), pg_temp.id(%L), %L, current_date - 30, current_date + 365)', 'org_a', 'p_staff_a1', pg_temp.gid('q'))) ~ '^[0-9a-f-]{36}$', true, 'manager A1 records the certificate for staff A1');
insert into ids select 'pq1', id from public.person_qualifications where person_id = pg_temp.id('p_staff_a1') and qualification_id = pg_temp.gid('q');
select is(pg_temp.f(format('select public.set_person_qualification(pg_temp.id(%L), pg_temp.id(%L), %L, current_date - 30, current_date + 400)', 'org_a', 'p_staff_a1', pg_temp.gid('q')))::uuid, pg_temp.gid('pq1'), 'recording it again renews the same row (upsert)');
select is((select expires_on from public.person_qualifications where id = pg_temp.gid('pq1')), current_date + 400, 'with the new expiry');
select is(pg_temp.fd(format('select public.set_person_qualification(pg_temp.id(%L), pg_temp.id(%L), %L)', 'org_a', 'p_manager_a1', pg_temp.gid('q'))), '42501 you cannot change your own qualifications', 'nobody records their own qualification (even an admin)');
select is(pg_temp.fd(format('select public.set_person_qualification(pg_temp.id(%L), pg_temp.id(%L), %L)', 'org_a', 'p_staff_a2', pg_temp.gid('q'))), '42501 not allowed', 'a manager cannot record one for someone at A2 (not visible to them)');
select is(pg_temp.fd(format('select public.set_person_qualification(pg_temp.id(%L), pg_temp.id(%L), %L)', 'org_a', 'p_staff_b1', pg_temp.gid('q'))), '42501 not allowed', 'nor for a person of another organization (same message)');
select is(pg_temp.fd(format('select public.set_person_qualification(pg_temp.id(%L), pg_temp.id(%L), %L, current_date + 5, current_date)', 'org_a', 'p_s2', pg_temp.gid('q'))) ~ '^(22023|23514)', true, 'an expiry before the start is refused');
select is(pg_temp.fd(format('select public.set_person_qualification(pg_temp.id(%L), pg_temp.id(%L), %L)', 'org_a', 'p_s2', gen_random_uuid())), '22023 unknown qualification', 'an unknown qualification is refused');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.set_person_qualification(pg_temp.id(%L), pg_temp.id(%L), %L)', 'org_a', 'p_s2', pg_temp.gid('q'))), '42501 not allowed', 'staff cannot record a qualification for a colleague');
select is(pg_temp.fd(format('select public.remove_person_qualification(%L)', pg_temp.gid('pq1'))), '42501 not allowed', 'nor remove their own');
select is((select count(*) from public.person_qualifications where qualification_id = pg_temp.gid('q')), 1::bigint, 'staff A1 reads their own qualification record');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.f(format('select public.set_person_qualification(pg_temp.id(%L), pg_temp.id(%L), %L)', 'org_a', 'p_staff_a2', pg_temp.gid('q'))) ~ '^[0-9a-f-]{36}$', true, 'twin: the org admin can record one for staff A2');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.remove_person_qualification(%L)', (select id from public.person_qualifications where person_id = pg_temp.id('p_staff_a2')))), '42501 not allowed', 'a manager cannot remove it (A2 person not visible to them)');
select is(pg_temp.fd(format('select public.remove_person_qualification(%L)', pg_temp.gid('pq1'))), 'ok', 'twin: the manager removes staff A1''s');
select is((select count(*) from public.person_qualifications where id = pg_temp.gid('pq1')), 0::bigint, 'it is gone');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 5. Shift templates
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.f($$select public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Standard week', 7)$$) ~ '^[0-9a-f-]{36}$', true, 'manager A1 saves a week template at A1');
insert into ids select 'tpl', id from public.shift_templates where name = 'Standard week';
select is(pg_temp.f($$select public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Day pattern', 1)$$) ~ '^[0-9a-f-]{36}$', true, 'and a one-day template');
insert into ids select 'tpl1', id from public.shift_templates where name = 'Day pattern';
select is(pg_temp.fd($$select public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Three days', 3)$$), '22023 a template covers 1 day or 7 days', 'a template covers 1 or 7 days');
select is(pg_temp.fd(format('select public.save_shift_template(pg_temp.id(%L), pg_temp.id(%L), %L, 1, %L)', 'org_a', 'loc_a1', 'Standard week', pg_temp.gid('tpl'))), '22023 the length of a template cannot change', 'its length cannot change later');
select is(pg_temp.fd($$select public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'At A2', 7)$$), '42501 not allowed', 'a manager cannot make a template for A2');
select is(pg_temp.fd(format('select public.save_shift_template(pg_temp.id(%L), pg_temp.id(%L), %L)', 'org_a', 'loc_a1', repeat('n', 101))), '22023 a name needs 1 to 100 characters', 'a 101 character name is refused');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 0, %L, 480, %L)', pg_temp.gid('tpl'), pg_temp.gid('pos_lg'), '09:00', pg_temp.id('p_s2'))), 'ok', 'an item for s2 (no certificate) is fine in a template: assignment rules apply when it is stamped');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 7, %L, 480)', pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), '09:00')) ~ '^(22023|23514)', true, 'a day outside the week is refused');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 1, %L, 480)', pg_temp.gid('tpl1'), pg_temp.gid('pos_fd'), '09:00')), '22023 that day is outside the template', 'a day beyond a one-day template is refused');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 0, %L, 10)', pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), '09:00')), '22023 a shift needs a start time and 15 minutes to 24 hours', 'ten minutes is too short');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 0, %L, 1441)', pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), '09:00')), '22023 a shift needs a start time and 15 minutes to 24 hours', 'and 24 hours and a minute too long');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 0, %L, 480, %L)', pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), '09:00', pg_temp.id('p_staff_a2'))), '23514 that person cannot work at this location [not_member]', 'a template cannot name someone from another location (not_member)');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 0, %L, 480, null, %L)', pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), '09:00', repeat('n', 1001))), '22023 notes are too long', 'notes over 1000 characters are refused');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 0, %L, 480)', pg_temp.gid('tpl'), pg_temp.id('pos_b'), '09:00')) ~ '^22023', true, 'a position of another organization is refused');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 2, %L, 60)', pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), '10:00')), 'ok', 'twin: an open item is fine');
insert into ids select 'item', id from public.shift_template_items where template_id = pg_temp.gid('tpl') and day_offset = 2;
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 2, %L, 60)', pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), '11:00')), '42501 not allowed', 'staff cannot add an item');
select is(pg_temp.fd(format('select public.remove_shift_template_item(%L)', pg_temp.gid('item'))), '42501 not allowed', 'nor remove one');
select is(pg_temp.fd(format('select public.archive_shift_template(%L)', pg_temp.gid('tpl'))), '42501 not allowed', 'nor archive a template');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 2, %L, 60)', pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), '11:00')), '42501 not allowed', 'org B admin cannot add one to an org A template');
select is(pg_temp.fd(format('select public.remove_shift_template_item(%L)', pg_temp.gid('item'))), '42501 not allowed', 'nor remove it');
select is(pg_temp.fd(format('select public.remove_shift_template_item(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown item gives the same refusal');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.remove_shift_template_item(%L)', pg_temp.gid('item'))), 'ok', 'twin: the manager removes it');
select is((select count(*) from public.shift_template_items where template_id = pg_temp.gid('tpl')), 1::bigint, 'one item is left');
select is(pg_temp.fd(format('select public.archive_shift_template(%L)', pg_temp.gid('tpl1'))), 'ok', 'the manager archives the day template');
select is((select archived_at is not null from public.shift_templates where id = pg_temp.gid('tpl1')), true, 'it is archived');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 0, %L, 60)', pg_temp.gid('tpl1'), pg_temp.gid('pos_fd'), '09:00')), 'ok', 'an archived template can still be edited (it just cannot be stamped: see 240)');
-- 200 items at most
select pg_temp.act_as('postgres');
insert into public.shift_template_items (organization_id, location_id, template_id, position_id, day_offset, start_time, duration_minutes)
select pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 3, time '00:00' + g * interval '1 minute', 15 from generate_series(1, 199) g;
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.add_shift_template_item(%L, %L, 4, %L, 60)', pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), '09:00')), '22023 a template holds at most 200 shifts', 'a template holds at most 200 items');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 6. Uniform refusals: a missing id and another organization's id read the same
-- ===========================================================================
create temp table un (n int, call text);
insert into un values
  (1, 'select public.archive_qualification(%L)'), (2, 'select public.archive_position(%L)'), (3, 'select public.remove_person_qualification(%L)'),
  (4, 'select public.archive_shift_template(%L)'), (5, 'select public.remove_shift_template_item(%L)');
grant all on un to public;
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format(u.call, gen_random_uuid())), '42501 not allowed', 'org B admin, unknown id: ' || u.call) from un u order by u.n;
select is(pg_temp.fd(format(u.call, case u.n when 1 then pg_temp.id('q_a') when 2 then pg_temp.id('pos_a') when 3 then (select id from public.person_qualifications limit 0) else pg_temp.id('stpl_a') end)), '42501 not allowed', 'org B admin, org A id: ' || u.call) from un u where u.n <> 3 and u.n <> 5 order by u.n;
select pg_temp.act_as('postgres');

select * from finish();
rollback;
