-- Phase 3 (staff scheduling): the uncovered-shift sweep (once per open shift per start time, fair across organizations, finite arguments), the two
-- worker reads (who is told about each event; the shift an event is about), and the rules judged on the location's local calendar day across the
-- two weeks of the year that contain a clock change. Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(114);

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


create function pg_temp.mk(k text, p text, d int, t1 text, t2 text, who text default null, n text default null) returns void language plpgsql as $$
begin
  insert into ids values (k, public.create_shift(pg_temp.gid('sched'), pg_temp.gid(p), pg_temp.a1(d, t1), pg_temp.a1(d, t2),
                                                 case when who is null then null else pg_temp.id(who) end, n));
end $$;
create function pg_temp.ev(p_type text, p_entity text) returns bigint language sql stable as $$
  select count(*) from public.outbox_events where type = p_type and entity_id = pg_temp.gid(p_entity) $$;
create function pg_temp.eid(p_type text, p_entity text, p_has jsonb default '{}') returns uuid language sql stable security definer as $$
  select id from public.outbox_events where type = p_type and entity_id = pg_temp.gid(p_entity) and payload @> p_has order by id limit 1 $$;
create function pg_temp.pn(p_id uuid) returns text language sql stable as $$
  select coalesce((select n from unnest(array['p_s2', 'p_s3', 'p_s4', 'p_s5', 'p_s6', 'p_s7', 'p_staff_a1', 'p_staff_a2', 'p_manager_a1', 'p_locadmin_a1', 'p_orgadmin_a',
                                               'p_staff_b1', 'p_disabled_a', 'p_unassigned_a']) n where pg_temp.id(n) = p_id), p_id::text) $$;
-- who is told about an event, as "name:reason" sorted by name (as the service connection)
create function pg_temp.rc(p_event uuid) returns text language sql stable as $$
  select coalesce((select string_agg(pg_temp.pn(r.person_id) || ':' || r.reason, ',' order by pg_temp.pn(r.person_id) collate "C") from public.worker_shift_event_recipients(p_event) r), '') $$;
grant execute on function pg_temp.mk(text, text, int, text, text, text, text), pg_temp.ev(text, text), pg_temp.eid(text, text, jsonb), pg_temp.pn(uuid), pg_temp.rc(uuid) to public;

-- ---------------------------------------------------------------------------
-- Setup: org A week (published) with assigned and open shifts; org B week with two open shifts; shifts that must never be swept
-- ---------------------------------------------------------------------------
select pg_temp.act_as('postgres');
insert into public.people (id, organization_id, first_name, last_name, archived_at) values (pg_temp.id('p_s7'), pg_temp.id('org_a'), 'S7', 'Archived', now());
insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_s7'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'));
select pg_temp.act_as('u_manager_a1');
insert into ids select 'q', public.save_qualification(pg_temp.id('org_a'), 'Lifeguard cert');
insert into ids select 'pos_lg', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Lifeguard', array[pg_temp.gid('q')]);
insert into ids select 'pos_fd', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Front desk');
select public.set_person_qualification(pg_temp.id('org_a'), pg_temp.id(k), pg_temp.gid('q'), current_date - 30, current_date + 365) from unnest(array['p_s2', 'p_s3']) k;
select public.set_person_qualification(pg_temp.id('org_a'), pg_temp.id('p_s5'), pg_temp.gid('q'), current_date - 400, pg_temp.wk() - 1);
insert into ids select 'sched', public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk());
select pg_temp.mk('a1', 'pos_fd', 0, '09:00', '13:00', 'p_s2');
select pg_temp.mk('a2', 'pos_fd', 1, '09:00', '13:00', 'p_s3');
select pg_temp.mk('x1', 'pos_fd', 2, '15:00', '17:00', 'p_s2');
select pg_temp.mk('x2', 'pos_fd', 3, '15:00', '17:00', 'p_s3');
select pg_temp.mk('x3', 'pos_fd', 5, '15:00', '17:00', 'p_s3');
select pg_temp.mk('x4', 'pos_fd', 5, '09:00', '11:00', 'p_s2');
select public.publish_schedule(pg_temp.gid('sched'));
select pg_temp.mk('f1', 'pos_fd', 0, '15:00', '17:00');
select pg_temp.mk('f2', 'pos_fd', 1, '15:00', '17:00');
select pg_temp.mk('f3', 'pos_fd', 2, '19:00', '21:00');
select pg_temp.mk('f4', 'pos_fd', 3, '19:00', '21:00', null, 'UNCOV-NOTE');
select pg_temp.mk('oc', 'pos_lg', 4, '09:00', '13:00');
select pg_temp.mk('cx', 'pos_fd', 4, '14:00', '16:00');
select public.cancel_shift(pg_temp.gid('cx'));
select pg_temp.act_as('postgres');
-- shifts that must never be swept: a draft week, a week far past, a week beyond 14 days
insert into public.schedules (id, organization_id, location_id, week_start, status, published_at) values
  (pg_temp.id('sc_draft'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 7, 'draft', null),
  (pg_temp.id('sc_past'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() - 14, 'published', now() - interval '20 days'),
  (pg_temp.id('sc_far'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 14, 'published', now());
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at) values
  (pg_temp.id('n_draft'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('sc_draft'), pg_temp.gid('pos_fd'), pg_temp.a1(7, '12:00'), pg_temp.a1(7, '14:00')),
  (pg_temp.id('n_past'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('sc_past'), pg_temp.gid('pos_fd'), pg_temp.a1(-14, '12:00'), pg_temp.a1(-14, '14:00')),
  (pg_temp.id('n_far'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('sc_far'), pg_temp.gid('pos_fd'), pg_temp.a1(14, '12:00'), pg_temp.a1(14, '14:00'));
-- org B: two open shifts late in the week (after all of org A's, so only a fair sweep reaches them first)
insert into public.positions (id, organization_id, name) values (pg_temp.id('pos_b'), pg_temp.id('org_b'), 'B desk');
insert into public.schedules (id, organization_id, location_id, week_start, status, published_at) values (pg_temp.id('sc_b'), pg_temp.id('org_b'), pg_temp.id('loc_b1'), pg_temp.wk(), 'published', now());
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at) values
  (pg_temp.id('bf1'), pg_temp.id('org_b'), pg_temp.id('loc_b1'), pg_temp.id('sc_b'), pg_temp.id('pos_b'), ((pg_temp.wk() + 5)::timestamp + time '12:00') at time zone 'America/Denver', ((pg_temp.wk() + 5)::timestamp + time '14:00') at time zone 'America/Denver'),
  (pg_temp.id('bf2'), pg_temp.id('org_b'), pg_temp.id('loc_b1'), pg_temp.id('sc_b'), pg_temp.id('pos_b'), ((pg_temp.wk() + 6)::timestamp + time '12:00') at time zone 'America/Denver', ((pg_temp.wk() + 6)::timestamp + time '14:00') at time zone 'America/Denver');
insert into ids values ('bf1', pg_temp.id('bf1')), ('bf2', pg_temp.id('bf2')), ('n_draft', pg_temp.id('n_draft')), ('n_past', pg_temp.id('n_past')), ('n_far', pg_temp.id('n_far'));
select is((select count(*) from public.outbox_events where type = 'shift.uncovered'), 0::bigint, 'sanity: nothing is uncovered yet');

-- ===========================================================================
-- 1. emit_uncovered_shift_events: who may call it, and finite arguments
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd($$select public.emit_uncovered_shift_events(interval '14 days')$$), '42501 permission denied for function emit_uncovered_shift_events', 'a signed-in manager cannot run the sweep');
select pg_temp.act_as('anon');
select is(pg_temp.fd($$select public.emit_uncovered_shift_events(interval '14 days')$$), '42501 permission denied for function emit_uncovered_shift_events', 'nor anon');
select pg_temp.act_as_service('u_manager_a1');
select is(pg_temp.fd($$select public.emit_uncovered_shift_events(interval '14 days')$$), '42501 not allowed', 'the service key with a user token is refused as well (42501)');
select pg_temp.act_as('service_role');
select is(pg_temp.fd($$select public.emit_uncovered_shift_events(null)$$), '22023 invalid window', 'a missing window is refused (22023)');
select is(pg_temp.fd($$select public.emit_uncovered_shift_events(interval '59 seconds')$$), '22023 invalid window', 'a window under a minute');
select is(pg_temp.fd($$select public.emit_uncovered_shift_events(interval '14 days 1 second')$$), '22023 invalid window', 'a window over 14 days');
select is(pg_temp.fd($$select public.emit_uncovered_shift_events(interval '-1 day')$$), '22023 invalid window', 'a negative window');
select is(pg_temp.fd($$select public.emit_uncovered_shift_events(interval '14 days', null)$$), '22023 invalid limit', 'a missing limit (22023)');
select is(pg_temp.fd($$select public.emit_uncovered_shift_events(interval '14 days', 0)$$), '22023 invalid limit', 'a limit of 0');
select is(pg_temp.fd($$select public.emit_uncovered_shift_events(interval '14 days', 5001)$$), '22023 invalid limit', 'a limit over 5000');
select is(pg_temp.f($$select public.emit_uncovered_shift_events(interval '1 minute', 5000)$$), '0', 'twin: the boundaries (1 minute, limit 5000) are accepted, and nothing starts within a minute');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'shift.uncovered'), 0::bigint, 'the refused calls emitted nothing');

-- ===========================================================================
-- 2. The sweep: fairness, exclusions, once per start time
-- ===========================================================================
select pg_temp.act_as('service_role');
select is(public.emit_uncovered_shift_events(interval '14 days', 4), 4, 'a sweep with limit 4 emits 4');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'shift.uncovered' and organization_id = pg_temp.id('org_a')), 2::bigint, 'two for org A...');
select is((select count(*) from public.outbox_events where type = 'shift.uncovered' and organization_id = pg_temp.id('org_b')), 2::bigint, '...and two for org B (round robin: the busy organization does not take all four)');
select is((select count(*) from public.outbox_events where type = 'shift.uncovered' and entity_id in (pg_temp.gid('f1'), pg_temp.gid('f2'), pg_temp.gid('bf1'), pg_temp.gid('bf2'))), 4::bigint, 'the soonest open shift of each organization first (f1, f2, bf1, bf2)');
select pg_temp.act_as('service_role');
select is(public.emit_uncovered_shift_events(interval '14 days', 100), 3, 'twin: the next sweep emits the 3 that remain in org A (f3, f4, the lifeguard shift)');
select is(public.emit_uncovered_shift_events(interval '14 days', 100), 0, 'and then nothing more (once per open shift per start time)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'shift.uncovered'), 7::bigint, 'seven events in all');
select is((select count(*) from public.outbox_events where type = 'shift.uncovered' and entity_id in (pg_temp.gid('n_draft'), pg_temp.gid('n_past'), pg_temp.gid('n_far'), pg_temp.gid('cx'), pg_temp.gid('a1'), pg_temp.gid('x1'))), 0::bigint,
  'never for a draft week, a past shift, a shift more than 14 days away, a cancelled shift or an assigned shift');
select is((select array_agg(k order by k) from (select distinct jsonb_object_keys(payload) k from public.outbox_events where type = 'shift.uncovered') x),
  array['actor_person_id', 'anchor_at', 'ends_at', 'location_id', 'person_id', 'position_id', 'schedule_id', 'shift_id', 'starts_at'], 'the payload is ids and times only');
select is((select count(*) from public.outbox_events e where e.type like 'shift.%' and e.payload::text like '%UNCOV-NOTE%'), 0::bigint, 'the shift note is in no payload');
select is((select count(distinct e.entity_id) from public.outbox_events e where e.type = 'shift.uncovered'), 7::bigint, 'one event per shift');
select is((select count(*) from public.outbox_events e join public.shifts s on s.id = e.entity_id where e.type = 'shift.uncovered' and s.organization_id <> e.organization_id), 0::bigint, 'each event carries its shift''s own organization');
select is((select uncovered_emitted_for from public.shifts where id = pg_temp.gid('f1')), (select starts_at from public.shifts where id = pg_temp.gid('f1')), 'the shift remembers the start time it was announced for');
-- a new start time is a new fact
select pg_temp.act_as('u_manager_a1');
select public.update_shift(pg_temp.gid('f1'), null, pg_temp.a1(0, '15:30'), pg_temp.a1(0, '17:30'));
select public.update_shift(pg_temp.gid('f3'), null, null, null, 'only a note');
select pg_temp.act_as('service_role');
select is(public.emit_uncovered_shift_events(interval '14 days', 100), 1, 'a shift whose start time changed is announced again for its new start (and a notes-only edit is not)');
select is(public.emit_uncovered_shift_events(interval '14 days', 100), 0, 'and only once');
-- assigned then opened again at the same start: already announced
select pg_temp.act_as('u_manager_a1');
select public.assign_shift(pg_temp.gid('f2'), pg_temp.id('p_s2'));
select public.assign_shift(pg_temp.gid('f2'), null);
select pg_temp.act_as('service_role');
select is(public.emit_uncovered_shift_events(interval '14 days', 100), 0, 'a shift assigned and opened again at the same start is not announced a second time');
-- a window shorter than the distance
select pg_temp.act_as('u_manager_a1');
select pg_temp.mk('late', 'pos_fd', 6, '12:00', '14:00');
select pg_temp.act_as('postgres');
select pg_temp.act_as('service_role');
select is(public.emit_uncovered_shift_events(interval '1 minute', 100), 0, 'a short window reaches nothing far away');
select is(public.emit_uncovered_shift_events(((select starts_at from public.shifts where id = pg_temp.gid('late')) - now()) + interval '1 minute', 100), 1, 'twin: a window that just reaches the shift emits it');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'shift.uncovered' and entity_id = pg_temp.gid('f1')), 2::bigint, 'f1 has two events (one per start time)');
select is((select count(*) from public.outbox_events where type = 'shift.uncovered' and entity_id = pg_temp.gid('f2')), 1::bigint, 'f2 has one');

-- ===========================================================================
-- 3. Flows that make the other events (all through the service functions)
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select public.update_shift(pg_temp.gid('a1'), null, pg_temp.a1(0, '09:30'), pg_temp.a1(0, '13:30'));           -- shift.changed (s2)
select public.cancel_shift(pg_temp.gid('a2'));                                                                -- shift.cancelled (s3)
select pg_temp.act_as('u_s2');
insert into ids select 'w_x1', public.request_shift_swap(pg_temp.gid('x1'), pg_temp.id('p_s3'));              -- shift_swap.requested (swap)
insert into ids select 'w_x4', public.request_shift_swap(pg_temp.gid('x4'), pg_temp.id('p_s3'));
select pg_temp.act_as('u_s3');
select public.respond_shift_swap(pg_temp.gid('w_x1'), true);                                                  -- shift_swap.accepted
insert into ids select 'w_x3', public.request_shift_drop(pg_temp.gid('x3'));                                  -- shift_swap.requested (drop)
select pg_temp.act_as('u_manager_a1');
select public.decide_shift_swap(pg_temp.gid('w_x1'), true);                                                   -- shift_swap.approved
select public.decide_shift_swap(pg_temp.gid('w_x3'), false);                                                  -- shift_swap.denied
select pg_temp.act_as('u_s2');
select public.cancel_shift_swap(pg_temp.gid('w_x4'));                                                         -- shift_swap.cancelled
select pg_temp.act_as('u_s4');
insert into ids select 'c_f4s4', public.request_shift_claim(pg_temp.gid('f4'));                               -- shift_claim.requested
select pg_temp.act_as('u_s6');
insert into ids select 'c_f4s6', public.request_shift_claim(pg_temp.gid('f4'));
select pg_temp.act_as('u_manager_a1');
select public.decide_shift_claim(pg_temp.gid('c_f4s4'), true);                                                -- shift_claim.approved (+ denied for s6)
select pg_temp.act_as('postgres');
insert into public.time_off_requests (id, organization_id, person_id, starts_on, ends_on) values
  (pg_temp.id('to_1'), pg_temp.id('org_a'), pg_temp.id('p_s2'), pg_temp.wk() + 6, pg_temp.wk() + 6),
  (pg_temp.id('to_2'), pg_temp.id('org_a'), pg_temp.id('p_s2'), pg_temp.wk() + 20, pg_temp.wk() + 20);
insert into ids values ('to_1', pg_temp.id('to_1')), ('to_2', pg_temp.id('to_2'));
select pg_temp.act_as('u_s2');
insert into ids select 'to_3', public.request_time_off(pg_temp.id('org_a'), pg_temp.wk() + 30, pg_temp.wk() + 31);   -- time_off.requested
select public.cancel_time_off(pg_temp.gid('to_3'));                                                           -- cancelled while pending
select pg_temp.act_as('u_manager_a1');
select public.decide_time_off(pg_temp.gid('to_1'), true);                                                     -- time_off.decided
select pg_temp.act_as('u_s2');
select public.cancel_time_off(pg_temp.gid('to_1'));                                                           -- cancelled while approved
select pg_temp.act_as('u_s2');
insert into ids select 'w_p1', public.request_shift_swap(pg_temp.gid('x4'), pg_temp.id('p_s3'));              -- stays requested
insert into ids select 'w_p2', public.request_shift_swap(pg_temp.gid('a1'), pg_temp.id('p_s3'));             -- will be accepted, then wait
insert into ids select 'to_p', public.request_time_off(pg_temp.id('org_a'), pg_temp.wk() + 40, pg_temp.wk() + 41);   -- stays pending
select pg_temp.act_as('u_s3');
select public.respond_shift_swap(pg_temp.gid('w_p2'), true);
insert into ids select 'w_p3', public.request_shift_drop(pg_temp.gid('x2'));                                 -- stays requested
select pg_temp.act_as('u_s5');
insert into ids select 'c_p', public.request_shift_claim(pg_temp.gid('f1'));                                 -- stays requested
select pg_temp.act_as('postgres');
-- time_off.requested events for the owner-inserted rows (the RPC path wrote one for to_3 only): use to_3 for the "requested" read
-- a forged event for another organization pointing at org A's shift, and events that name people who cannot be told
insert into public.outbox_events (id, organization_id, location_id, type, entity_table, entity_id, correlation_id, payload) values
  (pg_temp.id('ev_x_org'), pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'shift.assigned', 'shifts', pg_temp.gid('x2'), pg_temp.id('ev_x_org'), jsonb_build_object('person_id', pg_temp.id('p_staff_b1'))),
  (pg_temp.id('ev_x_pers'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'shift.assigned', 'shifts', pg_temp.gid('x2'), pg_temp.id('ev_x_pers'), jsonb_build_object('person_id', pg_temp.id('p_staff_b1'))),
  (pg_temp.id('ev_dis'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'shift.assigned', 'shifts', pg_temp.gid('x2'), pg_temp.id('ev_dis'), jsonb_build_object('person_id', pg_temp.id('p_disabled_a'))),
  (pg_temp.id('ev_arch'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'shift.assigned', 'shifts', pg_temp.gid('x2'), pg_temp.id('ev_arch'), jsonb_build_object('person_id', pg_temp.id('p_s7'))),
  (pg_temp.id('ev_bad'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'shift.assigned', 'shifts', pg_temp.gid('x2'), pg_temp.id('ev_bad'), jsonb_build_object('person_id', 'not-a-uuid')),
  (pg_temp.id('ev_other'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'shifts', pg_temp.gid('x2'), pg_temp.id('ev_other'), '{}'),
  (pg_temp.id('ev_tbl'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'shift.assigned', 'tasks', pg_temp.gid('x2'), pg_temp.id('ev_tbl'), jsonb_build_object('person_id', pg_temp.id('p_s2')));
insert into ids select k, pg_temp.id(k) from unnest(array['ev_x_org', 'ev_x_pers', 'ev_dis', 'ev_arch', 'ev_bad', 'ev_other', 'ev_tbl']) k;

-- ===========================================================================
-- 4. worker_shift_for_event
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.worker_shift_for_event(%L)', pg_temp.eid('shift.cancelled', 'a2'))), '42501 permission denied for function worker_shift_for_event', 'a signed-in manager cannot call it');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select count(*) from public.worker_shift_for_event(%L)', pg_temp.eid('shift.cancelled', 'a2'))), '42501 permission denied for function worker_shift_for_event', 'nor anon');
select pg_temp.act_as_service('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.worker_shift_for_event(%L)', pg_temp.eid('shift.cancelled', 'a2'))), '42501 not allowed', 'the service key with a user token is refused (42501)');
select pg_temp.act_as('service_role');
select results_eq(format($$select location_name, location_timezone, schedule_status, week_start, position_name, status, assigned_person_id is null from public.worker_shift_for_event(%L)$$, pg_temp.eid('shift.cancelled', 'a2')),
  $$values ('A1 Arena'::text, 'America/New_York'::text, 'published'::text, pg_temp.wk(), 'Front desk'::text, 'cancelled'::text, false)$$, 'for a shift event: the location, its time zone, the schedule state, the week, the position, the shift status');
select is((select starts_at from public.worker_shift_for_event(pg_temp.eid('shift.cancelled', 'a2'))), pg_temp.a1(1, '09:00'), 'with the start time');
select is((select shift_id from public.worker_shift_for_event(pg_temp.eid('shift_swap.requested', 'w_x1'))), pg_temp.gid('x1'), 'for a swap event: the shift being swapped');
select is((select shift_id from public.worker_shift_for_event(pg_temp.eid('shift_claim.requested', 'c_f4s4'))), pg_temp.gid('f4'), 'for a claim event: the shift being claimed');
select is((select count(*) from public.worker_shift_for_event(pg_temp.eid('schedule.published', 'sched'))), 0::bigint, 'a schedule event has no single shift (nothing returned)');
select is((select count(*) from public.worker_shift_for_event(pg_temp.eid('time_off.requested', 'to_3'))), 0::bigint, 'nor does a time off event');
select is((select count(*) from public.worker_shift_for_event(gen_random_uuid())), 0::bigint, 'an unknown event gives nothing');
select is((select count(*) from public.worker_shift_for_event(pg_temp.gid('ev_x_org'))), 0::bigint, 'an event of org B that points at org A''s shift gives nothing (organizations never mix)');
select is((select count(*) from public.worker_shift_for_event(pg_temp.gid('ev_tbl'))), 0::bigint, 'and an event about another table gives nothing');
select ok(pg_get_function_result('public.worker_shift_for_event(uuid)'::regprocedure) !~ 'notes', 'the result has no notes column');
select ok(pg_get_function_result('public.worker_shift_event_recipients(uuid)'::regprocedure) !~ 'notes', 'and neither do the recipients');
select is((select to_jsonb(r) ? 'notes' from public.worker_shift_for_event(pg_temp.eid('shift.cancelled', 'a2')) r), false, 'a returned row carries no notes key');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 5. worker_shift_event_recipients: who is told, per event type
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.worker_shift_event_recipients(%L)', pg_temp.eid('shift.cancelled', 'a2'))), '42501 permission denied for function worker_shift_event_recipients', 'a signed-in manager cannot call it');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select count(*) from public.worker_shift_event_recipients(%L)', pg_temp.eid('shift.cancelled', 'a2'))), '42501 permission denied for function worker_shift_event_recipients', 'nor anon');
select pg_temp.act_as_service('u_manager_a1');
select is(pg_temp.fd(format('select count(*) from public.worker_shift_event_recipients(%L)', pg_temp.eid('shift.cancelled', 'a2'))), '42501 not allowed', 'the service key with a user token is refused (42501)');
select pg_temp.act_as('service_role');
select is(pg_temp.rc(pg_temp.eid('schedule.published', 'sched')), 'p_s2:schedule_published,p_s3:schedule_published,p_s4:schedule_published', 'schedule.published: everyone who holds a scheduled shift in the week now (s2, s3, and s4 who claimed one since), once each');
select is(pg_temp.rc(pg_temp.eid('shift.assigned', 'f2')), 'p_s2:assigned', 'shift.assigned: the person who got it');
select is(pg_temp.rc(pg_temp.eid('shift.unassigned', 'f2')), 'p_s2:unassigned', 'shift.unassigned: the person who lost it');
select is(pg_temp.rc(pg_temp.eid('shift.changed', 'a1')), 'p_s2:changed', 'shift.changed: the holder');
select is(pg_temp.rc(pg_temp.eid('shift.cancelled', 'a2')), 'p_s3:cancelled', 'shift.cancelled: the person who held it');
select is(pg_temp.rc(pg_temp.eid('shift.opened', 'f2', jsonb_build_object('via', 'manager'))), 'p_locadmin_a1:can_claim,p_manager_a1:can_claim,p_orgadmin_a:can_claim,p_s2:can_claim,p_s3:can_claim,p_s4:can_claim,p_s5:can_claim,p_s6:can_claim,p_staff_a1:can_claim', 'shift.opened (plain position): every active member at the location who may claim it and passes every rule for it now (admins are members too)');
select is(pg_temp.rc(pg_temp.eid('shift.opened', 'oc')), 'p_s2:can_claim,p_s3:can_claim', 'shift.opened (Lifeguard): only the certified (s5''s certificate expired, the rest have none)');
select is(pg_temp.rc(pg_temp.eid('shift.opened', 'f4')), '', 'shift.opened for a shift that has since been filled: nobody (stale events tell no one)');
select is(pg_temp.rc(pg_temp.eid('shift.uncovered', 'f2')), 'p_locadmin_a1:uncovered,p_manager_a1:uncovered,p_orgadmin_a:uncovered', 'shift.uncovered: the schedulers and exchange approvers at the location, never plain staff');
select is(pg_temp.rc(pg_temp.eid('shift.uncovered', 'f4')), '', 'shift.uncovered for a shift that has since been filled: nobody');
select ok((select count(*) > 0 and bool_and(p.organization_id = pg_temp.id('org_b')) and bool_and(r.reason = 'uncovered') from public.worker_shift_event_recipients(pg_temp.eid('shift.uncovered', 'bf1')) r join public.people p on p.id = r.person_id), 'shift.uncovered in org B: only people of org B, never anyone of org A');
select is(pg_temp.rc(pg_temp.eid('shift_swap.requested', 'w_p1')), 'p_s3:swap_offered', 'shift_swap.requested (swap, still open): the person offered the swap');
select is(pg_temp.rc(pg_temp.eid('shift_swap.requested', 'w_p3')), 'p_locadmin_a1:needs_approval,p_manager_a1:needs_approval,p_orgadmin_a:needs_approval', 'shift_swap.requested (drop, still waiting): the approvers, not the person who dropped');
select is(pg_temp.rc(pg_temp.eid('shift_swap.requested', 'w_x1')), '', 'a swap request that was approved since: nobody is told to act');
select is(pg_temp.rc(pg_temp.eid('shift_swap.requested', 'w_x3')), '', 'a drop that was denied since: nobody is asked');
select is(pg_temp.rc(pg_temp.eid('shift_swap.requested', 'w_x4')), '', 'a swap request that was cancelled since: nobody is told to act');
select is(pg_temp.rc(pg_temp.eid('shift_swap.accepted', 'w_p2')), 'p_locadmin_a1:needs_approval,p_manager_a1:needs_approval,p_orgadmin_a:needs_approval,p_s2:swap_accepted', 'shift_swap.accepted (waiting): the person who offered it, and the approvers who must decide');
select is(pg_temp.rc(pg_temp.eid('shift_swap.accepted', 'w_x1')), 'p_s2:swap_accepted', 'shift_swap.accepted after it was approved: the person who offered it; the approvers are no longer asked');
select is(pg_temp.rc(pg_temp.eid('shift_swap.approved', 'w_x1')), 'p_s2:swap_approved,p_s3:swap_approved', 'shift_swap.approved: both parties (the manager who decided is not a party)');
select is(pg_temp.rc(pg_temp.eid('shift_swap.denied', 'w_x3')), 'p_s3:swap_denied', 'shift_swap.denied: the person who dropped');
select is(pg_temp.rc(pg_temp.eid('shift_swap.cancelled', 'w_x4')), 'p_s3:swap_cancelled', 'shift_swap.cancelled: the other party, not the one who cancelled');
select is(pg_temp.rc(pg_temp.eid('shift_claim.requested', 'c_p')), 'p_locadmin_a1:needs_approval,p_manager_a1:needs_approval,p_orgadmin_a:needs_approval', 'shift_claim.requested (waiting): the approvers, not the claimant');
select is(pg_temp.rc(pg_temp.eid('shift_claim.requested', 'c_f4s4')), '', 'shift_claim.requested for a claim already decided: nobody is asked to act');
select is(pg_temp.rc(pg_temp.eid('shift_claim.approved', 'c_f4s4')), 'p_s4:claim_approved', 'shift_claim.approved: the claimant');
select is(pg_temp.rc(pg_temp.eid('shift_claim.denied', 'c_f4s6')), 'p_s6:claim_denied', 'shift_claim.denied: the claimant');
select is(pg_temp.rc(pg_temp.eid('time_off.requested', 'to_p')), 'p_locadmin_a1:needs_approval,p_manager_a1:needs_approval,p_orgadmin_a:needs_approval', 'time_off.requested (pending): the approvers over the person');
select is(pg_temp.rc(pg_temp.eid('time_off.requested', 'to_3')), '', 'time_off.requested for a request cancelled since: nobody is asked to act');
select is(pg_temp.rc(pg_temp.eid('time_off.decided', 'to_1')), 'p_s2:time_off_decided', 'time_off.decided: the person');
select is(pg_temp.rc(pg_temp.eid('time_off.cancelled', 'to_1')), 'p_locadmin_a1:time_off_cancelled,p_manager_a1:time_off_cancelled,p_orgadmin_a:time_off_cancelled', 'time_off.cancelled of an approved request: the approvers (so schedulers hear of it)');
select is(pg_temp.rc(pg_temp.eid('time_off.cancelled', 'to_3')), '', 'time_off.cancelled of a pending request: nobody');
select is(pg_temp.rc(pg_temp.gid('ev_x_org')), '', 'an event of org B pointing at org A''s shift: nobody (organizations never mix)');
select is(pg_temp.rc(pg_temp.gid('ev_x_pers')), '', 'an org A event naming a person of org B: nobody');
select is(pg_temp.rc(pg_temp.gid('ev_dis')), '', 'a person whose account is disabled is not told');
select is(pg_temp.rc(pg_temp.gid('ev_arch')), '', 'nor an archived person');
select is(pg_temp.rc(pg_temp.gid('ev_bad')), '', 'a payload with a value that is not an id: nobody, and no error');
select is(pg_temp.rc(pg_temp.gid('ev_other')), '', 'an event type that is not a staffing event: nobody');
select is(pg_temp.rc(pg_temp.gid('ev_tbl')), '', 'an event about another table: nobody');
select is((select count(*) from public.worker_shift_event_recipients(gen_random_uuid())), 0::bigint, 'an unknown event: nobody');
select is((select count(*) from (select person_id from public.worker_shift_event_recipients(pg_temp.eid('shift.opened', 'f2', jsonb_build_object('via', 'manager'))) group by person_id having count(*) > 1) d), 0::bigint, 'each person appears once per event');
-- reading state "now": a swap approved later changes who is asked
select pg_temp.act_as('postgres');
select pg_temp.act_as('service_role');
select is(pg_temp.rc(pg_temp.eid('shift_swap.accepted', 'w_x3')), '', 'shift_swap.accepted of a drop does not exist; an unrelated lookup gives nobody (sanity)');

-- ===========================================================================
-- 6. Clock changes and the location's local calendar day
-- ===========================================================================
select pg_temp.act_as('postgres');
insert into public.schedules (id, organization_id, location_id, week_start) values
  (pg_temp.id('sc_sp'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), date '2027-03-08'),
  (pg_temp.id('sc_fb'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), date '2027-11-01');
insert into ids values ('sc_sp', pg_temp.id('sc_sp')), ('sc_fb', pg_temp.id('sc_fb'));
select pg_temp.act_as('u_manager_a1');
insert into ids select 'tpl', public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Weekend', 7);
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 5, '22:00', 600, pg_temp.id('p_s3'));   -- Saturday night, 10 hours of wall clock
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 6, '08:00', 60, pg_temp.id('p_s3'));    -- Sunday 08:00: starts exactly when the night ends
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 6, '07:00', 60, pg_temp.id('p_s3'));    -- Sunday 07:00: inside the night
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 6, '12:00', 480, null);
create temp table st_sp as select * from public.apply_shift_template(pg_temp.id('sc_sp'), pg_temp.gid('tpl'), 0);
create temp table st_fb as select * from public.apply_shift_template(pg_temp.id('sc_fb'), pg_temp.gid('tpl'), 0);
select pg_temp.act_as('postgres');
select is((select count(*) from st_sp), 4::bigint, 'spring week: four items stamped');
select is((select s.starts_at at time zone 'America/New_York' from public.shifts s join st_sp t on t.shift_id = s.id where s.starts_at < timestamptz '2027-03-14 06:00+00' and s.schedule_id = pg_temp.id('sc_sp')), timestamp '2027-03-13 22:00', 'spring: the Saturday night shift starts at 22:00 local');
select is((select s.ends_at at time zone 'America/New_York' from public.shifts s where s.schedule_id = pg_temp.id('sc_sp') and s.starts_at = timestamptz '2027-03-14 03:00+00'), timestamp '2027-03-14 08:00', 'and ends at 08:00 local, by the wall clock');
select is((select s.ends_at - s.starts_at from public.shifts s where s.schedule_id = pg_temp.id('sc_sp') and s.starts_at = timestamptz '2027-03-14 03:00+00'), interval '9 hours', 'which is 9 hours elapsed (the clock skipped an hour)');
select is((select s.ends_at - s.starts_at from public.shifts s where s.schedule_id = pg_temp.id('sc_fb') and s.starts_at = timestamptz '2027-11-07 02:00+00'), interval '11 hours', 'fall: the same item is 11 hours elapsed (the clock repeated an hour)');
select is((select s.ends_at at time zone 'America/New_York' from public.shifts s where s.schedule_id = pg_temp.id('sc_fb') and s.starts_at = timestamptz '2027-11-07 02:00+00'), timestamp '2027-11-07 08:00', 'and still ends at 08:00 local');
select is((select count(*) from public.shifts s where s.schedule_id = pg_temp.id('sc_sp') and s.assigned_person_id = pg_temp.id('p_s3')), 2::bigint, 'spring: the night shift and the Sunday 08:00 shift are both s3''s (the second starts exactly when the first ends, no overlap)');
select is((select refused from st_sp t join public.shifts s on s.id = t.shift_id where s.starts_at = timestamptz '2027-03-14 11:00+00'), 'overlap', 'spring: the Sunday 07:00 item (inside the night) is left open, naming overlap');
select is((select count(*) from public.shifts s where s.schedule_id = pg_temp.id('sc_fb') and s.assigned_person_id = pg_temp.id('p_s3')), 2::bigint, 'fall: the same two are s3''s, adjacent without an overlap');
select is((select refused from st_fb t join public.shifts s on s.id = t.shift_id where s.starts_at = timestamptz '2027-11-07 12:00+00'), 'overlap', 'fall: the 07:00 item is left open, naming overlap');
select is((select s.starts_at from public.shifts s where s.schedule_id = pg_temp.id('sc_sp') and s.assigned_person_id is null and s.ends_at - s.starts_at = interval '8 hours'), timestamptz '2027-03-14 16:00+00', 'the Sunday 12:00 shift after the change is 16:00 UTC (EDT), not 17:00');
select is((select s.starts_at from public.shifts s where s.schedule_id = pg_temp.id('sc_fb') and s.assigned_person_id is null and s.ends_at - s.starts_at = interval '8 hours'), timestamptz '2027-11-07 17:00+00', 'and 17:00 UTC after the clocks fall back (EST)');

-- qualification and time off judged on the location's local day (America/New_York is UTC-5 on 10 March 2027)
select pg_temp.act_as('postgres');
update public.person_qualifications set valid_from = date '2027-01-01', expires_on = date '2027-03-10' where person_id = pg_temp.id('p_s2') and qualification_id = pg_temp.gid('q');
insert into public.person_qualifications (organization_id, person_id, qualification_id, valid_from, expires_on) values
  (pg_temp.id('org_a'), pg_temp.id('p_s4'), pg_temp.gid('q'), date '2027-03-11', null);
insert into public.time_off_requests (organization_id, person_id, starts_on, ends_on, status, decided_by_person_id, decided_at)
values (pg_temp.id('org_a'), pg_temp.id('p_s5'), date '2027-03-10', date '2027-03-10', 'approved', pg_temp.id('p_manager_a1'), now());
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.id('sc_sp'), pg_temp.gid('pos_lg'),
  (timestamp '2027-03-10 23:00') at time zone 'America/New_York', (timestamp '2027-03-10 23:45') at time zone 'America/New_York', pg_temp.id('p_s2'))), 'ok',
  'a certificate valid until 10 March works a shift at 23:00 local on 10 March (it is already 11 March in UTC)');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.id('sc_sp'), pg_temp.gid('pos_lg'),
  (timestamp '2027-03-11 00:15') at time zone 'America/New_York', (timestamp '2027-03-11 01:00') at time zone 'America/New_York', pg_temp.id('p_s2'))), '23514 that person is missing a required qualification [qualification]',
  'but not at 00:15 local on 11 March (it has expired)');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.id('sc_sp'), pg_temp.gid('pos_lg'),
  (timestamp '2027-03-10 21:00') at time zone 'America/New_York', (timestamp '2027-03-10 22:00') at time zone 'America/New_York', pg_temp.id('p_s4'))), '23514 that person is missing a required qualification [qualification]',
  'a certificate valid from 11 March does not cover 21:00 local on 10 March (although that is 11 March in UTC)');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.id('sc_sp'), pg_temp.gid('pos_lg'),
  (timestamp '2027-03-11 00:15') at time zone 'America/New_York', (timestamp '2027-03-11 01:00') at time zone 'America/New_York', pg_temp.id('p_s4'))), 'ok',
  'twin: it does cover 00:15 local on 11 March');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.id('sc_sp'), pg_temp.gid('pos_fd'),
  (timestamp '2027-03-10 21:00') at time zone 'America/New_York', (timestamp '2027-03-10 22:00') at time zone 'America/New_York', pg_temp.id('p_s5'))), '23514 that person has approved time off then [time_off]',
  'time off on 10 March blocks 21:00 local on 10 March (although that is 11 March in UTC)');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.id('sc_sp'), pg_temp.gid('pos_fd'),
  (timestamp '2027-03-10 00:15') at time zone 'America/New_York', (timestamp '2027-03-10 01:00') at time zone 'America/New_York', pg_temp.id('p_s5'))), '23514 that person has approved time off then [time_off]',
  'and 00:15 local on 10 March (still 10 March in UTC as well)');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.id('sc_sp'), pg_temp.gid('pos_fd'),
  (timestamp '2027-03-11 00:15') at time zone 'America/New_York', (timestamp '2027-03-11 01:00') at time zone 'America/New_York', pg_temp.id('p_s5'))), 'ok',
  'twin: but not 00:15 local on 11 March, which is the next day');
select is(pg_temp.fd(format('select public.create_shift(%L, %L, %L, %L, %L)', pg_temp.id('sc_sp'), pg_temp.gid('pos_fd'),
  (timestamp '2027-03-09 22:00') at time zone 'America/New_York', (timestamp '2027-03-10 01:00') at time zone 'America/New_York', pg_temp.id('p_s5'))), '23514 that person has approved time off then [time_off]',
  'a shift that starts the evening before and runs into time off is refused too');
-- time off decided against shifts, by local day: s6 works 22:00-23:30 local on 10 March (03:00-04:30 UTC on 11 March)
select pg_temp.act_as('u_manager_a1');
select public.create_shift(pg_temp.id('sc_sp'), pg_temp.gid('pos_fd'), (timestamp '2027-03-10 22:00') at time zone 'America/New_York', (timestamp '2027-03-10 23:30') at time zone 'America/New_York', pg_temp.id('p_s6'));
select pg_temp.act_as('postgres');
insert into public.time_off_requests (id, organization_id, person_id, starts_on, ends_on) values
  (pg_temp.id('to_d10'), pg_temp.id('org_a'), pg_temp.id('p_s6'), date '2027-03-10', date '2027-03-10'),
  (pg_temp.id('to_d11'), pg_temp.id('org_a'), pg_temp.id('p_s6'), date '2027-03-11', date '2027-03-11');
insert into ids values ('to_d10', pg_temp.id('to_d10')), ('to_d11', pg_temp.id('to_d11'));
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_d11'))), 'ok', 'time off on 11 March is approved: the 22:00 shift on 10 March is a different local day (it is 11 March in UTC)');
select is(pg_temp.fd(format('select public.decide_time_off(%L, true)', pg_temp.gid('to_d10'))), '23514 that person has shifts on those days; reassign them first [has_shifts]', 'time off on 10 March is refused (has_shifts)');
select pg_temp.act_as('postgres');
select is((select status from public.time_off_requests where id = pg_temp.gid('to_d10')), 'pending', 'and stays pending');

select * from finish();
rollback;
