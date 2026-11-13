-- Phase 3 (staff scheduling): shift swaps, drops and open-shift claims. The four assignment rules on swap accept, swap approve, claim approve and
-- the first-come claim; the auto-approve and first-come settings; stale shifts; cancel by either party; nobody decides their own request;
-- one event per action with ids only. Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(205);

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


create function pg_temp.mk(k text, p text, d int, t1 text, t2 text, who text default null) returns void language plpgsql as $$
begin
  insert into ids values (k, public.create_shift(pg_temp.gid('sched'), pg_temp.gid(p), pg_temp.a1(d, t1), pg_temp.a1(d, t2),
                                                 case when who is null then null else pg_temp.id(who) end));
end $$;
create function pg_temp.ev(p_type text, p_entity text) returns bigint language sql stable as $$
  select count(*) from public.outbox_events where type = p_type and entity_id = pg_temp.gid(p_entity) $$;
create function pg_temp.sw(p_k text) returns text language sql stable as $$ select status from public.shift_swaps where id = pg_temp.gid(p_k) $$;
create function pg_temp.cl(p_k text) returns text language sql stable as $$ select status from public.shift_claims where id = pg_temp.gid(p_k) $$;
create function pg_temp.holder(p_k text) returns uuid language sql stable as $$ select assigned_person_id from public.shifts where id = pg_temp.gid(p_k) $$;
grant execute on function pg_temp.mk(text, text, int, text, text, text), pg_temp.ev(text, text), pg_temp.sw(text), pg_temp.cl(text), pg_temp.holder(text) to public;
create temp table sp_msg (rule text, msg text);
grant all on sp_msg to public;
insert into sp_msg values ('overlap', '23514 that person already has a shift at that time [overlap]'), ('time_off', '23514 that person has approved time off then [time_off]'),
  ('qualification', '23514 that person is missing a required qualification [qualification]'),
  ('stale', '23514 the shift changed since the swap was offered [stale]');

-- ---------------------------------------------------------------------------
-- Setup: a certified position, plain position, certificates for s2/s3/s5(expired), a published week of shifts
-- ---------------------------------------------------------------------------
select pg_temp.act_as('u_manager_a1');
insert into ids select 'q', public.save_qualification(pg_temp.id('org_a'), 'Lifeguard cert');
insert into ids select 'pos_lg', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Lifeguard', array[pg_temp.gid('q')]);
insert into ids select 'pos_fd', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Front desk');
select public.set_person_qualification(pg_temp.id('org_a'), pg_temp.id(k), pg_temp.gid('q'), current_date - 30, current_date + 365) from unnest(array['p_s2', 'p_s3']) k;
insert into ids select 'sched', public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk());
select pg_temp.mk('sA', 'pos_fd', 0, '09:00', '13:00', 'p_s2');   -- s2 to s3, but s3 holds sOv (overlap on accept)
select pg_temp.mk('sOv', 'pos_fd', 0, '10:00', '12:00', 'p_s3');
select pg_temp.mk('sB', 'pos_fd', 1, '09:00', '13:00', 'p_s2');   -- s2 to s4, who has time off that day
select pg_temp.mk('sC', 'pos_lg', 2, '09:00', '13:00', 'p_s2');   -- s2 to s6, who has no certificate
select pg_temp.mk('sD', 'pos_fd', 3, '09:00', '13:00', 'p_s2');   -- plain swap to s3; time off appears before the manager decides
select pg_temp.mk('sE', 'pos_fd', 4, '09:00', '13:00', 'p_s2');   -- plain swap to s3; an overlapping shift appears before the decision
select pg_temp.mk('sJ', 'pos_fd', 5, '09:00', '13:00', 'p_s2');   -- cancel tests
select pg_temp.mk('sF', 'pos_fd', 5, '14:00', '18:00', 'p_s2');   -- reassigned by the manager while a swap is open
select pg_temp.mk('sG', 'pos_fd', 6, '09:00', '13:00', 'p_s2');   -- changed under a swap by the owner (stale)
select pg_temp.mk('sH', 'pos_fd', 0, '14:00', '18:00', 'p_s5');   -- counter swap: s5 and s3 trade
select pg_temp.mk('sI', 'pos_fd', 1, '14:00', '18:00', 'p_s3');
select pg_temp.mk('sK', 'pos_fd', 2, '14:00', '18:00', 'p_s2');   -- auto-approve
select pg_temp.mk('sL', 'pos_fd', 6, '14:00', '18:00', 'p_s2');   -- auto-approve that cannot finish (counter shift)
select pg_temp.mk('sM', 'pos_fd', 6, '19:00', '21:00', 'p_s3');
select pg_temp.mk('d1', 'pos_fd', 3, '15:00', '19:00', 'p_s4');   -- drop, approved
select pg_temp.mk('d2', 'pos_fd', 3, '09:00', '13:00', 'p_s6');   -- drop, stale
select pg_temp.mk('d3', 'pos_fd', 4, '15:00', '19:00', 'p_s4');   -- drop, denied
select public.publish_schedule(pg_temp.gid('sched'));
-- open shifts (after publishing, so each is announced as shift.opened via manager)
select pg_temp.mk('o1', 'pos_lg', 1, '19:00', '21:00');           -- certified position
select pg_temp.mk('o2', 'pos_fd', 2, '19:00', '21:00');           -- two claimants, manager picks
select pg_temp.mk('o3', 'pos_fd', 3, '19:00', '21:00');           -- the manager's own claim
select pg_temp.mk('o4', 'pos_fd', 4, '19:00', '21:00');           -- time off appears after the claim
select pg_temp.mk('o5', 'pos_fd', 5, '19:00', '21:00');           -- overlap appears after the claim
select pg_temp.mk('o6', 'pos_fd', 6, '20:00', '22:00');           -- first come
select pg_temp.mk('o7', 'pos_lg', 0, '19:00', '21:00');           -- first come, uncertified claimant
select pg_temp.mk('o8', 'pos_fd', 4, '14:00', '18:00');           -- the assignee changes under a claim
select pg_temp.act_as('postgres');
-- held by an org admin (not a staff assignment, so written by the owner): the admin cannot decide their own swap
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id)
values (pg_temp.id('sO'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(1, '19:30'), pg_temp.a1(1, '20:30'), pg_temp.id('p_orgadmin_a'));
insert into ids values ('sO', pg_temp.id('sO'));
insert into public.time_off_requests (organization_id, person_id, starts_on, ends_on, status, decided_by_person_id, decided_at)
values (pg_temp.id('org_a'), pg_temp.id('p_s4'), pg_temp.wk() + 1, pg_temp.wk() + 1, 'approved', pg_temp.id('p_manager_a1'), now());
-- the draft week after: an open shift staff cannot see
insert into public.schedules (id, organization_id, location_id, week_start) values (pg_temp.id('sched_draft'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() + 7);
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id) values
  (pg_temp.id('sh_draft_open'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('sched_draft'), pg_temp.gid('pos_fd'), pg_temp.a1(7, '09:00'), pg_temp.a1(7, '13:00'), null),
  (pg_temp.id('sh_draft_s2'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('sched_draft'), pg_temp.gid('pos_fd'), pg_temp.a1(8, '09:00'), pg_temp.a1(8, '13:00'), pg_temp.id('p_s2'));
create temp table ev_base as select count(*) as n from public.outbox_events;
grant all on ev_base to public;
select is((select count(*) from public.outbox_events where type like 'shift_swap.%' or type like 'shift_claim.%'), 0::bigint, 'sanity: no exchange event yet');

-- ===========================================================================
-- 1. request_shift_swap: who may ask, whom, and which shifts
-- ===========================================================================
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.gid('sA'), pg_temp.id('p_staff_a1'))), '42501 not allowed', 'a person cannot offer a shift someone else holds (42501)');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', gen_random_uuid(), pg_temp.id('p_s3'))), '42501 not allowed', 'an unknown shift gives the same refusal');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.id('sh_draft_s2'), pg_temp.id('p_s3'))), '42501 not allowed', 'a shift on a draft week cannot be offered (staff cannot see drafts)');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.gid('sA'), pg_temp.id('p_s2'))), '23514 you cannot swap with that person [not_member]', 'a swap with yourself is refused (23514)');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, null)', pg_temp.gid('sA'))), '23514 you cannot swap with that person [not_member]', 'with nobody');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.gid('sA'), pg_temp.id('p_staff_a2'))), '23514 you cannot swap with that person [not_member]', 'with a person who works only at A2');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.gid('sA'), pg_temp.id('p_staff_b1'))), '23514 you cannot swap with that person [not_member]', 'with a person of another organization');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.gid('sA'), pg_temp.id('p_disabled_a'))), '23514 you cannot swap with that person [not_member]', 'with a disabled account');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L, null, %L)', pg_temp.gid('sA'), pg_temp.id('p_s3'), repeat('n', 501))), '22023 the note is too long', 'a note over 500 characters is refused');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L, %L)', pg_temp.gid('sA'), pg_temp.id('p_s3'), pg_temp.gid('sD'))), '22023 that shift cannot be part of this swap', 'a counter shift the other person does not hold is refused');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L, %L)', pg_temp.gid('sA'), pg_temp.id('p_s3'), pg_temp.id('sh_draft_s2'))), '22023 that shift cannot be part of this swap', 'a counter shift on a draft week is refused');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shift_swaps), 0::bigint, 'none of the refused requests left a swap');
select pg_temp.act_as('u_s2');
insert into ids select 'w_A', public.request_shift_swap(pg_temp.gid('sA'), pg_temp.id('p_s3'), null, 'SWAP-NOTE');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.gid('sA'), pg_temp.id('p_s4'))), '22023 this shift already has an open swap or drop', 'a second open swap on the same shift is refused (22023)');
select is(pg_temp.fd(format('select public.request_shift_drop(%L)', pg_temp.gid('sA'))), '22023 this shift already has an open swap or drop', 'and so is a drop');
insert into ids select 'w_B', public.request_shift_swap(pg_temp.gid('sB'), pg_temp.id('p_s4'));
insert into ids select 'w_C', public.request_shift_swap(pg_temp.gid('sC'), pg_temp.id('p_s6'));
insert into ids select 'w_D', public.request_shift_swap(pg_temp.gid('sD'), pg_temp.id('p_s3'));
insert into ids select 'w_E', public.request_shift_swap(pg_temp.gid('sE'), pg_temp.id('p_s3'));
insert into ids select 'w_J', public.request_shift_swap(pg_temp.gid('sJ'), pg_temp.id('p_s3'));
insert into ids select 'w_F', public.request_shift_swap(pg_temp.gid('sF'), pg_temp.id('p_s3'));
insert into ids select 'w_G', public.request_shift_swap(pg_temp.gid('sG'), pg_temp.id('p_s3'));
select pg_temp.act_as('u_s5');
insert into ids select 'w_H', public.request_shift_swap(pg_temp.gid('sH'), pg_temp.id('p_s3'), pg_temp.gid('sI'));
select pg_temp.act_as('postgres');
select results_eq($$select kind, status, from_person_id, to_person_id, counter_shift_id is null, auto_approved, decided_at is null from public.shift_swaps where id = pg_temp.gid('w_A')$$,
  $$values ('swap'::text, 'requested'::text, pg_temp.id('p_s2'), pg_temp.id('p_s3'), true, false, true)$$, 'a swap request: requested, from s2 to s3, no counter shift, not auto-approved');
select is((select count(*) from public.outbox_events where type = 'shift_swap.requested' and entity_id = pg_temp.gid('w_A')), 1::bigint, 'one shift_swap.requested per request');
select is((select array_agg(k order by k) from (select distinct jsonb_object_keys(payload) k from public.outbox_events where type = 'shift_swap.requested') x),
  array['actor_person_id', 'auto_approved', 'counter_shift_id', 'from_person_id', 'kind', 'location_id', 'shift_id', 'status', 'swap_id', 'to_person_id'], 'its payload is ids, kind and status only');
select is((select count(*) from public.outbox_events e where e.type like 'shift_swap.%' and e.payload::text like '%SWAP-NOTE%'), 0::bigint, 'the note is not in any event');
select is((select count(*) from public.shifts where id in (pg_temp.gid('sA'), pg_temp.gid('sB')) and assigned_person_id = pg_temp.id('p_s2')), 2::bigint, 'a request moves nobody (the shifts stay with s2)');

-- ===========================================================================
-- 2. respond_shift_swap: only the other person; B's own four rules apply (not overridable here)
-- ===========================================================================
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_A'))), '42501 not allowed', 'the person who offered cannot accept their own swap (42501)');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_A'))), '42501 not allowed', 'a third person cannot answer it');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_A'))), '42501 not allowed', 'nor can a manager answer for the other person');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_A'))), '42501 not allowed', 'nor an admin of another organization');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', gen_random_uuid())), '42501 not allowed', 'an unknown swap gives the same refusal');
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, null)', pg_temp.gid('w_A'))), '22023 accept or decline', 'neither accept nor decline is refused (22023)');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_A'))), '23514 that person already has a shift at that time [overlap]', 'accept: s3 already works Monday 10-12, so overlap is refused');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_B'))), '23514 that person has approved time off then [time_off]', 'accept: s4 has approved time off that day (time_off)');
select pg_temp.act_as('u_s6');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_C'))), '23514 that person is missing a required qualification [qualification]', 'accept: s6 has no Lifeguard certificate (qualification)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shift_swaps where status = 'requested' and id in (pg_temp.gid('w_A'), pg_temp.gid('w_B'), pg_temp.gid('w_C'))), 3::bigint, 'the refused accepts left the three swaps requested');
select is((select count(*) from public.outbox_events where type in ('shift_swap.accepted', 'shift_swap.approved') and entity_id in (pg_temp.gid('w_A'), pg_temp.gid('w_B'), pg_temp.gid('w_C'))), 0::bigint, 'and wrote no accepted event');
-- the decline path
select pg_temp.act_as('u_s3');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, false)', pg_temp.gid('w_A'))), 'denied', 'declining returns denied');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_A'))), '22023 this swap is no longer open', 'twin: answering a closed swap again is refused (22023)');
select pg_temp.act_as('postgres');
select results_eq($$select status, decided_by_person_id, auto_approved from public.shift_swaps where id = pg_temp.gid('w_A')$$, $$values ('denied'::text, pg_temp.id('p_s3'), false)$$, 'a declined swap is denied, decided by s3');
select is(pg_temp.ev('shift_swap.denied', 'w_A'), 1::bigint, 'one shift_swap.denied');
select is(pg_temp.holder('sA'), pg_temp.id('p_s2'), 'sA is still s2''s');
-- accept paths that succeed (no auto-approve): status accepted, waits for a manager
select pg_temp.act_as('u_s3');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_D'))), 'accepted', 'twin: s3 accepts the plain swap; with auto-approve off it waits (accepted)');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_E'))), 'accepted', 'and the second one');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_H'))), 'accepted', 'and the counter swap with s5');
select pg_temp.act_as('postgres');
select is(pg_temp.ev('shift_swap.accepted', 'w_D'), 1::bigint, 'one shift_swap.accepted');
select is((select count(*) from public.outbox_events where type = 'shift_swap.approved' and entity_id in (pg_temp.gid('w_D'), pg_temp.gid('w_E'), pg_temp.gid('w_H'))), 0::bigint, 'no approval yet, and no shift moved');
select is(pg_temp.holder('sD'), pg_temp.id('p_s2'), 'sD is still with s2 after the accept');
select is((select count(*) from public.outbox_events where type in ('shift.assigned', 'shift.unassigned') and entity_id in (pg_temp.gid('sD'), pg_temp.gid('sE'), pg_temp.gid('sH'), pg_temp.gid('sI'))), 0::bigint, 'and no shift.assigned or shift.unassigned');

-- ===========================================================================
-- 3. decide_shift_swap
-- ===========================================================================
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_D'))), '42501 not allowed', 'staff (shift_swaps edit only) cannot decide (42501)');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_D'))), '42501 not allowed', 'nor a bystander');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_D'))), '42501 not allowed', 'nor an admin of another organization');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', gen_random_uuid())), '42501 not allowed', 'an unknown swap gives the same refusal');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_D'))), '42501 permission denied for function decide_shift_swap', 'anon has no execute right');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, null)', pg_temp.gid('w_D'))), '22023 approve or deny', 'neither approve nor deny is refused (22023)');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_B'))), '22023 this request is not waiting for a decision', 'a swap the other person has not accepted cannot be decided (22023)');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true, true)', pg_temp.gid('w_D'))), '42501 not allowed', 'asking to override is refused first for someone who may not decide at all');
select pg_temp.act_as('postgres');
update public.user_permissions set level = level where false;
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_s4'), pg_temp.id('loc_a1'), 'shift_swaps', 'admin');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true, true)', pg_temp.gid('w_D'))), '42501 only a schedule admin can override', 'a shift_swaps admin without staff_schedule admin cannot override (42501)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shift_swaps where id = pg_temp.gid('w_D') and status = 'accepted'), 1::bigint, 'and the swap is untouched');
-- swap approve re-checks the rules: time off appears for s3 on Thursday after the accept
insert into public.time_off_requests (organization_id, person_id, starts_on, ends_on, status, decided_by_person_id, decided_at)
values (pg_temp.id('org_a'), pg_temp.id('p_s3'), pg_temp.wk() + 3, pg_temp.wk() + 3, 'approved', pg_temp.id('p_manager_a1'), now());
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id)
values (pg_temp.id('sh_conf'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(4, '11:00'), pg_temp.a1(4, '12:00'), pg_temp.id('p_s3'));
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_D'))), '23514 that person has approved time off then [time_off]', 'approve re-checks: time off added after the accept refuses the move (time_off)');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_E'))), '23514 that person already has a shift at that time [overlap]', 'and an overlap added after the accept (overlap)');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true, true)', pg_temp.gid('w_E'))), '23514 that person already has a shift at that time [overlap]', 'an overlap cannot be overridden, even by a schedule admin');
select pg_temp.act_as('postgres');
select is(pg_temp.holder('sD'), pg_temp.id('p_s2'), 'nothing moved after the refusals');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true, true)', pg_temp.gid('w_D'))), 'ok', 'twin: the schedule admin overrides time off and the swap goes through');
select pg_temp.act_as('postgres');
select results_eq($$select assigned_person_id, override_kinds, override_by_person_id from public.shifts where id = pg_temp.gid('sD')$$,
  $$values (pg_temp.id('p_s3'), array['time_off']::text[], pg_temp.id('p_manager_a1'))$$, 'sD is s3''s now, and the override (time_off, by the manager) is recorded on it');
select results_eq($$select status, decided_by_person_id, auto_approved from public.shift_swaps where id = pg_temp.gid('w_D')$$, $$values ('approved'::text, pg_temp.id('p_manager_a1'), false)$$, 'the swap is approved by the manager (not automatic)');
select is(pg_temp.ev('shift_swap.approved', 'w_D'), 1::bigint, 'one shift_swap.approved');
select results_eq($$select payload ->> 'person_id', payload ->> 'via', payload ->> 'previous_person_id', payload ->> 'override' from public.outbox_events where type = 'shift.assigned' and entity_id = pg_temp.gid('sD')$$,
  $$values (pg_temp.id('p_s3')::text, 'swap'::text, pg_temp.id('p_s2')::text, 'true'::text)$$, 'shift.assigned names s3, via swap, previous holder s2, override true');
select results_eq($$select payload ->> 'person_id', payload ->> 'new_person_id', payload ->> 'via' from public.outbox_events where type = 'shift.unassigned' and entity_id = pg_temp.gid('sD')$$,
  $$values (pg_temp.id('p_s2')::text, pg_temp.id('p_s3')::text, 'swap'::text)$$, 'and shift.unassigned names s2, via swap');
select is((select count(*) from public.outbox_events where type = 'shift.opened' and entity_id = pg_temp.gid('sD')), 0::bigint, 'a swap never announces the shift as open (X leaves A and reaches B in one transaction)');
select ok(exists (select 1 from public.audit_log where table_name = 'shifts' and row_id = pg_temp.gid('sD')::text and action = 'update' and (new_row ->> 'override_kinds') is not null), 'the override is audited');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_D'))), '22023 this request is not waiting for a decision', 'approving it again is refused (22023)');
-- w_E: remove the conflict, then approve (twin)
select pg_temp.act_as('postgres');
delete from public.shifts where id = pg_temp.id('sh_conf');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_E'))), 'ok', 'twin: with the conflict gone, the same swap is approved without an override');
select pg_temp.act_as('postgres');
select is((select override_kinds from public.shifts where id = pg_temp.gid('sE')), null, 'and nothing is recorded as overridden');
-- counter swap
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_H'))), 'ok', 'the counter swap is approved');
select pg_temp.act_as('postgres');
select results_eq($$select pg_temp.holder('sH'), pg_temp.holder('sI')$$, $$values (pg_temp.id('p_s3'), pg_temp.id('p_s5'))$$, 'both shifts moved: s3 has sH and s5 has sI');
select is((select count(*) from public.outbox_events where type = 'shift.assigned' and entity_id in (pg_temp.gid('sH'), pg_temp.gid('sI')) and payload ->> 'via' = 'swap'), 2::bigint, 'two shift.assigned (one per shift)');
select is((select count(*) from public.outbox_events where type = 'shift.unassigned' and entity_id in (pg_temp.gid('sH'), pg_temp.gid('sI')) and payload ->> 'via' = 'swap'), 2::bigint, 'two shift.unassigned');
select is(pg_temp.ev('shift_swap.approved', 'w_H'), 1::bigint, 'and one shift_swap.approved');
-- deny
select pg_temp.act_as('u_s3');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_J'))), 'accepted', 'twin: s3 accepts the swap of sJ');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, false)', pg_temp.gid('w_J'))), 'ok', 'a manager can deny an accepted swap');
select pg_temp.act_as('postgres');
select results_eq($$select status, decided_by_person_id from public.shift_swaps where id = pg_temp.gid('w_J')$$, $$values ('denied'::text, pg_temp.id('p_manager_a1'))$$, 'denied by the manager');
select is(pg_temp.holder('sJ'), pg_temp.id('p_s2'), 'and the shift did not move');
select is(pg_temp.ev('shift_swap.denied', 'w_J'), 1::bigint, 'one shift_swap.denied');
-- not deciding your own
select pg_temp.act_as('u_orgadmin_a');
insert into ids select 'w_O', public.request_shift_swap(pg_temp.gid('sO'), pg_temp.id('p_s3'));
select pg_temp.act_as('u_s3');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_O'))), 'accepted', 'an admin offers a shift and the other person accepts');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_O'))), '42501 you cannot decide your own swap', 'the admin (who may decide swaps in general) cannot decide their own (42501)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_O'))), 'ok', 'twin: a different admin decides it');

-- ===========================================================================
-- 4. Stale shifts, and cancel by either party
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select public.assign_shift(pg_temp.gid('sF'), pg_temp.id('p_s5'));
select pg_temp.act_as('postgres');
select results_eq($$select status, decided_by_person_id is null from public.shift_swaps where id = pg_temp.gid('w_F')$$, $$values ('cancelled'::text, true)$$, 'when a manager gives the shift to someone else, the open swap is cancelled by the system');
select is(pg_temp.ev('shift_swap.cancelled', 'w_F'), 1::bigint, 'with one shift_swap.cancelled');
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_F'))), '22023 this swap is no longer open', 'accepting it afterwards is refused (22023)');
select pg_temp.act_as('postgres');
-- the owner changes the holder without going through the service: accept and approve see the stale shift
update public.shifts set assigned_person_id = pg_temp.id('p_s6') where id = pg_temp.gid('sG');
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_G'))), '23514 the shift changed since the swap was offered [stale]', 'accept: a shift whose holder changed is stale (23514, stale)');
select pg_temp.act_as('postgres');
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id)
values (pg_temp.id('sh_stale'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(2, '22:00'), pg_temp.a1(2, '23:00'), pg_temp.id('p_s2'));
insert into public.shift_swaps (id, organization_id, location_id, kind, shift_id, from_person_id, to_person_id, status, accepted_at)
values (pg_temp.id('w_stale'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'swap', pg_temp.id('sh_stale'), pg_temp.id('p_s2'), pg_temp.id('p_s3'), 'accepted', now());
update public.shifts set assigned_person_id = pg_temp.id('p_s4') where id = pg_temp.id('sh_stale');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.id('w_stale'))), '23514 the shift changed since the swap was offered [stale]', 'approve: a stale shift is refused too (23514, stale)');
select pg_temp.act_as('postgres');
-- cancel by either party
select pg_temp.act_as('u_s2');
insert into ids select 'w_K1', public.request_shift_swap(pg_temp.gid('sJ'), pg_temp.id('p_s3'));
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('w_K1'))), '42501 not allowed', 'a bystander cannot cancel a swap (42501)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('w_K1'))), '42501 not allowed', 'nor can a manager (they decide; they do not cancel for a party)');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('w_K1'))), '42501 not allowed', 'nor another organization');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown swap gives the same refusal');
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('w_K1'))), 'ok', 'the person asked (s3) can cancel');
select pg_temp.act_as('postgres');
select results_eq($$select status, decided_by_person_id from public.shift_swaps where id = pg_temp.gid('w_K1')$$, $$values ('cancelled'::text, pg_temp.id('p_s3'))$$, 'cancelled, by s3');
select is(pg_temp.ev('shift_swap.cancelled', 'w_K1'), 1::bigint, 'one shift_swap.cancelled');
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('w_K1'))), '22023 this request is already closed', 'cancelling twice is refused (22023)');
select pg_temp.act_as('u_s2');
insert into ids select 'w_K2', public.request_shift_swap(pg_temp.gid('sJ'), pg_temp.id('p_s3'));
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('w_K2'))), 'ok', 'twin: the person who offered (s2) can cancel too');
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_K2'))), '22023 this swap is no longer open', 'and the cancelled swap can no longer be accepted');
select pg_temp.act_as('u_s2');
insert into ids select 'w_K3', public.request_shift_swap(pg_temp.gid('sJ'), pg_temp.id('p_s3'));
select pg_temp.act_as('u_s3');
select public.respond_shift_swap(pg_temp.gid('w_K3'), true);
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('w_K3'))), 'ok', 'an accepted swap can still be cancelled by the person who offered');
select pg_temp.act_as('postgres');
select is(pg_temp.sw('w_K3'), 'cancelled', 'status cancelled');

-- ===========================================================================
-- 5. Auto-approve setting
-- ===========================================================================
update public.organization_settings set settings = jsonb_set(settings, '{staffing}', '{"auto_approve_swaps": true}') where organization_id = pg_temp.id('org_a');
select pg_temp.act_as('u_s2');
insert into ids select 'w_K', public.request_shift_swap(pg_temp.gid('sK'), pg_temp.id('p_s3'));
insert into ids select 'w_L', public.request_shift_swap(pg_temp.gid('sL'), pg_temp.id('p_s3'), pg_temp.gid('sM'));
select pg_temp.act_as('postgres');
insert into public.time_off_requests (organization_id, person_id, starts_on, ends_on, status, decided_by_person_id, decided_at)
values (pg_temp.id('org_a'), pg_temp.id('p_s2'), pg_temp.wk() + 6, pg_temp.wk() + 6, 'approved', pg_temp.id('p_manager_a1'), now());
select pg_temp.act_as('u_s3');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_K'))), 'approved', 'with auto-approve on, an accepted swap that passes every rule is approved at once');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_L'))), 'accepted', 'but when the first person fails a rule on the counter shift (time off), it waits for a manager');
select pg_temp.act_as('postgres');
select results_eq($$select status, auto_approved, decided_by_person_id is null from public.shift_swaps where id = pg_temp.gid('w_K')$$, $$values ('approved'::text, true, true)$$, 'the automatic approval is marked auto_approved with no deciding person');
select is(pg_temp.holder('sK'), pg_temp.id('p_s3'), 'and the shift moved');
select is(pg_temp.ev('shift_swap.accepted', 'w_K') + pg_temp.ev('shift_swap.approved', 'w_K'), 2::bigint, 'one accepted and one approved event');
select is((select (payload ->> 'auto_approved')::boolean from public.outbox_events where type = 'shift_swap.approved' and entity_id = pg_temp.gid('w_K')), true, 'the approved event says auto_approved');
select results_eq($$select pg_temp.holder('sL'), pg_temp.holder('sM')$$, $$values (pg_temp.id('p_s2'), pg_temp.id('p_s3'))$$, 'nothing moved for the swap that could not finish');
select is((select count(*) from public.outbox_events where type = 'shift.assigned' and entity_id in (pg_temp.gid('sL'), pg_temp.gid('sM'))), 0::bigint, 'with no shift.assigned');
update public.organization_settings set settings = settings - 'staffing' where organization_id = pg_temp.id('org_a');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_L'))), '23514 that person has approved time off then [time_off]', 'the manager''s approval of that swap sees the same rule (time_off for s2 on the counter shift)');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true, true)', pg_temp.gid('w_L'))), 'ok', 'and the override lets it through');
select pg_temp.act_as('postgres');
select results_eq($$select pg_temp.holder('sL'), pg_temp.holder('sM'), (select override_kinds from public.shifts where id = pg_temp.gid('sM'))$$, $$values (pg_temp.id('p_s3'), pg_temp.id('p_s2'), array['time_off']::text[])$$, 'the shifts traded, and the override sits on the shift the overridden person received');

-- ===========================================================================
-- 6. Drops
-- ===========================================================================
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.request_shift_drop(%L)', pg_temp.gid('d1'))), '42501 not allowed', 'a person cannot drop a shift someone else holds (42501)');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.request_shift_drop(%L, %L)', pg_temp.gid('d1'), repeat('n', 501))), '22023 the note is too long', 'a drop note over 500 characters is refused');
select is(pg_temp.fd(format('select public.request_shift_drop(%L)', pg_temp.id('sh_draft_s2'))), '42501 not allowed', 'a shift on a draft week cannot be dropped');
insert into ids select 'w_d1', public.request_shift_drop(pg_temp.gid('d1'), 'DROP-NOTE');
insert into ids select 'w_d3', public.request_shift_drop(pg_temp.gid('d3'));
select pg_temp.act_as('u_s6');
insert into ids select 'w_d2', public.request_shift_drop(pg_temp.gid('d2'));
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('w_d2'))), '42501 not allowed', 'a drop cannot be accepted by anyone (it is not a swap)');
select pg_temp.act_as('postgres');
select results_eq($$select kind, status, to_person_id is null, counter_shift_id is null from public.shift_swaps where id = pg_temp.gid('w_d1')$$, $$values ('drop'::text, 'requested'::text, true, true)$$, 'a drop: kind drop, requested, no other person');
select is(pg_temp.ev('shift_swap.requested', 'w_d1'), 1::bigint, 'one shift_swap.requested (kind drop)');
select is((select count(*) from public.outbox_events e where e.type like 'shift_swap.%' and e.payload::text like '%DROP-NOTE%'), 0::bigint, 'the drop note is in no event');
select is(pg_temp.holder('d1'), pg_temp.id('p_s4'), 'it stays s4''s until a manager decides');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_d1'))), '42501 you cannot decide your own swap', 'a shift_swaps admin (s4, granted above) still cannot approve their own drop (42501)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_d1'))), 'ok', 'the manager approves the drop');
select pg_temp.act_as('postgres');
select is(pg_temp.holder('d1'), null, 'the shift is open');
select is(pg_temp.ev('shift_swap.approved', 'w_d1'), 1::bigint, 'one shift_swap.approved');
select results_eq($$select payload ->> 'person_id', payload ->> 'via' from public.outbox_events where type = 'shift.unassigned' and entity_id = pg_temp.gid('d1')$$, $$values (pg_temp.id('p_s4')::text, 'drop'::text)$$, 'one shift.unassigned for s4 via drop');
select results_eq($$select payload ->> 'via' from public.outbox_events where type = 'shift.opened' and entity_id = pg_temp.gid('d1')$$, $$values ('drop'::text)$$, 'and one shift.opened via drop (it is announced as open)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, false)', pg_temp.gid('w_d3'))), 'ok', 'a drop can be denied');
select pg_temp.act_as('postgres');
select results_eq($$select pg_temp.holder('d3'), pg_temp.sw('w_d3')$$, $$values (pg_temp.id('p_s4'), 'denied'::text)$$, 'and the shift stays with the person');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.request_shift_drop(%L)', pg_temp.gid('d3'))), 'ok', 'twin: after a denial the person can ask again');
select pg_temp.act_as('postgres');
update public.shifts set assigned_person_id = pg_temp.id('p_s5') where id = pg_temp.gid('d2');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('w_d2'))), '23514 the shift changed since the drop was requested [stale]', 'approving a drop for a shift that changed hands is refused (23514, stale)');
select pg_temp.act_as('postgres');
select is(pg_temp.holder('d2'), pg_temp.id('p_s5'), 'nothing was opened');

-- ===========================================================================
-- 7. Claims (manager approves)
-- ===========================================================================
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.gid('o1'))), '23514 that person is missing a required qualification [qualification]', 'a claim is refused when the claimant lacks the certificate (qualification)');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.id('sh_draft_open'))), '42501 not allowed', 'an open shift on a draft week cannot be claimed (staff cannot see it)');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown shift gives the same refusal');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.gid('sA'))), '23514 this shift is no longer open [stale]', 'a shift someone holds cannot be claimed (23514, stale)');
select is((select count(*) from public.shift_claims), 0::bigint, 'no claim was created by the refused calls');
select is((select count(*) from public.my_claimable_shifts(pg_temp.id('org_a')) where shift_id = pg_temp.gid('o1')), 0::bigint, 'my_claimable_shifts leaves out the certified shift for someone without the certificate');
select is((select count(*) from public.my_claimable_shifts(pg_temp.id('org_a')) where shift_id = pg_temp.gid('o2')), 1::bigint, 'twin: and lists a shift they can work');
select is((select count(*) from public.my_claimable_shifts(pg_temp.id('org_a')) where shift_id = pg_temp.id('sh_draft_open')), 0::bigint, 'but never an open shift on a draft week');
select is((select count(*) from public.my_claimable_shifts(pg_temp.id('org_b'))), 0::bigint, 'another organization''s id gives an empty list');
select ok((select count(*) from public.my_claimable_shifts(pg_temp.id('org_a'), 1)) = 1 and (select count(*) from public.my_claimable_shifts(pg_temp.id('org_a'), 0)) = 1 and (select count(*) from public.my_claimable_shifts(pg_temp.id('org_a'), null)) > 1, 'the limit is clamped to at least 1; null means 50');
select pg_temp.act_as('u_s2');
select is((select count(*) from public.my_claimable_shifts(pg_temp.id('org_a')) where shift_id = pg_temp.gid('o1')), 1::bigint, 'a certified, free person is offered the certified shift');
select is((select count(*) from public.my_claimable_shifts(pg_temp.id('org_a')) where shift_id = pg_temp.gid('d1')), 1::bigint, 'and the shift just dropped by s4');
select pg_temp.act_as('u_s3');
insert into ids select 'c_o2s3', public.request_shift_claim(pg_temp.gid('o2'));
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.gid('o2'))), '22023 you already asked for this shift', 'a second claim of the same shift by the same person is refused (22023)');
select is((select count(*) from public.my_claimable_shifts(pg_temp.id('org_a')) where shift_id = pg_temp.gid('o2')), 0::bigint, 'and the shift leaves their claimable list');
select pg_temp.act_as('u_s4');
insert into ids select 'c_o2s4', public.request_shift_claim(pg_temp.gid('o2'));
select pg_temp.act_as('postgres');
select results_eq($$select status, auto_approved, decided_at is null from public.shift_claims where id = pg_temp.gid('c_o2s3')$$, $$values ('requested'::text, false, true)$$, 'with first-come off a claim waits for a manager');
select is(pg_temp.ev('shift_claim.requested', 'c_o2s3'), 1::bigint, 'one shift_claim.requested');
select is((select array_agg(k order by k) from (select distinct jsonb_object_keys(payload) k from public.outbox_events where type = 'shift_claim.requested') x),
  array['actor_person_id', 'auto_approved', 'claim_id', 'location_id', 'person_id', 'shift_id', 'status'], 'its payload is ids and status only');
select is(pg_temp.holder('o2'), null, 'and the shift is still open');
-- deciding
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', pg_temp.gid('c_o2s3'))), '42501 not allowed', 'staff cannot decide a claim, not even their own (42501)');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', pg_temp.gid('c_o2s3'))), '42501 not allowed', 'nor another organization');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', gen_random_uuid())), '42501 not allowed', 'an unknown claim gives the same refusal');
select pg_temp.act_as('anon');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', pg_temp.gid('c_o2s3'))), '42501 permission denied for function decide_shift_claim', 'anon has no execute right');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, null)', pg_temp.gid('c_o2s3'))), '22023 approve or deny', 'neither approve nor deny is refused (22023)');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true, true)', pg_temp.gid('c_o2s3'))), '42501 only a schedule admin can override', 'asking to override is refused for a shift_swaps admin (s4) who is not a schedule admin');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', pg_temp.gid('c_o2s3'))), 'ok', 'twin: the manager approves s3''s claim');
select pg_temp.act_as('postgres');
select is(pg_temp.holder('o2'), pg_temp.id('p_s3'), 'the shift is s3''s');
select results_eq($$select status, decided_by_person_id, auto_approved from public.shift_claims where id = pg_temp.gid('c_o2s3')$$, $$values ('approved'::text, pg_temp.id('p_manager_a1'), false)$$, 'approved by the manager');
select results_eq($$select status, decided_by_person_id is null from public.shift_claims where id = pg_temp.gid('c_o2s4')$$, $$values ('denied'::text, true)$$, 'the other claim on that shift is denied by the system (no deciding person)');
select is(pg_temp.ev('shift_claim.approved', 'c_o2s3'), 1::bigint, 'one shift_claim.approved');
select is(pg_temp.ev('shift_claim.denied', 'c_o2s4'), 1::bigint, 'and one shift_claim.denied for the other claim');
select results_eq($$select payload ->> 'person_id', payload ->> 'via', payload ->> 'override' from public.outbox_events where type = 'shift.assigned' and entity_id = pg_temp.gid('o2') and payload ->> 'via' = 'claim'$$, $$values (pg_temp.id('p_s3')::text, 'claim'::text, 'false'::text)$$, 'one shift.assigned via claim, no override');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', pg_temp.gid('c_o2s4'))), '22023 this request is not waiting for a decision', 'a denied claim cannot be approved afterwards (22023)');
-- a deny
select pg_temp.act_as('u_s2');
insert into ids select 'c_o8s4', public.request_shift_claim(pg_temp.gid('o8'));
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, false)', pg_temp.gid('c_o8s4'))), 'ok', 'a claim can be denied');
select pg_temp.act_as('postgres');
select results_eq($$select status, decided_by_person_id from public.shift_claims where id = pg_temp.gid('c_o8s4')$$, $$values ('denied'::text, pg_temp.id('p_manager_a1'))$$, 'denied by the manager');
select is(pg_temp.holder('o8'), null, 'and the shift is still open');
-- not deciding your own
select pg_temp.act_as('u_manager_a1');
insert into ids select 'c_o3m', public.request_shift_claim(pg_temp.gid('o3'));
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', pg_temp.gid('c_o3m'))), '42501 you cannot decide your own request', 'a manager cannot decide their own claim (42501)');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', pg_temp.gid('c_o3m'))), 'ok', 'twin: another admin can');
-- rules again at approval
select pg_temp.act_as('u_s5');
insert into ids select 'c_o4', public.request_shift_claim(pg_temp.gid('o4'));
select pg_temp.act_as('u_s6');
insert into ids select 'c_o5', public.request_shift_claim(pg_temp.gid('o5'));
select pg_temp.act_as('postgres');
insert into public.time_off_requests (organization_id, person_id, starts_on, ends_on, status, decided_by_person_id, decided_at)
values (pg_temp.id('org_a'), pg_temp.id('p_s5'), pg_temp.wk() + 4, pg_temp.wk() + 4, 'approved', pg_temp.id('p_manager_a1'), now());
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id)
values (pg_temp.id('sh_conf2'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.gid('sched'), pg_temp.gid('pos_fd'), pg_temp.a1(5, '20:00'), pg_temp.a1(5, '22:00'), pg_temp.id('p_s6'));
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', pg_temp.gid('c_o4'))), '23514 that person has approved time off then [time_off]', 'claim approve re-checks: time off added after the claim (time_off)');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', pg_temp.gid('c_o5'))), '23514 that person already has a shift at that time [overlap]', 'and an overlap added after the claim (overlap)');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true, true)', pg_temp.gid('c_o5'))), '23514 that person already has a shift at that time [overlap]', 'an overlap cannot be overridden, even by a schedule admin');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shifts where id in (pg_temp.gid('o4'), pg_temp.gid('o5')) and assigned_person_id is not null), 0::bigint, 'both shifts are still open after the refusals');
select is((select count(*) from public.shift_claims where id in (pg_temp.gid('c_o4'), pg_temp.gid('c_o5')) and status = 'requested'), 2::bigint, 'and both claims are still waiting');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true, true)', pg_temp.gid('c_o4'))), 'ok', 'twin: the schedule admin overrides time off and approves the first claim');
select pg_temp.act_as('postgres');
select results_eq($$select assigned_person_id, override_kinds, override_by_person_id from public.shifts where id = pg_temp.gid('o4')$$, $$values (pg_temp.id('p_s5'), array['time_off']::text[], pg_temp.id('p_manager_a1'))$$, 'recorded on the shift: kind, and who overrode');
select is((select (payload ->> 'override')::boolean from public.outbox_events where type = 'shift.assigned' and entity_id = pg_temp.gid('o4') and payload ->> 'via' = 'claim'), true, 'and shift.assigned says override true');
-- the assignee changes under a claim: the system denies it
select pg_temp.act_as('u_s3');
insert into ids select 'c_o8s3', public.request_shift_claim(pg_temp.gid('o8'));
select pg_temp.act_as('u_manager_a1');
select public.assign_shift(pg_temp.gid('o8'), pg_temp.id('p_s6'));
select pg_temp.act_as('postgres');
select results_eq($$select status, decided_by_person_id is null from public.shift_claims where id = pg_temp.gid('c_o8s3')$$, $$values ('denied'::text, true)$$, 'when a manager assigns the shift directly, an open claim on it is denied by the system');
select is(pg_temp.ev('shift_claim.denied', 'c_o8s3'), 1::bigint, 'with one shift_claim.denied');
-- cancelling a claim
select pg_temp.act_as('u_s2');
insert into ids select 'c_o1', public.request_shift_claim(pg_temp.gid('o1'));
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.cancel_shift_claim(%L)', pg_temp.gid('c_o1'))), '42501 not allowed', 'only the claimant can cancel a claim (42501)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.cancel_shift_claim(%L)', pg_temp.gid('c_o1'))), '42501 not allowed', 'not even a manager');
select is(pg_temp.fd(format('select public.cancel_shift_claim(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown claim gives the same refusal');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.cancel_shift_claim(%L)', pg_temp.gid('c_o1'))), 'ok', 'the claimant cancels');
select is(pg_temp.fd(format('select public.cancel_shift_claim(%L)', pg_temp.gid('c_o1'))), '22023 this request is already closed', 'cancelling twice is refused (22023)');
select pg_temp.act_as('postgres');
select results_eq($$select status, decided_by_person_id from public.shift_claims where id = pg_temp.gid('c_o1')$$, $$values ('cancelled'::text, pg_temp.id('p_s2'))$$, 'cancelled by the claimant');
select is(pg_temp.ev('shift_claim.cancelled', 'c_o1'), 1::bigint, 'one shift_claim.cancelled');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.gid('o1'))), 'ok', 'twin: after cancelling, the same person can claim again');

-- ===========================================================================
-- 8. First come, first served
-- ===========================================================================
select pg_temp.act_as('postgres');
update public.organization_settings set settings = jsonb_set(settings, '{staffing}', '{"first_come_open_shifts": true}') where organization_id = pg_temp.id('org_a');
create temp table ev_pre as select count(*) as n from public.outbox_events;
grant all on ev_pre to public;
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.gid('o7'))), '23514 that person is missing a required qualification [qualification]', 'first-come: an uncertified claimant is refused (qualification), not approved by luck');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shift_claims where shift_id = pg_temp.gid('o7')), 0::bigint, 'and no claim row exists (the whole call rolled back)');
select is((select count(*) from public.outbox_events) - (select n from ev_pre), 0::bigint, 'and no event was written');
select pg_temp.act_as('u_s4');
insert into ids select 'c_o6s4', public.request_shift_claim(pg_temp.gid('o6'));
select pg_temp.act_as('postgres');
select results_eq($$select status, auto_approved, decided_by_person_id is null from public.shift_claims where id = pg_temp.gid('c_o6s4')$$, $$values ('approved'::text, true, true)$$, 'first-come: the claim is approved at once, marked auto_approved, no deciding person');
select is(pg_temp.holder('o6'), pg_temp.id('p_s4'), 'the shift is s4''s');
select is(pg_temp.ev('shift_claim.approved', 'c_o6s4'), 1::bigint, 'one shift_claim.approved');
select is(pg_temp.ev('shift_claim.requested', 'c_o6s4'), 0::bigint, 'and no shift_claim.requested (it never waited)');
select results_eq($$select payload ->> 'person_id', payload ->> 'via' from public.outbox_events where type = 'shift.assigned' and entity_id = pg_temp.gid('o6')$$, $$values (pg_temp.id('p_s4')::text, 'claim'::text)$$, 'and one shift.assigned via claim');
select pg_temp.act_as('u_s5');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.gid('o6'))), '23514 this shift is no longer open [stale]', 'the second claimant loses (23514, stale)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shift_claims where shift_id = pg_temp.gid('o6')), 1::bigint, 'and leaves no claim behind');
-- first-come still applies overlap
select pg_temp.act_as('u_s6');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.gid('o2'))), '23514 this shift is no longer open [stale]', 'twin: a shift already assigned stays closed to claims');
select pg_temp.act_as('postgres');
update public.organization_settings set settings = settings - 'staffing' where organization_id = pg_temp.id('org_a');

-- ===========================================================================
-- 9. Whole-family checks
-- ===========================================================================
select is((select count(*) from public.outbox_events e, jsonb_object_keys(e.payload) k where (e.type like 'shift_swap.%' or e.type like 'shift_claim.%') and k in ('note', 'notes', 'reason', 'name', 'title')), 0::bigint, 'no free-text key in any swap or claim payload');
select ok(not exists (select 1 from public.outbox_events e where (e.type like 'shift_swap.%' or e.type like 'shift_claim.%') and e.organization_id <> pg_temp.id('org_a')), 'every swap and claim event belongs to org A');
select is((select count(*) from public.audit_log a where a.table_name = 'shift_swaps' and (a.new_row::text like '%SWAP-NOTE%' or a.new_row::text like '%DROP-NOTE%')), 0::bigint, 'swap and drop notes are not in the audit log');
select is((select new_row ->> 'note' from public.audit_log where table_name = 'shift_swaps' and action = 'insert' and row_id = pg_temp.gid('w_A')::text), '[redacted]', 'the note column is redacted there');
-- exchanges only on published, not-started shifts (the visibility guard alone must not be what stops them)
select pg_temp.act_as('postgres');
insert into public.schedules (id, organization_id, location_id, week_start, status, published_at) values
  (pg_temp.id('sc_past'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk() - 14, 'published', now() - interval '20 days');
insert into public.shifts (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id) values
  (pg_temp.id('sh_past'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('sc_past'), pg_temp.gid('pos_fd'), pg_temp.a1(-14, '09:00'), pg_temp.a1(-14, '13:00'), pg_temp.id('p_s2')),
  (pg_temp.id('sh_past_open'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('sc_past'), pg_temp.gid('pos_fd'), pg_temp.a1(-13, '09:00'), pg_temp.a1(-13, '13:00'), null),
  (pg_temp.id('sh_draft_s5'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('sched_draft'), pg_temp.gid('pos_fd'), pg_temp.a1(9, '09:00'), pg_temp.a1(9, '13:00'), pg_temp.id('p_s5'));
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_s5'), pg_temp.id('loc_a1'), 'staff_schedule', 'edit');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.id('sh_past'), pg_temp.id('p_s3'))), '22023 this shift cannot be swapped now', 'a shift that has already started cannot be offered (22023)');
select is(pg_temp.fd(format('select public.request_shift_drop(%L)', pg_temp.id('sh_past'))), '22023 this shift cannot be dropped now', 'nor dropped');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.id('sh_past_open'))), '23514 this shift is no longer open [stale]', 'nor an open shift that has started claimed');
select pg_temp.act_as('u_s5');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.id('sh_draft_s5'), pg_temp.id('p_s3'))), '22023 this shift cannot be swapped now', 'a scheduler who can see a draft week still cannot offer a shift of it (22023)');
select is(pg_temp.fd(format('select public.request_shift_drop(%L)', pg_temp.id('sh_draft_s5'))), '22023 this shift cannot be dropped now', 'nor drop it');
select pg_temp.act_as('postgres');
select is((select count(*) from public.shift_swaps where shift_id in (pg_temp.id('sh_past'), pg_temp.id('sh_draft_s5'))), 0::bigint, 'and no swap or drop row exists for them');
select ok((select count(*) from public.shift_swaps where status in ('requested', 'accepted') and (shift_id in (select id from public.shifts where status = 'cancelled'))) = 0, 'no open swap points at a cancelled shift');

select * from finish();
rollback;
