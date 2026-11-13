-- PHASE 3 GATE: a week of shifts built, published, swapped and covered, end to end, as real roles.
--   a manager builds a week from a template and publishes it; staff A offers a shift to staff B, B accepts, the manager approves;
--   staff C drops a shift, the manager approves and it opens; the uncovered sweep announces the open shifts exactly once;
--   staff D claims an open shift and the manager approves. Then: the final assignments, the exact events of every step, and
--   that running each service function again changes nothing.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(60);

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


create function pg_temp.sh(p_day int, p_time text default '09:00') returns uuid language sql stable security definer as $$
  select id from public.shifts where schedule_id = pg_temp.gid('sched') and starts_at = pg_temp.a1(p_day, p_time) $$;
create function pg_temp.pn(p_id uuid) returns text language sql stable security definer as $$
  select coalesce((select n from unnest(array['p_s2', 'p_s3', 'p_s4', 'p_s5', 'p_s6', 'p_staff_a1', 'p_manager_a1', 'p_locadmin_a1', 'p_orgadmin_a']) n where pg_temp.id(n) = p_id), p_id::text) $$;
create function pg_temp.holder(p_day int, p_time text default '09:00') returns text language sql stable security definer as $$
  select coalesce(pg_temp.pn(assigned_person_id), 'open') from public.shifts where id = pg_temp.sh(p_day, p_time) $$;
-- the event types written since the last call, sorted, and mark them as seen
create temp table seen (id uuid primary key);
grant all on seen to public;
create function pg_temp.step() returns text[] language plpgsql security definer as $$
declare v text[];
begin
  select coalesce(array_agg(type order by type collate "C"), '{}') into v from public.outbox_events where id not in (select id from seen);
  insert into seen select id from public.outbox_events on conflict do nothing;
  return v;
end $$;
grant execute on function pg_temp.sh(int, text), pg_temp.pn(uuid), pg_temp.holder(int, text), pg_temp.step() to public;
create function pg_temp.snapshot() returns text language sql stable security definer as $$
  select (select count(*) from public.shifts)::text || '/' || (select count(*) from public.schedules)::text || '/' || (select count(*) from public.shift_swaps)::text || '/' ||
         (select count(*) from public.shift_claims)::text || '/' || (select count(*) from public.outbox_events)::text || '/' ||
         (select string_agg(coalesce(assigned_person_id::text, '-') || status, ',' order by starts_at, id) from public.shifts) || '/' ||
         (select string_agg(status, ',' order by id) from public.shift_swaps) || '/' || (select string_agg(status, ',' order by id) from public.shift_claims) $$;
grant execute on function pg_temp.snapshot() to public;
-- the shift week was empty and quiet: mark everything written so far as seen
select pg_temp.step();

-- ---------------------------------------------------------------------------
-- The people: manager, A (s2), B (s3), C (s4), D (s5); a Lifeguard-free week, so no qualification is involved
-- ---------------------------------------------------------------------------
select pg_temp.act_as('u_manager_a1');
insert into ids select 'pos_fd', public.save_position(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Front desk');

-- ===========================================================================
-- Step 1: the manager builds the week from a template (draft: nothing is announced)
-- ===========================================================================
insert into ids select 'tpl', public.save_shift_template(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Standard week', 7);
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 0, '09:00', 480, pg_temp.id('p_s2'));
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 1, '09:00', 480, pg_temp.id('p_s3'));
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 2, '09:00', 480, pg_temp.id('p_s4'));
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 3, '09:00', 480, null);
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 4, '09:00', 480, pg_temp.id('p_s6'));
select public.add_shift_template_item(pg_temp.gid('tpl'), pg_temp.gid('pos_fd'), 5, '10:00', 240, null);
insert into ids select 'sched', public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk());
create temp table stamped as select * from public.apply_shift_template(pg_temp.gid('sched'), pg_temp.gid('tpl'), 0);
select pg_temp.act_as('postgres');
select is((select count(*) from stamped), 6::bigint, 'step 1: the template made six shifts');
select is((select count(*) from stamped where refused is not null), 0::bigint, 'none of them was refused by a rule');
select is(array[pg_temp.holder(0), pg_temp.holder(1), pg_temp.holder(2), pg_temp.holder(3), pg_temp.holder(4), pg_temp.holder(5, '10:00')],
  array['p_s2', 'p_s3', 'p_s4', 'open', 'p_s6', 'open'], 'step 1: four shifts are assigned (A, B, C, s6) and two are open');
select is((select status from public.schedules where id = pg_temp.gid('sched')), 'draft', 'step 1: the week is a draft');
select is(pg_temp.step(), '{}'::text[], 'step 1: a draft week announces nothing');
-- staff see nothing of a draft
select pg_temp.act_as('u_s2');
select is((select count(*) from public.shifts), 0::bigint, 'step 1: staff A sees no shift of the draft');
select is((select count(*) from public.schedules where id = pg_temp.gid('sched')), 0::bigint, 'and not the schedule');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.sh(0), pg_temp.id('p_s3'))), '42501 not allowed', 'and cannot offer a shift of it');

-- ===========================================================================
-- Step 2: the manager publishes
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select public.publish_schedule(pg_temp.gid('sched'));
select pg_temp.act_as('postgres');
select is(pg_temp.step(), array['schedule.published']::text[], 'step 2 (publish): exactly one schedule.published (no shift.opened per open shift)');
select is((select (payload ->> 'open_shift_count')::int from public.outbox_events where type = 'schedule.published'), 2, 'step 2: it says two shifts are open');
select is((select status from public.schedules where id = pg_temp.gid('sched')), 'published', 'step 2: the week is published');
select pg_temp.act_as('u_s2');
select is((select count(*) from public.shifts), 6::bigint, 'step 2: staff A now sees the six shifts of the week');
select pg_temp.act_as('u_orgadmin_b');
select is((select count(*) from public.shifts), 0::bigint, 'and an admin of the other organization sees none');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- Step 3: A offers Monday's shift to B; B accepts; the manager approves
-- ===========================================================================
select pg_temp.act_as('u_s2');
insert into ids select 'swap', public.request_shift_swap(pg_temp.sh(0), pg_temp.id('p_s3'));
select pg_temp.act_as('postgres');
select is(pg_temp.step(), array['shift_swap.requested']::text[], 'step 3a (A offers): exactly one shift_swap.requested');
select is(pg_temp.holder(0), 'p_s2', 'step 3a: the shift is still A''s');
select pg_temp.act_as('u_s3');
select is(pg_temp.f(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('swap'))), 'accepted', 'step 3b (B accepts): the swap waits for a manager (auto-approve is off)');
select pg_temp.act_as('postgres');
select is(pg_temp.step(), array['shift_swap.accepted']::text[], 'step 3b: exactly one shift_swap.accepted');
select is(pg_temp.holder(0), 'p_s2', 'step 3b: the shift is still A''s');
select pg_temp.act_as('u_manager_a1');
select public.decide_shift_swap(pg_temp.gid('swap'), true);
select pg_temp.act_as('postgres');
select is(pg_temp.step(), array['shift.assigned', 'shift.unassigned', 'shift_swap.approved']::text[], 'step 3c (manager approves): shift_swap.approved, one shift.assigned (B) and one shift.unassigned (A)');
select is(pg_temp.holder(0), 'p_s3', 'step 3c: Monday''s shift is B''s');
select is((select status from public.shift_swaps where id = pg_temp.gid('swap')), 'approved', 'step 3c: the swap is approved');

-- ===========================================================================
-- Step 4: C drops Wednesday's shift; the manager approves; it opens
-- ===========================================================================
select pg_temp.act_as('u_s4');
insert into ids select 'drop', public.request_shift_drop(pg_temp.sh(2));
select pg_temp.act_as('postgres');
select is(pg_temp.step(), array['shift_swap.requested']::text[], 'step 4a (C drops): exactly one shift_swap.requested');
select is(pg_temp.holder(2), 'p_s4', 'step 4a: the shift is still C''s until a manager decides');
select pg_temp.act_as('u_manager_a1');
select public.decide_shift_swap(pg_temp.gid('drop'), true);
select pg_temp.act_as('postgres');
select is(pg_temp.step(), array['shift.opened', 'shift.unassigned', 'shift_swap.approved']::text[], 'step 4b (manager approves): shift_swap.approved, one shift.unassigned (C) and one shift.opened');
select is(pg_temp.holder(2), 'open', 'step 4b: Wednesday''s shift is open');

-- ===========================================================================
-- Step 5: the uncovered sweep announces the open shifts exactly once
-- ===========================================================================
select pg_temp.act_as('service_role');
select is(public.emit_uncovered_shift_events(interval '14 days', 100), 3, 'step 5: the sweep announces the three open shifts (Wednesday, Thursday, Saturday)');
select pg_temp.act_as('postgres');
select is(pg_temp.step(), array['shift.uncovered', 'shift.uncovered', 'shift.uncovered']::text[], 'step 5: exactly three shift.uncovered');
select is((select count(distinct entity_id) from public.outbox_events where type = 'shift.uncovered'), 3::bigint, 'one per shift');
select pg_temp.act_as('service_role');
select is(public.emit_uncovered_shift_events(interval '14 days', 100), 0, 'step 5: a second sweep announces nothing');
select pg_temp.act_as('postgres');
select is(pg_temp.step(), '{}'::text[], 'and writes nothing');

-- ===========================================================================
-- Step 6: D claims Thursday's shift; the manager approves
-- ===========================================================================
select pg_temp.act_as('u_s5');
select is((select count(*) from public.my_claimable_shifts(pg_temp.id('org_a')) where shift_id = pg_temp.sh(3)), 1::bigint, 'step 6: D is offered the open Thursday shift');
insert into ids select 'claim', public.request_shift_claim(pg_temp.sh(3));
select pg_temp.act_as('postgres');
select is(pg_temp.step(), array['shift_claim.requested']::text[], 'step 6a (D claims): exactly one shift_claim.requested');
select is(pg_temp.holder(3), 'open', 'step 6a: the shift is still open (first-come is off)');
select pg_temp.act_as('u_manager_a1');
select public.decide_shift_claim(pg_temp.gid('claim'), true);
select pg_temp.act_as('postgres');
select is(pg_temp.step(), array['shift.assigned', 'shift_claim.approved']::text[], 'step 6b (manager approves): shift_claim.approved and one shift.assigned (D)');
select is(pg_temp.holder(3), 'p_s5', 'step 6b: Thursday''s shift is D''s');

-- ===========================================================================
-- Final state
-- ===========================================================================
select is(array[pg_temp.holder(0), pg_temp.holder(1), pg_temp.holder(2), pg_temp.holder(3), pg_temp.holder(4), pg_temp.holder(5, '10:00')],
  array['p_s3', 'p_s3', 'open', 'p_s5', 'p_s6', 'open'], 'final: Monday B (swap), Tuesday B, Wednesday open (C dropped), Thursday D (claim), Friday s6, Saturday open');
select is((select count(*) from public.shifts where schedule_id = pg_temp.gid('sched')), 6::bigint, 'final: still six shifts (nothing was created or lost along the way)');
select is((select count(*) from public.shifts where override_kinds is not null), 0::bigint, 'final: no override was needed anywhere');
select results_eq($$select type, count(*) from public.outbox_events group by type order by type collate "C"$$,
  $$values ('schedule.published'::text, 1::bigint), ('shift.assigned', 2), ('shift.opened', 1), ('shift.unassigned', 2), ('shift.uncovered', 3),
           ('shift_claim.approved', 1), ('shift_claim.requested', 1), ('shift_swap.accepted', 1), ('shift_swap.approved', 2), ('shift_swap.requested', 2)$$,
  'final: the whole week wrote exactly these events (16), each action once');
select is((select count(*) from public.outbox_events where organization_id <> pg_temp.id('org_a')), 0::bigint, 'final: all of them belong to org A');
select is((select count(*) from public.outbox_events e, jsonb_object_keys(e.payload) k where k in ('note', 'notes', 'reason', 'name', 'title')), 0::bigint, 'final: no free text in any payload');
-- who is told (the worker reads), as the service connection
select pg_temp.act_as('service_role');
select is((select string_agg(pg_temp.pn(person_id) || ':' || reason, ',' order by pg_temp.pn(person_id) collate "C") from public.worker_shift_event_recipients((select id from public.outbox_events where type = 'schedule.published'))),
  'p_s3:schedule_published,p_s5:schedule_published,p_s6:schedule_published', 'final: schedule.published reaches everyone who holds a shift in the week now (B, D, s6)');
select is((select string_agg(pg_temp.pn(person_id) || ':' || reason, ',' order by pg_temp.pn(person_id) collate "C") from public.worker_shift_event_recipients((select id from public.outbox_events where type = 'shift_claim.approved'))), 'p_s5:claim_approved', 'final: the claim approval reaches D');
select is((select string_agg(pg_temp.pn(person_id) || ':' || reason, ',' order by pg_temp.pn(person_id) collate "C") from public.worker_shift_event_recipients((select id from public.outbox_events where type = 'shift_swap.approved' and entity_id = pg_temp.gid('swap')))), 'p_s2:swap_approved,p_s3:swap_approved', 'final: the swap approval reaches A and B');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- Running each service function again changes nothing
-- ===========================================================================
create temp table snap (s text);
grant all on snap to public;
insert into snap select pg_temp.snapshot();
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.fd(format('select public.publish_schedule(%L)', pg_temp.gid('sched'))), '22023 this schedule is already published', 'again: publish_schedule is refused');
select is(public.create_schedule(pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.wk()), pg_temp.gid('sched'), 'again: create_schedule returns the same schedule');
select is(pg_temp.fd(format('select count(*) from public.apply_shift_template(%L, %L, 0)', pg_temp.gid('sched'), pg_temp.gid('tpl'))), '22023 a template can only be added to a draft schedule', 'again: apply_shift_template is refused on a published week');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('swap'))), '22023 this request is not waiting for a decision', 'again: decide_shift_swap (swap) is refused');
select is(pg_temp.fd(format('select public.decide_shift_swap(%L, true)', pg_temp.gid('drop'))), '22023 this request is not waiting for a decision', 'again: decide_shift_swap (drop) is refused');
select is(pg_temp.fd(format('select public.decide_shift_claim(%L, true)', pg_temp.gid('claim'))), '22023 this request is not waiting for a decision', 'again: decide_shift_claim is refused');
select is(pg_temp.fd(format('select public.assign_shift(%L, %L)', pg_temp.sh(3), pg_temp.id('p_s5'))), '22023 nothing to change', 'again: assign_shift to the current holder is refused');
select pg_temp.act_as('u_s2');
select is(pg_temp.fd(format('select public.request_shift_swap(%L, %L)', pg_temp.sh(0), pg_temp.id('p_s3'))), '42501 not allowed', 'again: A no longer holds Monday''s shift, so cannot offer it');
select pg_temp.act_as('u_s3');
select is(pg_temp.fd(format('select public.respond_shift_swap(%L, true)', pg_temp.gid('swap'))), '22023 this swap is no longer open', 'again: respond_shift_swap is refused');
select is(pg_temp.fd(format('select public.cancel_shift_swap(%L)', pg_temp.gid('swap'))), '22023 this request is already closed', 'again: cancel_shift_swap is refused');
select pg_temp.act_as('u_s4');
select is(pg_temp.fd(format('select public.request_shift_drop(%L)', pg_temp.sh(2))), '42501 not allowed', 'again: C no longer holds Wednesday''s shift, so cannot drop it');
select pg_temp.act_as('u_s5');
select is(pg_temp.fd(format('select public.request_shift_claim(%L)', pg_temp.sh(3))), '23514 this shift is no longer open [stale]', 'again: request_shift_claim on the filled shift is refused');
select is(pg_temp.fd(format('select public.cancel_shift_claim(%L)', pg_temp.gid('claim'))), '22023 this request is already closed', 'again: cancel_shift_claim is refused');
select pg_temp.act_as('service_role');
select is(public.emit_uncovered_shift_events(interval '14 days', 100), 0, 'again: the sweep announces nothing');
select pg_temp.act_as('postgres');
select is(pg_temp.step(), '{}'::text[], 'again: not one event was written');
select is(pg_temp.snapshot(), (select s from snap), 'again: shifts, schedules, swaps, claims, events and every assignment are exactly as before');

select * from finish();
rollback;
