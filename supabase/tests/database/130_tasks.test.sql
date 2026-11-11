-- Phase 2 / tasks and workflows: who sees which task (own, job title, unassigned, other location, other org, manager,
-- platform admin), every RPC allowed or refused per role and location, no direct writes for anyone (including a forged
-- source_event_id), the state machine, one task_events row and one outbox event per change, who may be assigned, and
-- uniform 42501 refusals that never "pass on NULL" (an invisible task cannot be started, completed, commented or reassigned).
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(201);

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

create function pg_temp.try_msg(p_sql text) returns text language plpgsql as $$
begin
  execute p_sql;
  return 'ok';
exception when others then return sqlstate || ' ' || sqlerrm;
end $$;
create function pg_temp.val(p_expr text) returns text language plpgsql as $$
declare v text;
begin
  execute 'select (' || p_expr || ')::text' into v;
  return coalesce(v, 'null');
exception when others then return 'ERR ' || sqlstate;
end $$;
-- a fingerprint of everything an RPC may touch (owner view)
create function pg_temp.fp() returns text language sql security definer set search_path = '' as $$
  select md5((select coalesce(string_agg(to_jsonb(t)::text, ',' order by t.id), '') from public.tasks t) || '|' ||
             (select count(*)::text from public.task_events) || '|' || (select count(*)::text from public.outbox_events))
$$;
grant execute on function pg_temp.try_msg(text), pg_temp.val(text), pg_temp.fp() to public;

-- Extra people: a second staff member at A1 with no job title and no special rights.
insert into auth.users (id, email) values (pg_temp.id('u_staff_a1b'), 'staff-a1b@test.invalid');
insert into public.people (id, organization_id, first_name, last_name) values (pg_temp.id('p_staff_a1b'), pg_temp.id('org_a'), 'Sid', 'StaffA1b');
insert into public.accounts (id, organization_id, person_id, user_id) values (pg_temp.id('acct_staff_a1b'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.id('u_staff_a1b'));
insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'));
insert into public.job_titles (id, organization_id, name) values (pg_temp.id('jt_x'), pg_temp.id('org_a'), 'Zamboni driver');
-- an archived person with a login and assignment, and a person whose only role is archived
insert into public.people (id, organization_id, first_name, last_name, archived_at) values (pg_temp.id('p_archived_a'), pg_temp.id('org_a'), 'Ari', 'Archived', now());

-- Tasks. The title is the name used in the tests.
insert into public.tasks (id, organization_id, location_id, title, status, assigned_person_id, assigned_job_title_id, completed_at, cancelled_at) values
  (pg_temp.id('t_own'),        pg_temp.id('org_a'), pg_temp.id('loc_a1'), 't_own',        'open',        pg_temp.id('p_staff_a1'),   null, null, null),
  (pg_temp.id('t_other'),      pg_temp.id('org_a'), pg_temp.id('loc_a1'), 't_other',      'open',        pg_temp.id('p_manager_a1'), null, null, null),
  (pg_temp.id('t_title'),      pg_temp.id('org_a'), pg_temp.id('loc_a1'), 't_title',      'open',        null, pg_temp.id('jt_a'), null, null),
  (pg_temp.id('t_title_x'),    pg_temp.id('org_a'), pg_temp.id('loc_a1'), 't_title_x',    'open',        null, pg_temp.id('jt_x'), null, null),
  (pg_temp.id('t_unassigned'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 't_unassigned', 'open',        null, null, null, null),
  (pg_temp.id('t_both'),       pg_temp.id('org_a'), pg_temp.id('loc_a1'), 't_both',       'open',        pg_temp.id('p_manager_a1'), pg_temp.id('jt_a'), null, null),
  (pg_temp.id('t_prog'),       pg_temp.id('org_a'), pg_temp.id('loc_a1'), 't_prog',       'in_progress', pg_temp.id('p_staff_a1'),   null, null, null),
  (pg_temp.id('t_done'),       pg_temp.id('org_a'), pg_temp.id('loc_a1'), 't_done',       'done',        pg_temp.id('p_staff_a1'),   null, now(), null),
  (pg_temp.id('t_canc'),       pg_temp.id('org_a'), pg_temp.id('loc_a1'), 't_canc',       'cancelled',   pg_temp.id('p_staff_a1'),   null, null, now()),
  (pg_temp.id('t_a2'),         pg_temp.id('org_a'), pg_temp.id('loc_a2'), 't_a2',         'open',        pg_temp.id('p_staff_a2'),   null, null, null),
  (pg_temp.id('t_a2_un'),      pg_temp.id('org_a'), pg_temp.id('loc_a2'), 't_a2_un',      'open',        null, null, null, null),
  (pg_temp.id('t_b'),          pg_temp.id('org_b'), pg_temp.id('loc_b1'), 't_b',          'open',        null, null, null, null);

-- ===========================================================================
-- 1. Visibility matrix
-- ===========================================================================
create temp table seen (who text, aal text, titles text);
grant all on seen to public;
create function pg_temp.look(p_who text, p_aal text default 'aal2') returns void language plpgsql as $$
begin
  perform pg_temp.act_as(p_who, p_aal);
  insert into seen select p_who || '/' || p_aal, p_aal, coalesce((select string_agg(title, ',' order by title) from public.tasks), '');
  perform pg_temp.act_as('postgres');
end $$;
grant execute on function pg_temp.look(text, text) to public;
select pg_temp.look('u_staff_a1'); select pg_temp.look('u_staff_a1b'); select pg_temp.look('u_manager_a1'); select pg_temp.look('u_locadmin_a1');
select pg_temp.look('u_staff_a2'); select pg_temp.look('u_orgadmin_a'); select pg_temp.look('u_platform'); select pg_temp.look('u_orgadmin_b');
select pg_temp.look('u_noaccount'); select pg_temp.look('u_disabled_a'); select pg_temp.look('u_staff_b1'); select pg_temp.look('u_orgadmin_a', 'aal1'); select pg_temp.look('u_platform', 'aal1');
select pg_temp.look('u_locadmin_a1', 'aal1');
select is((select titles from seen where who = 'u_staff_a1/aal2'), 't_canc,t_done,t_own,t_prog,t_title,t_unassigned',
  'staff A1 sees: their own tasks (any status), the job-title task for a title they hold, and unassigned tasks at A1; not another person''s, not a title they lack, not t_both (person + title: the person only)');
select is((select titles from seen where who = 'u_staff_a1b/aal2'), 't_unassigned', 'staff A1b (no job title) sees only the unassigned task');
select is((select titles from seen where who = 'u_manager_a1/aal2'), 't_both,t_canc,t_done,t_other,t_own,t_prog,t_title,t_title_x,t_unassigned', 'manager A1 (tasks admin at A1) sees every task at A1 and none at A2 or in org B');
select is((select titles from seen where who = 'u_locadmin_a1/aal2'), 't_both,t_canc,t_done,t_other,t_own,t_prog,t_title,t_title_x,t_unassigned', 'location admin A1 sees every task at A1');
select is((select titles from seen where who = 'u_staff_a2/aal2'), 't_a2,t_a2_un', 'staff A2 sees A2''s own and unassigned tasks, nothing at A1');
select is((select titles from seen where who = 'u_orgadmin_a/aal2'), 't_a2,t_a2_un,t_both,t_canc,t_done,t_other,t_own,t_prog,t_title,t_title_x,t_unassigned', 'org admin A sees every task of org A');
select is((select titles from seen where who = 'u_platform/aal2'), 't_a2,t_a2_un,t_b,t_both,t_canc,t_done,t_other,t_own,t_prog,t_title,t_title_x,t_unassigned', 'platform admin (aal2) sees every task of every organization');
select is((select titles from seen where who = 'u_orgadmin_b/aal2'), 't_b', 'org admin B sees only org B''s task');
select is((select titles from seen where who = 'u_staff_b1/aal2'), 't_b', 'staff B1 sees the unassigned task at B1');
select is((select titles from seen where who = 'u_noaccount/aal2'), '', 'a signed-in user with no account sees no tasks');
select is((select titles from seen where who = 'u_disabled_a/aal2'), '', 'a disabled account sees no tasks');
select is((select titles from seen where who = 'u_orgadmin_a/aal1'), '', 'org admin A at aal1 sees no tasks');
select is((select titles from seen where who = 'u_locadmin_a1/aal1'), '', 'location admin A1 at aal1 sees no tasks');
select is((select titles from seen where who = 'u_platform/aal1'), '', 'platform admin at aal1 sees no tasks');
select pg_temp.act_as('anon');
select is(pg_temp.try('select count(*) from public.tasks'), '42501', 'anon cannot read tasks');
select is(pg_temp.try('select count(*) from public.task_events'), '42501', 'anon cannot read task_events');
select pg_temp.act_as('postgres');
select cmp_ok(length((select titles from seen where who = 'u_staff_a1/aal2')), '>', 0, 'the visibility strings above are not empty strings by accident (staff A1 really sees tasks)');

-- task_events follow the task: the history of a task is visible exactly when the task is
insert into public.task_events (id, organization_id, location_id, task_id, kind) values
  (pg_temp.id('te_own'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('t_own'), 'created'),
  (pg_temp.id('te_other'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('t_other'), 'created'),
  (pg_temp.id('te_a2'), pg_temp.id('org_a'), pg_temp.id('loc_a2'), pg_temp.id('t_a2'), 'created'),
  (pg_temp.id('te_b'), pg_temp.id('org_b'), pg_temp.id('loc_b1'), pg_temp.id('t_b'), 'created');
select pg_temp.act_as('u_staff_a1');
select is((select array_agg(id) from public.task_events), array[pg_temp.id('te_own')], 'staff A1 sees the history of their own task only');
select pg_temp.act_as('u_manager_a1');
select is((select array_agg(id order by id) from public.task_events), (select array_agg(x order by x) from unnest(array[pg_temp.id('te_own'), pg_temp.id('te_other')]) x), 'manager A1 sees the history of A1 tasks only');
select pg_temp.act_as('u_staff_a2');
select is((select array_agg(id) from public.task_events), array[pg_temp.id('te_a2')], 'staff A2 sees the history of A2''s own task only');
select pg_temp.act_as('u_orgadmin_b');
select is((select array_agg(id) from public.task_events), array[pg_temp.id('te_b')], 'org admin B sees only org B history');
select pg_temp.act_as('postgres');

-- A job-title change reveals only the matching task and nothing else; the title must be held at the task's location.
select pg_temp.look('u_staff_a1b');
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id)
values (pg_temp.id('pjt_1b'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.id('jt_x'), pg_temp.id('loc_a2'));
select pg_temp.look('u_staff_a1b', 'aal1');   -- aal1 changes nothing for a plain staff member
select is((select titles from seen where who = 'u_staff_a1b/aal1' and aal = 'aal1' order by titles limit 1), 't_unassigned', 'staff A1b given the Zamboni title at A2 only: still sees just the unassigned A1 task (a title held elsewhere reveals nothing)');
select pg_temp.act_as('postgres');
update public.person_job_titles set job_title_id = pg_temp.id('jt_a') where id = pg_temp.id('pjt_1b');
select pg_temp.act_as('u_staff_a1b'); create temp table s2 as select title from public.tasks; select pg_temp.act_as('postgres');
select is((select string_agg(title, ',' order by title) from s2), 't_unassigned', 'a Lifeguard title held at A2 only does not reveal the A1 Lifeguard task either');
drop table s2;
delete from public.person_job_titles where id = pg_temp.id('pjt_1b');
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id)
values (pg_temp.id('pjt_1b'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.id('jt_x'), pg_temp.id('loc_a1'));
select pg_temp.look('u_staff_a1b', 'aal2');
select is((select titles from seen where who = 'u_staff_a1b/aal2' order by length(titles) desc limit 1), 't_title_x,t_unassigned', 'staff A1b given the Zamboni title at A1: now also sees exactly the Zamboni task and nothing else changed');
select pg_temp.act_as('postgres');
delete from public.person_job_titles where id = pg_temp.id('pjt_1b');
create temp table s3 (t text); grant all on s3 to public;
select pg_temp.act_as('u_staff_a1b'); insert into s3 select title from public.tasks; select pg_temp.act_as('postgres');
select is((select string_agg(t, ',' order by t) from s3), 't_unassigned', 'and when the title is removed the Zamboni task is hidden again');
-- a title held everywhere (no location) reaches every location of the organization
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id)
values (pg_temp.id('pjt_1b'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.id('jt_x'), null);
truncate s3;
select pg_temp.act_as('u_staff_a1b'); insert into s3 select title from public.tasks; select pg_temp.act_as('postgres');
select is((select string_agg(t, ',' order by t) from s3), 't_title_x,t_unassigned', 'a title held everywhere reveals the matching task at A1, and only that');
delete from public.person_job_titles where id = pg_temp.id('pjt_1b');
-- a title never grants reach: someone with the title but no membership at the location sees nothing there
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id)
values (pg_temp.id('pjt_a2'), pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), pg_temp.id('jt_x'), null);
truncate s3;
select pg_temp.act_as('u_staff_a2'); insert into s3 select title from public.tasks; select pg_temp.act_as('postgres');
select is((select string_agg(t, ',' order by t) from s3), 't_a2,t_a2_un', 'staff A2 holding the Zamboni title everywhere still sees nothing at A1 (titles only narrow what the module already allows)');
delete from public.person_job_titles where id = pg_temp.id('pjt_a2');
-- view-only level: sees the same set, cannot work on it
insert into public.user_permissions (id, organization_id, person_id, location_id, module_key, level) values (pg_temp.id('up_view'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), null, 'tasks', 'view');
select pg_temp.act_as('u_staff_a1b');
select is(pg_temp.try_msg($$select public.start_task(pg_temp.id('t_unassigned'))$$), '42501 not allowed', 'view-only: cannot start a task they can see');
select is(pg_temp.try_msg($$select public.add_task_comment(pg_temp.id('t_unassigned'), 'hi')$$), '42501 not allowed', 'view-only: cannot comment on a task they can see');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x')$$), '42501 not allowed', 'view-only: cannot create a task');
select is((select count(*) from public.tasks), 1::bigint, 'view-only: still sees the unassigned task');
select pg_temp.act_as('postgres');
update public.user_permissions set level = 'none' where id = pg_temp.id('up_view');
select pg_temp.act_as('u_staff_a1b');
select is((select count(*) from public.tasks), 0::bigint, 'tasks = none: sees nothing');
select pg_temp.act_as('postgres');
delete from public.user_permissions where id = pg_temp.id('up_view');
insert into public.user_permissions (id, organization_id, person_id, location_id, module_key, level) values (pg_temp.id('up_view'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), null, 'tasks', 'edit');
select pg_temp.act_as('u_staff_a1b');
select is(pg_temp.try_msg($$select public.start_task(pg_temp.id('t_unassigned'))$$), 'ok', 'twin, edit level: starts the unassigned task');
select pg_temp.act_as('postgres');
delete from public.user_permissions where id = pg_temp.id('up_view');
update public.tasks set status = 'open', assigned_person_id = null where id = pg_temp.id('t_unassigned');

-- ===========================================================================
-- 2. No direct writes, for any role
-- ===========================================================================
create temp table dw (who text, tbl text, op text, res text);
grant all on dw to public;
do $$
declare w text; t text; r record;
begin
  foreach w in array array['u_staff_a1', 'u_manager_a1', 'u_locadmin_a1', 'u_orgadmin_a', 'u_platform', 'u_orgadmin_b', 'anon', 'service_role'] loop
    perform pg_temp.act_as(w);
    insert into dw values
      (w, 'tasks', 'insert', pg_temp.try($q$insert into public.tasks (organization_id, location_id, title) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'direct')$q$)),
      (w, 'tasks', 'insert_forged_source', pg_temp.try($q$insert into public.tasks (organization_id, location_id, title, source_event_id, source_rule_id, task_template_id)
          values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'forged', gen_random_uuid(), gen_random_uuid(), gen_random_uuid())$q$)),
      (w, 'tasks', 'update_status', pg_temp.try($q$update public.tasks set status = 'done', completed_at = now() where id = pg_temp.id('t_own')$q$)),
      (w, 'tasks', 'update_title', pg_temp.try($q$update public.tasks set title = 'renamed' where id = pg_temp.id('t_own')$q$)),
      (w, 'tasks', 'update_assignee', pg_temp.try($q$update public.tasks set assigned_person_id = pg_temp.id('p_staff_a1b') where id = pg_temp.id('t_own')$q$)),
      (w, 'tasks', 'update_source_event', pg_temp.try($q$update public.tasks set source_event_id = gen_random_uuid() where id = pg_temp.id('t_own')$q$)),
      (w, 'tasks', 'update_overdue_marker', pg_temp.try($q$update public.tasks set overdue_emitted_for = now() where id = pg_temp.id('t_own')$q$)),
      (w, 'tasks', 'delete', pg_temp.try($q$delete from public.tasks where id = pg_temp.id('t_own')$q$)),
      (w, 'tasks', 'truncate', pg_temp.try('truncate public.tasks cascade')),
      (w, 'task_events', 'insert', pg_temp.try($q$insert into public.task_events (organization_id, location_id, task_id, kind) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('t_own'), 'commented')$q$)),
      (w, 'task_events', 'insert_forged_source', pg_temp.try($q$insert into public.task_events (organization_id, location_id, task_id, kind, source_event_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('t_own'), 'created', gen_random_uuid())$q$)),
      (w, 'task_events', 'update', pg_temp.try($q$update public.task_events set body = 'edited' where id = pg_temp.id('te_own')$q$)),
      (w, 'task_events', 'delete', pg_temp.try($q$delete from public.task_events where id = pg_temp.id('te_own')$q$)),
      (w, 'task_events', 'truncate', pg_temp.try('truncate public.task_events cascade'));
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select string_agg(distinct res, ',') from dw where who = w.who), '42501', w.who || ': no direct insert, update, delete or truncate on tasks or task_events (14 attempts, all 42501)')
  from (values ('u_staff_a1'), ('u_manager_a1'), ('u_locadmin_a1'), ('u_orgadmin_a'), ('u_platform'), ('u_orgadmin_b'), ('anon'), ('service_role')) w (who);
select is((select count(*) from dw), 8 * 14::bigint, 'all 8 x 14 attempts ran');
select is((select count(*) from public.tasks), 12::bigint, 'and the tasks table still has its 12 rows');
select is((select count(*) from public.tasks where title in ('direct', 'forged', 'renamed')), 0::bigint, 'with none of the attempted content in it');
select is((select count(*) from public.task_events), 5::bigint, 'and task_events still has its 5 rows (the 4 above plus the "started" row of the edit-level twin)');
-- the owner cannot rewrite history either (append-only trigger)
select is(pg_temp.try($$update public.task_events set body = 'rewritten' where id = pg_temp.id('te_own')$$), '42501', 'task_events is append-only: even the owner cannot update a row');
select is(pg_temp.try($$update public.task_events set kind = 'completed' where id = pg_temp.id('te_own')$$), '42501', 'append-only: the kind cannot be changed either');
select ok(not has_table_privilege('authenticated', 'public.tasks', 'insert,update,delete,truncate') and not has_any_column_privilege('authenticated', 'public.tasks', 'insert,update'), 'authenticated has no write privilege of any kind on tasks (table or column)');
select ok(not has_table_privilege('authenticated', 'public.task_events', 'insert,update,delete,truncate') and not has_any_column_privilege('authenticated', 'public.task_events', 'insert,update'), 'authenticated has no write privilege on task_events');
select ok(not has_table_privilege('service_role', 'public.tasks', 'insert,update,delete,truncate') and not has_table_privilege('service_role', 'public.task_events', 'insert,update,delete,truncate'), 'service_role has no write privilege on tasks or task_events either (only the service functions write them)');

-- ===========================================================================
-- 3. RPCs per role and location, with allowed twins. Every refusal is the uniform 42501.
-- ===========================================================================
create temp table ev0 as select (select count(*) from public.task_events) as te, (select count(*) from public.outbox_events) as ob;
grant all on ev0 to public;
-- create_task
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff for me', null, null, 'normal', null, pg_temp.id('p_staff_a1'))$$), 'ok', 'create_task: staff A1 creates a task for themselves at A1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff for nobody')$$), 'ok', 'create_task: staff A1 creates an unassigned task at A1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff for other', null, null, 'normal', null, pg_temp.id('p_manager_a1'))$$), '42501 only a manager can assign tasks to others', 'create_task: staff cannot assign to someone else');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff for title', null, null, 'normal', null, null, pg_temp.id('jt_a'))$$), '42501 only a manager can assign tasks to others', 'create_task: staff cannot route to a job title');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'wrong location')$$), '42501 not allowed', 'create_task: staff A1 cannot create at A2');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'wrong org')$$), '42501 not allowed', 'create_task: staff A1 cannot create in org B');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_b1'), 'mixed org and location')$$), '42501 not allowed', 'create_task: an org A / location B1 mix is refused the same way');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), null, 'no location')$$), '42501 not allowed', 'create_task: no location is refused');
select is(pg_temp.try_msg($$select public.create_task(null, pg_temp.id('loc_a1'), 'no org')$$), '42501 not allowed', 'create_task: no organization is refused');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'mgr to staff', 'Do it', now() + interval '1 day', 'urgent', pg_temp.id('space_a1'), pg_temp.id('p_staff_a1'))$$), 'ok', 'create_task: manager A1 assigns to staff A1, with a due time, priority and space');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'mgr to title', null, null, 'low', null, null, pg_temp.id('jt_a'))$$), 'ok', 'create_task: manager A1 routes to a job title');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'mgr at A2')$$), '42501 not allowed', 'create_task: manager A1 cannot create at A2');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'a2 own')$$), 'ok', 'create_task: twin, staff A2 creates at A2');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'a2 at a1')$$), '42501 not allowed', 'create_task: staff A2 cannot create at A1');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'locadmin', null, null, 'normal', null, pg_temp.id('p_manager_a1'))$$), 'ok', 'create_task: location admin A1 assigns to a manager at A1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'locadmin at a2')$$), '42501 not allowed', 'create_task: location admin A1 cannot create at A2');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'orgadmin a1')$$), 'ok', 'create_task: org admin A creates at A1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'orgadmin a2', null, null, 'normal', null, pg_temp.id('p_staff_a2'))$$), 'ok', 'create_task: org admin A creates at A2 for staff A2');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'orgadmin in b')$$), '42501 not allowed', 'create_task: org admin A cannot create in org B');
select pg_temp.act_as('u_platform');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'platform in b')$$), 'ok', 'create_task: a platform admin (aal2) creates in any organization');
select pg_temp.act_as('u_noaccount');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'stranger')$$), '42501 not allowed', 'create_task: a user with no account is refused');
select pg_temp.act_as('u_disabled_a');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'disabled')$$), '42501 not allowed', 'create_task: a disabled account is refused');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'org b admin in a')$$), '42501 not allowed', 'create_task: org admin B cannot create in org A');
select pg_temp.act_as('anon');
select is(pg_temp.try('select public.create_task(pg_temp.id(''org_a''), pg_temp.id(''loc_a1''), ''anon'')'), '42501', 'create_task: anon cannot call it');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'server key')$$), '42501 not signed in', 'create_task: the server key with no user is refused (it has the service functions instead)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.tasks where title in ('wrong location', 'wrong org', 'mixed org and location', 'no location', 'no org', 'mgr at A2', 'a2 at a1', 'locadmin at a2', 'orgadmin in b', 'stranger', 'disabled', 'org b admin in a', 'anon', 'server key', 'staff for other', 'staff for title')), 0::bigint,
  'none of the refused create_task calls left a task behind');
select is((select count(*) from public.tasks where title in ('staff for me', 'staff for nobody', 'mgr to staff', 'mgr to title', 'a2 own', 'locadmin', 'orgadmin a1', 'orgadmin a2', 'platform in b')), 9::bigint, 'and the 9 allowed ones did');
-- each create wrote exactly one history row and one event
select is((select count(*) from public.task_events where kind = 'created' and task_id in (select id from public.tasks where title in ('staff for me', 'staff for nobody', 'mgr to staff', 'mgr to title', 'a2 own', 'locadmin', 'orgadmin a1', 'orgadmin a2', 'platform in b'))), 9::bigint, 'create_task writes exactly one created row in task_events per task');
select is((select count(*) from public.outbox_events where type = 'task.created' and entity_id in (select id from public.tasks where title in ('staff for me', 'staff for nobody', 'mgr to staff', 'mgr to title', 'a2 own', 'locadmin', 'orgadmin a1', 'orgadmin a2', 'platform in b'))), 9::bigint, 'and exactly one task.created event per task');
select is((select count(*) from public.task_events) - (select te from ev0), 9::bigint, 'no other history rows appeared');
select is((select count(*) from public.outbox_events) - (select ob from ev0), 9::bigint, 'no other outbox events appeared');
select results_eq($$select t.status, t.priority, t.due_at is not null, t.assigned_person_id, t.created_by_person_id, t.space_id, t.instructions, t.location_id, t.organization_id from public.tasks t where t.title = 'mgr to staff'$$,
  $$select 'open'::text, 'urgent'::text, true, pg_temp.id('p_staff_a1'), pg_temp.id('p_manager_a1'), pg_temp.id('space_a1'), 'Do it'::text, pg_temp.id('loc_a1'), pg_temp.id('org_a')$$, 'a created task carries what was asked, is open, and records its creator');
select results_eq($$select e.kind, e.actor_person_id, e.from_status, e.to_status, e.assigned_person_id, e.source_event_id from public.task_events e join public.tasks t on t.id = e.task_id where t.title = 'mgr to staff'$$,
  $$select 'created'::text, pg_temp.id('p_manager_a1'), null::text, 'open'::text, pg_temp.id('p_staff_a1'), null::uuid$$, 'its created history row: kind, actor, to_status, the assignee');
select is((select created_by_person_id from public.tasks where title = 'platform in b'), null, 'a task created by a platform admin has no creator person (they are not a member)');
select results_eq($$select e.type, e.entity_table, e.organization_id, e.location_id, e.payload ->> 'status', e.payload ->> 'actor_person_id', e.correlation_id = e.id from public.outbox_events e where e.type = 'task.created' and e.entity_id = (select id from public.tasks where title = 'mgr to staff')$$,
  $$select 'task.created'::text, 'tasks'::text, pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'open'::text, pg_temp.id('p_manager_a1')::text, true$$, 'its event: type, entity, scope, status, actor, own correlation id');
select is((select count(*) from public.outbox_events e where e.type like 'task.%' and (e.payload ? 'title' or e.payload ? 'instructions' or e.payload ? 'body' or e.payload ? 'note')), 0::bigint, 'task events never carry the title, instructions or comment text (ids and statuses only)');

-- validation (every error is a clean code, nothing is created)
select pg_temp.act_as('u_manager_a1');
create temp table fp1 as select pg_temp.fp() as f;
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', null, null, 'bogus')$$), '22023 invalid priority', 'create_task: a bad priority is 22023');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', null, null, null)$$), '22023 invalid priority', 'create_task: a null priority is 22023');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', null, null, 'normal', pg_temp.id('space_a2'))$$), '22023 unknown space at this location', 'create_task: a space at another location is 22023');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', null, null, 'normal', pg_temp.id('space_b1'))$$), '22023 unknown space at this location', 'create_task: another organization''s space is the same 22023');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', null, null, 'normal', null, null, gen_random_uuid())$$), '22023 unknown job title', 'create_task: an unknown job title is 22023');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', null, null, 'normal', null, null, pg_temp.id('jt_b'))$$), '22023 unknown job title', 'create_task: another organization''s job title is the same 22023');
select ok(pg_temp.try($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), null)$$) in ('23502', '22023'), 'create_task: a null title is rejected');
select ok(pg_temp.try($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), '   ')$$) in ('23514', '22023'), 'create_task: a blank title is rejected');
select ok(pg_temp.try($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), repeat('x', 201))$$) in ('23514', '22023'), 'create_task: a 201-character title is rejected');
select ok(pg_temp.try($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', repeat('x', 4001))$$) in ('23514', '22023'), 'create_task: 4001 characters of instructions are rejected');
select is(pg_temp.try($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), repeat('x', 200))$$), 'ok', 'twin: a 200-character title is fine');
select pg_temp.act_as('postgres');

-- assignee must be a member with an active login covering the location (and visible to the caller)
create temp table asg (n int, label text, who text, aal text, call text, expect text);
grant all on asg to public;
insert into asg values
  (1,  'staff A1 (member at A1)',                         'u_manager_a1', 'aal2', 'p_staff_a1',     'ok'),
  (2,  'the manager themselves',                           'u_manager_a1', 'aal2', 'p_manager_a1',   'ok'),
  (3,  'staff A2 (member at A2 only)',                     'u_manager_a1', 'aal2', 'p_staff_a2',     '22023'),
  (4,  'a person with no login at all',                    'u_manager_a1', 'aal2', 'p_unassigned_a', '22023'),
  (5,  'a disabled account',                               'u_manager_a1', 'aal2', 'p_disabled_a',   '22023'),
  (6,  'an archived person',                               'u_manager_a1', 'aal2', 'p_archived_a',   '22023'),
  (7,  'another organization''s person',                   'u_manager_a1', 'aal2', 'p_staff_b1',     '22023'),
  (8,  'the org admin (covers A1 but not visible to a location manager)', 'u_manager_a1', 'aal2', 'p_orgadmin_a', '22023'),
  (9,  'the org admin, assigned by the org admin',         'u_orgadmin_a', 'aal2', 'p_orgadmin_a',   'ok'),
  (10, 'staff A2, assigned by the org admin at A1',        'u_orgadmin_a', 'aal2', 'p_staff_a2',     '22023'),
  (11, 'a person with no login, assigned by the org admin','u_orgadmin_a', 'aal2', 'p_unassigned_a', '22023'),
  (12, 'a disabled account, assigned by a platform admin', 'u_platform',   'aal2', 'p_disabled_a',   '22023'),
  (13, 'staff A1, assigned by a platform admin',           'u_platform',   'aal2', 'p_staff_a1',     'ok');
select is(pg_temp.try_msg(format($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'assignee test %s', null, null, 'normal', null, pg_temp.id(%L))$$, a.n, a.call)) like (case a.expect when 'ok' then 'ok' else a.expect || ' that person cannot be given tasks at this location' end),
  true, 'create_task assignee: ' || a.label || ' -> ' || a.expect)
  from (select * from asg order by n offset 0) a, lateral (select pg_temp.act_as(a.who, a.aal)) s;
select pg_temp.act_as('postgres');
-- a role archived: the member with only that role no longer covers the location
update public.roles set archived_at = now() where id = pg_temp.id('role_custom_a');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', null, null, 'normal', null, pg_temp.id('p_staff_a1'))$$), 'ok', 'sanity: an unrelated archived role changes nothing');
select pg_temp.act_as('postgres');
-- assign_task uses the same rule
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.assign_task(pg_temp.id('t_unassigned'), pg_temp.id('p_staff_a2'), null)$$), '22023 that person cannot be given tasks at this location', 'assign_task: staff A2 cannot be assigned an A1 task');
select is(pg_temp.try_msg($$select public.assign_task(pg_temp.id('t_unassigned'), pg_temp.id('p_disabled_a'), null)$$), '22023 that person cannot be given tasks at this location', 'assign_task: a disabled account cannot');
select is(pg_temp.try_msg($$select public.assign_task(pg_temp.id('t_unassigned'), pg_temp.id('p_unassigned_a'), null)$$), '22023 that person cannot be given tasks at this location', 'assign_task: a person with no login cannot');
select is(pg_temp.try_msg($$select public.assign_task(pg_temp.id('t_unassigned'), pg_temp.id('p_staff_b1'), null)$$), '22023 that person cannot be given tasks at this location', 'assign_task: another organization''s person cannot');
select is(pg_temp.try_msg($$select public.assign_task(pg_temp.id('t_unassigned'), null, gen_random_uuid())$$), '22023 unknown job title', 'assign_task: an unknown job title is 22023');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 4. The state machine and what each RPC writes
-- ===========================================================================
-- A fresh task per run, owned by staff A1 at A1. The sequence is ordered; every step names who acts, what, and the expected result.
insert into public.tasks (id, organization_id, location_id, title, status, assigned_person_id) values
  (pg_temp.id('sm'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'sm', 'open', pg_temp.id('p_staff_a1'));
create temp table steps (n int, who text, expr text, expect text, kind text, to_status text);
grant all on steps to public;
insert into steps values
  (1,  'u_staff_a1',    $$public.complete_task(pg_temp.id('sm'), 'done quickly')$$,                 'ok',   'completed', 'done'),
  (2,  'u_staff_a1',    $$public.start_task(pg_temp.id('sm'))$$,                                     '22023', null, null),
  (3,  'u_staff_a1',    $$public.complete_task(pg_temp.id('sm'))$$,                                  '22023', null, null),
  (4,  'u_staff_a1',    $$public.cancel_task(pg_temp.id('sm'))$$,                                    '42501', null, null),
  (5,  'u_manager_a1',  $$public.cancel_task(pg_temp.id('sm'))$$,                                    '22023', null, null),
  (6,  'u_manager_a1',  $$public.assign_task(pg_temp.id('sm'), pg_temp.id('p_manager_a1'), null)$$,  '22023', null, null),
  (7,  'u_staff_a1',    $$public.reopen_task(pg_temp.id('sm'), 'oops')$$,                            'ok',   'reopened', 'open'),
  (8,  'u_staff_a1',    $$public.reopen_task(pg_temp.id('sm'))$$,                                    '22023', null, null),
  (9,  'u_staff_a1',    $$public.start_task(pg_temp.id('sm'))$$,                                     'ok',   'started', 'in_progress'),
  (10, 'u_staff_a1',    $$public.start_task(pg_temp.id('sm'))$$,                                     '22023', null, null),
  (11, 'u_staff_a1',    $$public.add_task_comment(pg_temp.id('sm'), 'working on it')$$,               'ok',   'commented', 'in_progress'),
  (12, 'u_staff_a1',    $$public.assign_task(pg_temp.id('sm'), pg_temp.id('p_manager_a1'), null)$$,   '42501', null, null),
  (13, 'u_manager_a1',  $$public.assign_task(pg_temp.id('sm'), pg_temp.id('p_manager_a1'), null)$$,   'ok',   'assigned', 'in_progress'),
  (14, 'u_manager_a1',  $$public.assign_task(pg_temp.id('sm'), pg_temp.id('p_manager_a1'), null)$$,   '22023', null, null),
  (15, 'u_staff_a1',    $$public.add_task_comment(pg_temp.id('sm'), 'now not mine')$$,                '42501', null, null),
  (16, 'u_staff_a1',    $$public.complete_task(pg_temp.id('sm'))$$,                                  '42501', null, null),
  (17, 'u_manager_a1',  $$public.assign_task(pg_temp.id('sm'), null, pg_temp.id('jt_a'))$$,            'ok',   'assigned', 'in_progress'),
  (18, 'u_manager_a1',  $$public.assign_task(pg_temp.id('sm'), null, null)$$,                         'ok',   'assigned', 'in_progress'),
  (19, 'u_manager_a1',  $$public.cancel_task(pg_temp.id('sm'), 'duplicate')$$,                        'ok',   'cancelled', 'cancelled'),
  (20, 'u_manager_a1',  $$public.complete_task(pg_temp.id('sm'))$$,                                  '22023', null, null),
  (21, 'u_manager_a1',  $$public.start_task(pg_temp.id('sm'))$$,                                     '22023', null, null),
  (22, 'u_manager_a1',  $$public.cancel_task(pg_temp.id('sm'))$$,                                    '22023', null, null),
  (23, 'u_manager_a1',  $$public.assign_task(pg_temp.id('sm'), pg_temp.id('p_staff_a1'), null)$$,     '22023', null, null),
  (24, 'u_manager_a1',  $$public.add_task_comment(pg_temp.id('sm'), 'closing note')$$,                'ok',   'commented', 'cancelled'),
  (25, 'u_manager_a1',  $$public.reopen_task(pg_temp.id('sm'))$$,                                    'ok',   'reopened', 'open'),
  (26, 'u_manager_a1',  $$public.complete_task(pg_temp.id('sm'))$$,                                  'ok',   'completed', 'done'),
  (27, 'u_manager_a1',  $$public.cancel_task(pg_temp.id('sm'))$$,                                    '22023', null, null),
  (28, 'u_manager_a1',  $$public.reopen_task(pg_temp.id('sm'))$$,                                    'ok',   'reopened', 'open'),
  (29, 'u_manager_a1',  $$public.cancel_task(pg_temp.id('sm'))$$,                                    'ok',   'cancelled', 'cancelled'),
  (30, 'u_staff_a1',    $$public.reopen_task(pg_temp.id('sm'))$$,                                    '42501', null, null);
create temp table step_log (n int, res text, te_delta bigint, ob_delta bigint, kind text, to_status text, ob_type text);
grant all on step_log to public;
do $$
declare s record; te_ids uuid[]; ob_ids uuid[]; r text; k text; ts text; ot text; te_new int; ob_new int;
begin
  perform pg_temp.act_as('postgres');
  te_ids := array(select id from public.task_events); ob_ids := array(select id from public.outbox_events);
  for s in select * from steps order by n loop
    perform pg_temp.act_as(s.who);
    r := pg_temp.try_msg('select ' || s.expr);
    perform pg_temp.act_as('postgres');
    select count(*), max(e.kind), max(e.to_status) into te_new, k, ts from public.task_events e where e.id <> all (te_ids);
    select count(*), max(e.type) into ob_new, ot from public.outbox_events e where e.id <> all (ob_ids);
    insert into step_log values (s.n, r, te_new, ob_new, k, ts, ot);
    te_ids := array(select id from public.task_events); ob_ids := array(select id from public.outbox_events);
  end loop;
end $$;
select is(case when l.res = 'ok' then 'ok' else split_part(l.res, ' ', 1) end, s.expect,
  'step ' || s.n || ': ' || s.who || ' ' || regexp_replace(s.expr, '^public\.([a-z_]+)\(.*$', '\1') || ' -> ' || s.expect)
  from steps s join step_log l using (n) order by s.n;
select is((select count(*) from step_log l join steps s using (n) where s.expect = 'ok' and (l.te_delta <> 1 or l.ob_delta <> 1)), 0::bigint, 'every successful RPC wrote exactly one task_events row and exactly one outbox event');
select is((select count(*) from step_log l join steps s using (n) where s.expect <> 'ok' and (l.te_delta <> 0 or l.ob_delta <> 0)), 0::bigint, 'every refused or failed RPC wrote no history row and no event');
select is((select count(*) from step_log l join steps s using (n) where s.expect = 'ok' and (l.kind is distinct from s.kind or l.to_status is distinct from s.to_status or l.ob_type is distinct from 'task.' || s.kind)), 0::bigint,
  'each successful step wrote the history kind and status it should, and the matching task.<kind> event');
select is((select count(*) from step_log l join steps s using (n) where s.expect not in ('ok', '42501', '22023')), 0::bigint, 'only the expected error classes occur (sanity)');
select results_eq($$select status, completed_at is null, completed_by_person_id, cancelled_at is not null, assigned_person_id from public.tasks where id = pg_temp.id('sm')$$,
  $$select 'cancelled'::text, true, null::uuid, true, pg_temp.id('p_manager_a1')$$,
  'the task ends cancelled: completion cleared by the reopen, cancel time set; step 26 (completing an unassigned task) had assigned it to the manager who completed it');

-- the details of single steps
select pg_temp.act_as('postgres');
insert into public.tasks (id, organization_id, location_id, title, status, assigned_person_id, assigned_job_title_id) values
  (pg_temp.id('sd1'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'sd1', 'open', null, pg_temp.id('jt_a')),
  (pg_temp.id('sd2'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'sd2', 'open', null, null);
select pg_temp.act_as('u_staff_a1');
select public.start_task(pg_temp.id('sd1'));
select public.complete_task(pg_temp.id('sd2'), '  all good  ');
select pg_temp.act_as('postgres');
select results_eq($$select status, assigned_person_id, assigned_job_title_id from public.tasks where id = pg_temp.id('sd1')$$, $$select 'in_progress'::text, pg_temp.id('p_staff_a1'), pg_temp.id('jt_a')$$,
  'starting a task routed to a job title claims it for the starter (the title stays)');
select results_eq($$select t.status, t.completed_by_person_id, t.assigned_person_id, t.completed_at = now(), e.body from public.tasks t join public.task_events e on e.task_id = t.id and e.kind = 'completed' where t.id = pg_temp.id('sd2')$$,
  $$select 'done'::text, pg_temp.id('p_staff_a1'), pg_temp.id('p_staff_a1'), true, 'all good'::text$$, 'completing an unassigned task: done, completed_by and assignee are the completer, the trimmed note is in the history');
select is((select payload ->> 'task_id' from public.outbox_events where type = 'task.completed' and entity_id = pg_temp.id('sd2')), pg_temp.id('sd2')::text, 'the completed event names the task in its payload');
select is((select (payload ->> 'task_event_id')::uuid from public.outbox_events where type = 'task.completed' and entity_id = pg_temp.id('sd2')), (select id from public.task_events where task_id = pg_temp.id('sd2') and kind = 'completed'), 'and the history row it belongs to');

-- ===========================================================================
-- 5. An invisible task cannot be started, completed, commented on, reopened, assigned or cancelled; the refusal is
--    the same 42501 "not allowed" whether the task exists or not (no NULL-pass, no existence leak) and nothing changes.
-- ===========================================================================
select pg_temp.act_as('postgres');
create temp table inv (n int, label text, who text, task text);
grant all on inv to public;
insert into inv values
  (1, 'someone else''s task (same location)',                   'u_staff_a1', 't_other'),
  (2, 'a task routed to a job title they do not hold',          'u_staff_a1', 't_title_x'),
  (3, 'a task with a person AND a title, assigned to another',  'u_staff_a1', 't_both'),
  (4, 'a task at another location of the same organization',    'u_staff_a1', 't_a2'),
  (5, 'an unassigned task at another location',                 'u_staff_a1', 't_a2_un'),
  (6, 'another organization''s task',                           'u_staff_a1', 't_b'),
  (7, 'a task that does not exist',                             'u_staff_a1', null),
  (8, 'a location manager''s view of another location',         'u_manager_a1', 't_a2'),
  (9, 'a location manager''s view of another organization',     'u_manager_a1', 't_b'),
  (10, 'a location admin''s view of another location',          'u_locadmin_a1', 't_a2_un'),
  (11, 'an org admin''s view of another organization',          'u_orgadmin_a', 't_b'),
  (12, 'org B admin on an org A task',                          'u_orgadmin_b', 't_own'),
  (13, 'a user with no account',                                'u_noaccount', 't_unassigned'),
  (14, 'a disabled account on its own location''s task',        'u_disabled_a', 't_unassigned'),
  (15, 'org admin A at aal1',                                   'u_orgadmin_a', 't_unassigned'),
  (16, 'a platform admin at aal1',                              'u_platform', 't_unassigned');
create temp table inv_actions (n int, name text, sql text);
grant all on inv_actions to public;
insert into inv_actions values
  (1, 'start_task',       $$select public.start_task(%L)$$),
  (2, 'complete_task',    $$select public.complete_task(%L, 'x')$$),
  (3, 'add_task_comment', $$select public.add_task_comment(%L, 'hello')$$),
  (4, 'reopen_task',      $$select public.reopen_task(%L, 'x')$$),
  (5, 'assign_task',      $$select public.assign_task(%L, pg_temp.id('p_staff_a1'), null)$$),
  (6, 'cancel_task',      $$select public.cancel_task(%L, 'x')$$);
select pg_temp.act_as('postgres');
create temp table inv_res (i int, a int, res text, same boolean);
grant all on inv_res to public;
create temp table fp_before as select pg_temp.fp() as f;
do $$
declare v record; a record; r text; tid uuid;
begin
  for v in select * from inv order by n loop
    for a in select * from inv_actions order by n loop
      tid := coalesce(pg_temp.id(v.task), gen_random_uuid());
      perform pg_temp.act_as(v.who, case when v.n = 15 or v.n = 16 then 'aal1' else 'aal2' end);
      r := pg_temp.try_msg(format(a.sql, tid));
      perform pg_temp.act_as('postgres');
      insert into inv_res values (v.n, a.n, r, null);
    end loop;
  end loop;
end $$;
select is((select count(distinct res) from inv_res), 1::bigint, 'all ' || (select count(*) from inv_res) || ' attempts (16 actors x 6 actions) got the identical answer') ;
select is((select min(res) from inv_res), '42501 not allowed', 'and that answer is the uniform "42501 not allowed" (it does not say whether the task exists, where it is, or who has it)');
select is(pg_temp.fp(), (select f from fp_before), 'and none of them changed a task, a history row or an event');
select is((select count(*) from inv_res where i = 7), 6::bigint, 'including the six attempts on a task id that does not exist');
-- the twins: the same actions on a task the same actor CAN see are not refused as "not allowed"
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg(format($$select public.add_task_comment(%L, 'hello')$$, pg_temp.id('t_own'))), 'ok', 'twin: staff A1 comments on their own task');
select is(pg_temp.try_msg(format($$select public.start_task(%L)$$, pg_temp.id('t_title'))), 'ok', 'twin: staff A1 starts the task routed to their job title');
select is(pg_temp.try_msg(format($$select public.complete_task(%L)$$, pg_temp.id('t_unassigned'))), 'ok', 'twin: staff A1 completes an unassigned task at A1');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg(format($$select public.add_task_comment(%L, 'mgr hello')$$, pg_temp.id('t_other'))), 'ok', 'twin: manager A1 comments on a task assigned to someone else');
select is(pg_temp.try_msg(format($$select public.cancel_task(%L, 'x')$$, pg_temp.id('t_title_x'))), 'ok', 'twin: manager A1 cancels a task routed to a title nobody they know holds');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg(format($$select public.assign_task(%L, pg_temp.id('p_staff_a2'), null)$$, pg_temp.id('t_a2_un'))), 'ok', 'twin: org admin A assigns a task at A2 to staff A2');
select pg_temp.act_as('postgres');

-- comments
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg(format($$select public.add_task_comment(%L, null)$$, pg_temp.id('t_prog'))), '22023 a comment needs 1 to 2000 characters', 'comment: null is 22023');
select is(pg_temp.try_msg(format($$select public.add_task_comment(%L, '   ')$$, pg_temp.id('t_prog'))), '22023 a comment needs 1 to 2000 characters', 'comment: blank is 22023');
select is(pg_temp.try_msg(format($$select public.add_task_comment(%L, %L)$$, pg_temp.id('t_prog'), repeat('c', 2001))), '22023 a comment needs 1 to 2000 characters', 'comment: 2001 characters is 22023');
select is(pg_temp.try_msg(format($$select public.add_task_comment(%L, %L)$$, pg_temp.id('t_prog'), repeat('c', 2000))), 'ok', 'twin: 2000 characters is fine');
select is(pg_temp.try_msg(format($$select public.complete_task(%L, %L)$$, pg_temp.id('t_prog'), repeat('n', 2001))), '22023 note is too long', 'complete: a 2001-character note is 22023');
select is(pg_temp.try_msg(format($$select public.add_task_comment(%L, 'on a done task')$$, pg_temp.id('t_done'))), 'ok', 'a comment can be added to a closed task');
select pg_temp.act_as('postgres');
select is((select count(*) from public.task_events where task_id = pg_temp.id('t_prog') and kind = 'commented'), 1::bigint, 'only the valid comment on t_prog was stored');

-- ===========================================================================
-- 6. Templates and rules (configuration): tasks = admin, organization-wide rows need organization scope
-- ===========================================================================
select pg_temp.act_as('postgres');
insert into public.task_templates (id, organization_id, location_id, title) values
  (pg_temp.id('cfg_a1'),   pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'cfg A1'),
  (pg_temp.id('cfg_a2'),   pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'cfg A2'),
  (pg_temp.id('cfg_wide'), pg_temp.id('org_a'), null,                 'cfg wide'),
  (pg_temp.id('cfg_b'),    pg_temp.id('org_b'), null,                 'cfg B');
insert into public.workflow_rules (id, organization_id, location_id, name, event_type, task_template_id) values
  (pg_temp.id('cfgr_a1'),  pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'rule A1', 'booking.confirmed', pg_temp.id('cfg_a1')),
  (pg_temp.id('cfgr_wide'),pg_temp.id('org_a'), null,                 'rule wide', 'booking.confirmed', pg_temp.id('cfg_wide')),
  (pg_temp.id('cfgr_b'),   pg_temp.id('org_b'), null,                 'rule B', 'booking.confirmed', pg_temp.id('cfg_b'));
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.task_templates), 0::bigint, 'configuration: staff see no templates');
select is((select count(*) from public.workflow_rules), 0::bigint, 'configuration: staff see no rules');
select is(pg_temp.try($$insert into public.task_templates (organization_id, location_id, title) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff template')$$), '42501', 'configuration: staff cannot create a template');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff rule', 'booking.confirmed', pg_temp.id('cfg_a1'))$$), '42501', 'configuration: staff cannot create a rule');
select pg_temp.act_as('u_manager_a1');
select is((select array_agg(title order by title) from public.task_templates), array['cfg A1', 'cfg wide'], 'configuration: manager A1 reads A1''s templates and the organization-wide ones, not A2''s or org B''s');
select is((select array_agg(name order by name) from public.workflow_rules), array['rule A1', 'rule wide'], 'configuration: manager A1 reads A1''s rules and the organization-wide ones');
select is(pg_temp.try($$insert into public.task_templates (organization_id, location_id, title) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'mgr template')$$), 'ok', 'twin: manager A1 creates a template at A1');
select is(pg_temp.try($$insert into public.task_templates (organization_id, location_id, title) values (pg_temp.id('org_a'), null, 'mgr wide template')$$), '42501', 'configuration: manager A1 cannot create an organization-wide template (needs organization scope)');
select is(pg_temp.try($$insert into public.task_templates (organization_id, location_id, title) values (pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'mgr a2 template')$$), '42501', 'configuration: manager A1 cannot create a template at A2');
select is(pg_temp.affected($$update public.task_templates set title = 'edited' where id = pg_temp.id('cfg_wide')$$), 0::bigint, 'configuration: manager A1 cannot edit an organization-wide template (0 rows)');
select is(pg_temp.affected($$update public.task_templates set title = 'edited' where id = pg_temp.id('cfg_a1')$$), 1::bigint, 'twin: manager A1 edits the A1 template');
select is(pg_temp.try($$update public.task_templates set location_id = pg_temp.id('loc_a2') where id = pg_temp.id('cfg_a1')$$), '42501', 'configuration: a template''s location cannot be changed (no column grant)');
select is(pg_temp.try($$update public.task_templates set organization_id = pg_temp.id('org_b') where id = pg_temp.id('cfg_a1')$$), '42501', 'configuration: nor its organization');
select is(pg_temp.try($$insert into public.task_templates (organization_id, location_id, title, assign_to, assign_person_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'to a2 person', 'person', pg_temp.id('p_staff_a2'))$$), '42501', 'configuration: a template cannot name a person the manager cannot see');
select is(pg_temp.try($$insert into public.task_templates (organization_id, location_id, title, assign_to, assign_person_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'to a1 person', 'person', pg_temp.id('p_staff_a1'))$$), 'ok', 'twin: a template can name a person the manager can see');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id, enabled) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'sneaky', 'booking.confirmed', pg_temp.id('cfg_a1'), true)$$), 'ok', 'a rule can be inserted with enabled = true...');
select is((select enabled from public.workflow_rules where name = 'sneaky'), false, '...but it is stored disabled (a new rule is always created disabled)');
select is(pg_temp.affected($$update public.workflow_rules set enabled = true where name = 'sneaky'$$), 1::bigint, 'and the manager can enable it afterwards');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'foreign template', 'booking.confirmed', pg_temp.id('cfg_b'))$$), '42501', 'configuration: a rule cannot use another organization''s template');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'hidden template', 'booking.confirmed', pg_temp.id('cfg_a2'))$$), '42501', 'configuration: a rule at A1 cannot use a template that belongs to A2 (uniform 42501, same as a missing template)');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), null, 'mgr wide rule', 'booking.confirmed', pg_temp.id('cfg_wide'))$$), '42501', 'configuration: manager A1 cannot create an organization-wide rule');
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.task_templates), (select count(*) from public.task_templates where organization_id = pg_temp.id('org_a')), 'configuration: org admin A reads every template of org A and none of org B');
select is(pg_temp.try($$insert into public.task_templates (organization_id, location_id, title) values (pg_temp.id('org_a'), null, 'wide by org admin')$$), 'ok', 'twin: the org admin creates an organization-wide template');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), null, 'wide rule by org admin', 'booking.confirmed', pg_temp.id('cfg_wide'))$$), 'ok', 'twin: and an organization-wide rule');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try($$insert into public.task_templates (organization_id, location_id, title) values (pg_temp.id('org_a'), null, 'wide by loc admin')$$), '42501', 'configuration: a location admin cannot create an organization-wide template either');
select is((select count(*) from public.task_templates where location_id is null), 2::bigint, 'configuration: but can read the organization-wide ones (to build rules at A1 on them)');
select pg_temp.act_as('u_orgadmin_b');
select is((select array_agg(title) from public.task_templates), array['cfg B'], 'configuration: org admin B sees only org B''s template');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 7. Service code: a template that names a person who cannot hold the task still creates the task, unassigned
-- ===========================================================================
insert into public.task_templates (id, organization_id, location_id, title, assign_to, assign_person_id) values
  (pg_temp.id('tpl_dis'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'for a disabled person', 'person', pg_temp.id('p_disabled_a'));
insert into public.workflow_rules (id, organization_id, location_id, name, event_type, task_template_id) values
  (pg_temp.id('rule_dis'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'dis', 'incident.submitted', pg_temp.id('tpl_dis'));
update public.workflow_rules set enabled = true where id = pg_temp.id('rule_dis');
create temp table ev_dis as select private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'incident.submitted', 'incidents', gen_random_uuid(), '{}') as id;
grant all on ev_dis to public;
select pg_temp.act_as('service_role');
select isnt(public.create_task_from_event((select id from ev_dis), pg_temp.id('rule_dis')), null, 'a rule''s template naming a disabled account still creates the task');
select pg_temp.act_as('postgres');
select is((select assigned_person_id from public.tasks where source_event_id = (select id from ev_dis)), null, 'the task is created unassigned (the template''s person cannot hold tasks)');

select pg_temp.act_as('postgres');
select * from finish();
rollback;
