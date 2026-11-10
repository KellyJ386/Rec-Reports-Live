-- Security review fixes (migration 20261111000600): F1 permission cap on granting roles, F2 people
-- visibility/archive rules, F5 location archive guard, F6 no information leaks from BEFORE triggers,
-- F9 settings size, F10 scope-aware helpers, L6 overlapping hours. Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(93);

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

-- Switch identity: act_as('u_staff_a1') = authenticated with that user's JWT; act_as('anon');
-- act_as('postgres') (or null) goes back to the owner.
create function pg_temp.act_as(p_who text) returns void language plpgsql as $$
begin
  if p_who is null or p_who = 'postgres' then
    perform set_config('role', 'none', true);
    perform set_config('request.jwt.claims', '', true);
  elsif p_who = 'anon' then
    perform set_config('role', 'none', true);
    perform set_config('request.jwt.claims', '{"role":"anon"}', true);
    perform set_config('role', 'anon', true);
  else
    perform set_config('role', 'none', true);
    perform set_config('request.jwt.claims',
      json_build_object('sub', pg_temp.id(p_who), 'role', 'authenticated')::text, true);
    perform set_config('role', 'authenticated', true);
  end if;
end $$;
grant execute on function pg_temp.act_as(text) to public;

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

-- message + detail of a failing statement, as "<sqlstate>: <message> | <detail>"
create function pg_temp.try_msg(p_sql text) returns text language plpgsql as $f$
declare m text; d text; st text;
begin
  execute p_sql;
  return 'ok';
exception when others then
  get stacked diagnostics m = message_text, d = pg_exception_detail, st = returned_sqlstate;
  return st || ': ' || m || ' | ' || coalesce(d, '');
end $f$;
-- a space kind of an organization, readable by anyone (so non-members can build a statement)
create function pg_temp.kind_of(p_org uuid) returns uuid language sql stable security definer set search_path = ''
as $$ select id from public.space_kinds where organization_id = p_org and key = 'pool' $$;
grant execute on function pg_temp.try_msg(text), pg_temp.kind_of(uuid) to public;

-- Setup: roles for the F1 cases, targets for grants.
--   role_acc_a: custom role whose defaults include accidents = admin (the manager's own level is none)
--   role_harm_a: custom role with only tasks = view
insert into public.roles (id, organization_id, key, name, rank) values
  (pg_temp.id('role_acc_a'), pg_temp.id('org_a'), 'accident_lead', 'Accident Lead', 20),
  (pg_temp.id('role_harm_a'), pg_temp.id('org_a'), 'harmless', 'Harmless', 20);
insert into public.role_default_permissions (role_id, module_key, level) values
  (pg_temp.id('role_acc_a'), 'accidents', 'admin'), (pg_temp.id('role_acc_a'), 'tasks', 'view'),
  (pg_temp.id('role_harm_a'), 'tasks', 'view');
insert into public.people (id, organization_id, first_name, last_name) values
  (pg_temp.id('p_t1'), pg_temp.id('org_a'), 'Tee', 'One'), (pg_temp.id('p_t2'), pg_temp.id('org_a'), 'Tee', 'Two'),
  (pg_temp.id('p_arch'), pg_temp.id('org_a'), 'Ann', 'Archived');
insert into public.role_assignments (id, organization_id, person_id, role_id, location_id) values
  (pg_temp.id('ra_t1'), pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1')),
  (pg_temp.id('ra_t2'), pg_temp.id('org_a'), pg_temp.id('p_t2'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1')),
  (pg_temp.id('ra_arch'), pg_temp.id('org_a'), pg_temp.id('p_arch'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'));
update public.people set archived_at = now() where id = pg_temp.id('p_arch');
-- manager A1 may administer people at A1 (override); their accidents level stays none
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level)
values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('loc_a1'), 'people_roles', 'admin');

-- ===========================================================================
-- F1: a role cannot be granted if its defaults exceed the granter's own levels
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'accidents'), 'none', '(setup) the manager''s own accidents level is none');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('role_acc_a'), pg_temp.id('loc_a1'))$q$), '42501', 'F1: a manager cannot grant a role whose defaults include accidents = admin (direct insert)');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('role_harm_a'), pg_temp.id('loc_a1'))$q$), 'ok', 'F1 allowed twin: the same manager can grant a harmless custom role');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'F1Acc', 'Review', pg_temp.id('role_acc_a'), pg_temp.id('loc_a1'))$q$), '42501', 'F1: nor through create_person_with_assignment');
select is((select count(*) from public.people where first_name = 'F1Acc'), 0::bigint, 'F1: and the refused onboarding leaves no person behind');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'F1Ok', 'Review', pg_temp.id('role_harm_a'), pg_temp.id('loc_a1'))$q$), 'ok', 'F1 allowed twin: create_person_with_assignment with the harmless role works');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t2'), pg_temp.id('role_acc_a'), pg_temp.id('loc_a1'))$q$), '42501', 'F1: nor through replace_role_assignment');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t2'), pg_temp.id('role_harm_a'), pg_temp.id('loc_a1'))$q$), 'ok', 'F1 allowed twin: replace_role_assignment with the harmless role works');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('role_acc_a'), pg_temp.id('loc_a1'))$q$), 'ok', 'F1 allowed twin: a location admin (accidents = admin) can grant that role');
-- mirror: defaults of a custom role cannot exceed the org admin's own organization-scope level
select pg_temp.act_as('postgres');
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values
  (pg_temp.id('org_a'), pg_temp.id('p_orgadmin_a'), null, 'checklists', 'view'),
  (pg_temp.id('org_a'), pg_temp.id('p_orgadmin_a'), null, 'tasks', 'view');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($q$insert into public.role_default_permissions (role_id, module_key, level) values (pg_temp.id('role_custom_a'), 'checklists', 'edit')$q$), '42501',
  'F1 mirror: an org admin whose checklists level was lowered to view cannot set a custom role default of edit');
select is(pg_temp.try($q$insert into public.role_default_permissions (role_id, module_key, level) values (pg_temp.id('role_custom_a'), 'checklists', 'view')$q$), 'ok',
  'F1 mirror allowed twin: they can set it up to their own level (view)');
select is(pg_temp.try($q$update public.role_default_permissions set level = 'edit' where id = pg_temp.id('rdp_a')$q$), '42501',
  'F1 mirror: nor raise an existing default above their own level (tasks view -> edit refused)');
select is(pg_temp.affected($q$update public.role_default_permissions set level = 'view' where id = pg_temp.id('rdp_a')$q$), 1::bigint,
  'F1 mirror allowed twin: lowering it to their own level works');
select pg_temp.act_as('postgres');
delete from public.user_permissions where person_id = pg_temp.id('p_orgadmin_a') and module_key in ('checklists', 'tasks');

-- ===========================================================================
-- F2: people visibility, archived people, direct inserts
-- ===========================================================================
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'F2: a location admin cannot assign a role to an unassigned person they cannot see');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_arch'), pg_temp.id('role_harm_a'), pg_temp.id('loc_a1'))$q$), '42501', 'F2: nor to an archived person (needs an organization-scope people_roles admin)');
select is(pg_temp.affected($q$update public.people set archived_at = null where id = pg_temp.id('p_arch')$q$), 0::bigint, 'F2: a location admin cannot un-archive a person');
select is(pg_temp.try($q$insert into public.people (organization_id, first_name, last_name) values (pg_temp.id('org_a'), 'Direct', 'Insert')$q$), '42501', 'F2: nor insert into people directly');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'F2Rpc', 'Review', pg_temp.id('role_harm_a'), pg_temp.id('loc_a1'))$q$), 'ok', 'F2 allowed twin: onboarding through create_person_with_assignment works');
select is((select count(*) from public.people where first_name = 'F2Rpc'), 1::bigint, 'F2: and the onboarded person reads back straight away');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_arch'), pg_temp.id('role_harm_a'), pg_temp.id('loc_a1'))$q$), 'ok', 'F2 allowed twin: an org admin can assign a role to an archived person');
select is(pg_temp.affected($q$update public.people set archived_at = null where id = pg_temp.id('p_arch')$q$), 1::bigint, 'F2 allowed twin: an org admin can un-archive a person');
select is(pg_temp.try($q$insert into public.people (organization_id, first_name, last_name) values (pg_temp.id('org_a'), 'Direct', 'Insert')$q$), 'ok', 'F2 allowed twin: an org admin can insert into people directly');

-- ===========================================================================
-- F5: archiving or restoring a location needs an organization-scope admin
-- ===========================================================================
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try($q$update public.locations set archived_at = now() where id = pg_temp.id('loc_a1')$q$), '42501', 'F5: a location admin cannot archive their location');
select is(pg_temp.affected($q$update public.locations set name = 'A1 Arena (renamed)' where id = pg_temp.id('loc_a1')$q$), 1::bigint, 'F5 allowed twin: but can rename it');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.affected($q$update public.locations set archived_at = now() where id = pg_temp.id('loc_a2')$q$), 1::bigint, 'F5 allowed twin: an org admin can archive a location');
select is(pg_temp.affected($q$update public.locations set archived_at = null where id = pg_temp.id('loc_a2')$q$), 1::bigint, 'F5 allowed twin: and restore it');
select is(pg_temp.affected($q$update public.locations set archived_at = now() where id = pg_temp.id('loc_a1')$q$), 1::bigint, '(setup) org admin archives A1');
select pg_temp.act_as('u_locadmin_a1');
select cmp_ok(pg_temp.affected($q$update public.locations set archived_at = null where id = pg_temp.id('loc_a1')$q$), '<=', 0::bigint, 'F5: a location admin cannot restore an archived location');
select pg_temp.act_as('postgres');
select isnt((select archived_at from public.locations where id = pg_temp.id('loc_a1')), null, 'F5: and it is still archived');
update public.locations set archived_at = null where id = pg_temp.id('loc_a1');

-- ===========================================================================
-- F6: refusals do not reveal roles, names or other rows
-- ===========================================================================
-- Role cases, for people who are not members of org A and for a member who names another org's role.
create temp table f6 (actor text, role_what text, msg text);
grant all on f6 to public;
select pg_temp.act_as('u_noaccount');
insert into f6 values ('u_noaccount', 'another orgs custom role', pg_temp.try_msg($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('role_custom_b'), pg_temp.id('loc_a1'))$q$));
select pg_temp.act_as('u_noaccount');
insert into f6 values ('u_noaccount', 'a custom role of org A', pg_temp.try_msg($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('role_custom_a'), pg_temp.id('loc_a1'))$q$));
select pg_temp.act_as('u_noaccount');
insert into f6 values ('u_noaccount', 'a random role id', pg_temp.try_msg($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_t1'), gen_random_uuid(), pg_temp.id('loc_a1'))$q$));
select pg_temp.act_as('u_orgadmin_b');
insert into f6 values ('u_orgadmin_b', 'another orgs custom role', pg_temp.try_msg($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('role_custom_b'), pg_temp.id('loc_a1'))$q$));
select pg_temp.act_as('u_orgadmin_b');
insert into f6 values ('u_orgadmin_b', 'a custom role of org A', pg_temp.try_msg($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('role_custom_a'), pg_temp.id('loc_a1'))$q$));
select pg_temp.act_as('u_orgadmin_b');
insert into f6 values ('u_orgadmin_b', 'a random role id', pg_temp.try_msg($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_t1'), gen_random_uuid(), pg_temp.id('loc_a1'))$q$));
select pg_temp.act_as('u_staff_a1');
insert into f6 values ('u_staff_a1', 'another orgs custom role', pg_temp.try_msg($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('role_custom_b'), pg_temp.id('loc_a1'))$q$));
select pg_temp.act_as('u_staff_a1');
insert into f6 values ('u_staff_a1', 'a random role id', pg_temp.try_msg($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_t1'), gen_random_uuid(), pg_temp.id('loc_a1'))$q$));
select pg_temp.act_as('postgres');
select is(f.msg, '42501: not allowed | ', 'F6: ' || f.actor || ' naming ' || f.role_what || ' gets the generic 42501 with no detail') from f6 f order by f.actor, f.role_what;
select ok(position('lead' in lower(f.msg)) = 0 and position('Lead' in f.msg) = 0 and position(pg_temp.id('role_custom_b')::text in f.msg) = 0,
  'F6: ' || f.actor || ' naming ' || f.role_what || ': the message has no role key, name or id') from f6 f order by f.actor, f.role_what;
select is((select count(distinct msg) from f6), 1::bigint, 'F6: every case, existing or not, gives the identical message');
create temp table f6s (actor text, what text, msg text);
grant all on f6s to public;
select pg_temp.act_as('u_noaccount');
insert into f6s values ('u_noaccount', 'another-org space', pg_temp.try_msg($q$insert into public.spaces (organization_id, location_id, space_kind_id, parent_space_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.kind_of(pg_temp.id('org_a')), pg_temp.id('space_b1'), 'F6 child')$q$));
select pg_temp.act_as('u_noaccount');
insert into f6s values ('u_noaccount', 'a random space id', pg_temp.try_msg($q$insert into public.spaces (organization_id, location_id, space_kind_id, parent_space_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.kind_of(pg_temp.id('org_a')), gen_random_uuid(), 'F6 child')$q$));
select pg_temp.act_as('u_orgadmin_b');
insert into f6s values ('u_orgadmin_b', 'another-org space', pg_temp.try_msg($q$insert into public.spaces (organization_id, location_id, space_kind_id, parent_space_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.kind_of(pg_temp.id('org_a')), pg_temp.id('space_b1'), 'F6 child')$q$));
select pg_temp.act_as('u_orgadmin_b');
insert into f6s values ('u_orgadmin_b', 'a random space id', pg_temp.try_msg($q$insert into public.spaces (organization_id, location_id, space_kind_id, parent_space_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.kind_of(pg_temp.id('org_a')), gen_random_uuid(), 'F6 child')$q$));
select pg_temp.act_as('u_orgadmin_a');
insert into f6s values ('u_orgadmin_a', 'another-org space', pg_temp.try_msg($q$insert into public.spaces (organization_id, location_id, space_kind_id, parent_space_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.kind_of(pg_temp.id('org_a')), pg_temp.id('space_b1'), 'F6 child')$q$));
select pg_temp.act_as('u_orgadmin_a');
insert into f6s values ('u_orgadmin_a', 'a random space id', pg_temp.try_msg($q$insert into public.spaces (organization_id, location_id, space_kind_id, parent_space_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.kind_of(pg_temp.id('org_a')), gen_random_uuid(), 'F6 child')$q$));
select pg_temp.act_as('postgres');
select is(regexp_replace(f.msg, '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<id>', 'g'),
  case when f.actor = 'u_orgadmin_a' then regexp_replace(f.msg, '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<id>', 'g') else '42501: not allowed | ' end,
  'F6: ' || f.actor || ' naming ' || f.what || ' as a parent gets the expected refusal') from f6s f order by f.actor, f.what;
select is((select count(distinct regexp_replace(msg, '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<id>', 'g')) from f6s where actor = 'u_orgadmin_a'), 1::bigint,
  'F6: for a member of A, another org''s parent space and a random id give the same message (a foreign-key error, ids aside)');
select ok((select bool_and(position('B1 Pool' in msg) = 0 and position('Pool' in msg) = 0) from f6s), 'F6: no refusal contains the other org''s space name');
select ok((select bool_and(msg like '42501%' or msg like '23503%') from f6s), 'F6: only generic permission or foreign-key errors (never a hierarchy message about another org''s space)');

-- ===========================================================================
-- F9: organization_settings.settings is bounded
-- ===========================================================================
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($q$update public.organization_settings set settings = jsonb_build_object('blob', repeat('x', 70000)) where organization_id = pg_temp.id('org_a')$q$), '23514',
  'F9: an oversized settings value is refused');
select is(pg_temp.try($q$update public.organization_settings set settings = '{"theme": "dark", "notes": ["a", "b"]}'::jsonb where organization_id = pg_temp.id('org_a')$q$), 'ok',
  'F9 allowed twin: a normal settings value is accepted');
select is(pg_temp.try($q$update public.organization_settings set settings = jsonb_build_object('blob', repeat('x', 60000)) where organization_id = pg_temp.id('org_a')$q$), 'ok',
  'F9: just under the limit is accepted');

-- ===========================================================================
-- F10: the helpers know which scopes exist
-- ===========================================================================
select pg_temp.act_as('u_orgadmin_a');
select ok(not public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_b1'), 'admin') and not public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_b1'), 'people_roles', 'none') and public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_b1')) = 0
  and public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_b1'), 'people_roles') = 'none', 'F10: orgadmin_a / a location of another organization: has_role false, has_permission false (even at none), actor_rank 0, effective_permission none');
select ok(not public.has_role(pg_temp.id('org_a'), gen_random_uuid(), 'admin') and not public.has_permission(pg_temp.id('org_a'), gen_random_uuid(), 'people_roles', 'none') and public.actor_rank(pg_temp.id('org_a'), gen_random_uuid()) = 0
  and public.effective_permission(pg_temp.id('org_a'), gen_random_uuid(), 'people_roles') = 'none', 'F10: orgadmin_a / a random location: has_role false, has_permission false (even at none), actor_rank 0, effective_permission none');
select ok(not public.has_role(gen_random_uuid(), null, 'admin') and not public.has_permission(gen_random_uuid(), null, 'people_roles', 'none') and public.actor_rank(gen_random_uuid(), null) = 0
  and public.effective_permission(gen_random_uuid(), null, 'people_roles') = 'none', 'F10: orgadmin_a / a random organization: has_role false, has_permission false (even at none), actor_rank 0, effective_permission none');
select ok(not public.has_role(pg_temp.id('org_b'), gen_random_uuid(), 'admin') and not public.has_permission(pg_temp.id('org_b'), gen_random_uuid(), 'people_roles', 'none') and public.actor_rank(pg_temp.id('org_b'), gen_random_uuid()) = 0
  and public.effective_permission(pg_temp.id('org_b'), gen_random_uuid(), 'people_roles') = 'none', 'F10: orgadmin_a / a random location in org B: has_role false, has_permission false (even at none), actor_rank 0, effective_permission none');
select pg_temp.act_as('u_platform');
select ok(not public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_b1'), 'admin') and not public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_b1'), 'people_roles', 'none') and public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_b1')) = 0
  and public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_b1'), 'people_roles') = 'none', 'F10: platform / a location of another organization: has_role false, has_permission false (even at none), actor_rank 0, effective_permission none');
select ok(not public.has_role(pg_temp.id('org_a'), gen_random_uuid(), 'admin') and not public.has_permission(pg_temp.id('org_a'), gen_random_uuid(), 'people_roles', 'none') and public.actor_rank(pg_temp.id('org_a'), gen_random_uuid()) = 0
  and public.effective_permission(pg_temp.id('org_a'), gen_random_uuid(), 'people_roles') = 'none', 'F10: platform / a random location: has_role false, has_permission false (even at none), actor_rank 0, effective_permission none');
select ok(not public.has_role(gen_random_uuid(), null, 'admin') and not public.has_permission(gen_random_uuid(), null, 'people_roles', 'none') and public.actor_rank(gen_random_uuid(), null) = 0
  and public.effective_permission(gen_random_uuid(), null, 'people_roles') = 'none', 'F10: platform / a random organization: has_role false, has_permission false (even at none), actor_rank 0, effective_permission none');
select ok(not public.has_role(pg_temp.id('org_b'), gen_random_uuid(), 'admin') and not public.has_permission(pg_temp.id('org_b'), gen_random_uuid(), 'people_roles', 'none') and public.actor_rank(pg_temp.id('org_b'), gen_random_uuid()) = 0
  and public.effective_permission(pg_temp.id('org_b'), gen_random_uuid(), 'people_roles') = 'none', 'F10: platform / a random location in org B: has_role false, has_permission false (even at none), actor_rank 0, effective_permission none');
select ok(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles', 'admin') and public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')) > 0,
  'F10 allowed twin: the platform admin still gets everything in a scope that exists');
select pg_temp.act_as('u_orgadmin_a');
select ok(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles', 'admin') and public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'admin'),
  'F10 allowed twin: the org admin still gets everything in their own org''s locations');
select pg_temp.act_as('u_noaccount');
select is(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks', lvl), false, 'F10: noaccount (not a member of A): has_permission is false at level ' || lvl) from unnest(enum_range(null::public.permission_level)) lvl;
select pg_temp.act_as('u_disabled_a');
select is(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks', lvl), false, 'F10: disabled_a (not a member of A): has_permission is false at level ' || lvl) from unnest(enum_range(null::public.permission_level)) lvl;
select pg_temp.act_as('u_staff_b1');
select is(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks', lvl), false, 'F10: staff_b1 (not a member of A): has_permission is false at level ' || lvl) from unnest(enum_range(null::public.permission_level)) lvl;
select pg_temp.act_as('u_staff_a1');
select is(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles', 'none'), true, 'F10 allowed twin: a member passes the none level (it is a level, not a stranger check)');
select ok(not public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'tasks', 'none'), 'F10: but a member with no assignment at A2 does not pass any level there');

-- ===========================================================================
-- L6: weekly hours cannot overlap
-- ===========================================================================
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 1, '20:00', '23:00', null, null)$q$), '23P01', 'L6: hours overlapping an existing row (Monday 06:00-22:00) are refused');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 1, '22:00', '23:00', null, null)$q$), 'ok', 'L6 allowed twin: adjacent hours (22:00-23:00) are accepted');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 2, '06:00', '22:00', null, null)$q$), 'ok', 'L6 allowed twin: the same times on another weekday are accepted');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 3, '06:00', '22:00', '2030-01-01', '2030-06-30')$q$), 'ok', 'L6 allowed twin: a seasonal row is accepted');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 3, '06:00', '22:00', '2030-07-01', '2030-12-31')$q$), 'ok', 'L6 allowed twin: the same times in a different season are accepted');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 3, '08:00', '09:00', '2030-06-15', '2030-07-15')$q$), '23P01', 'L6: a row overlapping both seasons is refused');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 1, '05:00', '06:00', null, null)$q$), 'ok', 'L6 allowed twin: hours ending exactly when the first row opens are accepted');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to) values (pg_temp.id('org_a'), pg_temp.id('loc_a2'), pg_temp.id('space_a2'), 1, '22:00', '23:00', null, null)$q$), 'ok', 'L6 allowed twin: hours for another space are independent');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 1, '21:00', '22:30', null, null)$q$), '23P01', 'L6: a manager (authenticated, so the range constructor must be executable) is refused on overlap too');
-- cross-organization: the failure must not reveal org B's row
select pg_temp.act_as('u_orgadmin_a');
create temp table l6 (msg text);
grant all on l6 to public;
insert into l6 values (pg_temp.try_msg($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_b1'), 1, '06:00', '22:00', null, null)$q$));
select pg_temp.act_as('postgres');
select is((select substr(msg, 1, 5) from l6), '23503', 'L6: an org A row naming org B''s space fails as a foreign key (sqlstate 23503), not as an overlap');
select ok((select position('22:00' in msg) = 0 and position('06:00' in msg) = 0 and position('conflicts' in msg) = 0 and position('space_hours_no_overlap' in msg) = 0 from l6),
  'L6: and the message and detail do not reveal org B''s hours or the exclusion constraint');
select * from finish();
rollback;
