-- The two people RPCs from 20261111000500_people_rpcs.sql: public.create_person_with_assignment
-- and public.update_own_profile. They are SECURITY DEFINER, so RLS does not apply to their
-- writes; these tests check that the body enforces the same rules as the policies.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(46);

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

-- ---- create_person_with_assignment: allowed
select pg_temp.act_as('u_locadmin_a1');
select is((select count(*) from public.people where first_name = 'Nia'), 0::bigint, '(setup) no one called Nia exists yet');
create temp table made (k text primary key, id uuid);
grant all on made to public;
insert into made select 'nia', public.create_person_with_assignment(pg_temp.id('org_a'), '  Nia ', ' Newhire', pg_temp.sys_role('staff'), pg_temp.id('loc_a1'), ' Nee ', 'nia@test.invalid', ' 555-0111 ', 'E-100');
select ok((select id from made where k = 'nia') is not null, 'positive: a location admin can onboard a person at their location and gets the id back');
select results_eq($$select first_name, last_name, preferred_name, email, phone, employee_number, organization_id from public.people where id = (select id from made where k = 'nia')$$,
  $$select 'Nia'::text, 'Newhire'::text, 'Nee'::text, 'nia@test.invalid'::text, '555-0111'::text, 'E-100'::text, pg_temp.id('org_a')$$,
  'the new person is readable straight away (no RETURNING problem) and the fields are trimmed');
select is((select count(*) from public.role_assignments where person_id = (select id from made where k = 'nia') and location_id = pg_temp.id('loc_a1') and role_id = pg_temp.sys_role('staff')), 1::bigint,
  'the first role assignment exists');
select pg_temp.act_as('postgres');
select is((select count(*) from public.audit_log where table_name in ('people', 'role_assignments') and (new_row ->> 'person_id' = (select id::text from made where k = 'nia') or row_id = (select id::text from made where k = 'nia'))), 2::bigint,
  'exactly one audit row for the person and one for the assignment');
select results_eq($$select actor_user_id, actor_person_id, actor_role, organization_id, location_id from public.audit_log where table_name = 'people' and row_id = (select id::text from made where k = 'nia')$$,
  $$select pg_temp.id('u_locadmin_a1'), pg_temp.id('p_locadmin_a1'), 'authenticated'::text, pg_temp.id('org_a'), null::uuid$$,
  'the audit row records the real caller, not the function owner');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Mo', 'Manager', pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), 'ok', 'positive: a location admin can onboard a manager at their location (rank 50 < 80)');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Cu', 'Custom', pg_temp.id('role_custom_a'), pg_temp.id('loc_a1'))$q$), 'ok', 'positive: a location admin can onboard with a custom role');
-- ---- create_person_with_assignment: denied, and nothing is left behind
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Ad', 'Admin', pg_temp.sys_role('admin'), pg_temp.id('loc_a1'))$q$), '42501', 'a location admin cannot onboard an admin');
select is((select count(*) from public.people where first_name = 'Ad'), 0::bigint, 'a refused onboarding rolls the new person back');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Oa', 'OrgAdmin', pg_temp.sys_role('admin'), null)$q$), '42501', 'a location admin cannot onboard an org admin');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Tw', 'TwoLoc', pg_temp.sys_role('staff'), pg_temp.id('loc_a2'))$q$), '42501', 'a location admin cannot onboard at another location');
select is((select count(*) from public.people where first_name = 'Tw'), 0::bigint, 'nothing left behind after the A2 attempt');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_b'), 'Xo', 'CrossOrg', pg_temp.sys_role('staff'), pg_temp.id('loc_b1'))$q$), '42501', 'a location admin cannot onboard into another organization');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Cb', 'CustomB', pg_temp.id('role_custom_b'), pg_temp.id('loc_a1'))$q$), '42501', 'a role of another organization is refused');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Nr', 'NoRole', null, pg_temp.id('loc_a1'))$q$), '22023', 'a missing role is refused');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Em', 'BadEmail', pg_temp.sys_role('staff'), pg_temp.id('loc_a1'), null, 'not-an-email')$q$), '23514', 'an invalid email fails the whole call');
select is((select count(*) from public.people where first_name = 'Em'), 0::bigint, 'nothing left behind after the invalid email');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'St', 'ByStaff', pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'staff cannot onboard anyone');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Mg', 'ByManager', pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'a manager without people_roles = admin cannot onboard anyone');
select is((select count(*) from public.people where first_name = 'Mg'), 0::bigint, 'nothing left behind after the manager attempt');
select pg_temp.act_as('u_noaccount');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Na', 'NoAccount', pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'a user with no account cannot onboard');
select pg_temp.act_as('u_disabled_a');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Di', 'Disabled', pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'a disabled account cannot onboard');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Ob', 'OrgAdminB', pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'org admin B cannot onboard into org A');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'La', 'LocAdmin2', pg_temp.sys_role('admin'), pg_temp.id('loc_a2'))$q$), 'ok', 'positive: org admin A can onboard a location admin');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Oo', 'OrgAdmin3', pg_temp.sys_role('admin'), null)$q$), '42501', 'org admin A cannot onboard an org admin');
select is((select count(*) from public.people where first_name = 'Oo'), 0::bigint, 'nothing left behind after the org-admin attempt');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Lb', 'OtherOrgLoc', pg_temp.sys_role('staff'), pg_temp.id('loc_b1'))$q$), '23503', 'org admin A cannot place someone at a location of org B (composite foreign key)');
select is((select count(*) from public.people where first_name = 'Lb'), 0::bigint, 'nothing left behind after the cross-org location attempt');
select pg_temp.act_as('u_platform');
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Pa', 'ByPlatform', pg_temp.sys_role('admin'), null)$q$), 'ok', 'positive: a platform admin can onboard an org admin');
select pg_temp.act_as('postgres');
set local role service_role;
select is(pg_temp.try($q$select public.create_person_with_assignment(pg_temp.id('org_a'), 'Sv', 'ByService', pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'service_role has no signed-in user, so the function refuses (use direct inserts instead)');
select pg_temp.act_as('postgres');

-- ---- update_own_profile
select pg_temp.act_as('u_staff_a1');
select is(public.update_own_profile(pg_temp.id('org_a'), '  Sammy ', ' 555-0199 '), pg_temp.id('p_staff_a1'), 'positive: a member edits their own profile and gets their person id back');
select results_eq($$select preferred_name, phone, first_name, last_name, email, employee_number, archived_at is null from public.people where id = pg_temp.id('p_staff_a1')$$,
  $$select 'Sammy'::text, '555-0199'::text, 'Sam'::text, 'StaffA1'::text, null::text, null::text, true$$,
  'only preferred_name and phone change (trimmed); names of record, email and employee number do not');
select is(public.update_own_profile(pg_temp.id('org_a'), '   ', null), pg_temp.id('p_staff_a1'), 'blank or null clears the field');
select results_eq($$select preferred_name, phone from public.people where id = pg_temp.id('p_staff_a1')$$, $$select null::text, null::text$$, 'cleared');
select is(pg_temp.try($q$select public.update_own_profile(pg_temp.id('org_b'), 'x', 'y')$q$), '42501', 'a member of A cannot use it for org B');
select is((select count(*) from public.people where organization_id = pg_temp.id('org_b') and (preferred_name = 'x' or phone = 'y')), 0::bigint, 'and org B is untouched');
select pg_temp.act_as('u_locadmin_a1');
select is(public.update_own_profile(pg_temp.id('org_a'), 'Lou', null), pg_temp.id('p_locadmin_a1'), 'positive: a location admin edits their own profile (the tier rule forbids it on the table)');
select is((select preferred_name from public.people where id = pg_temp.id('p_staff_a1')), null, 'and it only ever touched their own row');
select pg_temp.act_as('postgres');
select results_eq($$select action, changed_columns, actor_person_id, organization_id from public.audit_log
    where table_name = 'people' and row_id = pg_temp.id('p_locadmin_a1')::text and action = 'update'$$,
  $$select 'update'::text, array['preferred_name']::text[], pg_temp.id('p_locadmin_a1'), pg_temp.id('org_a')$$, 'the profile edit is audited with the real caller');
select pg_temp.act_as('u_noaccount');
select is(pg_temp.try($q$select public.update_own_profile(pg_temp.id('org_a'), 'Hacked', '000')$q$), '42501', 'a user with no account cannot use update_own_profile');
select pg_temp.act_as('u_disabled_a');
select is(pg_temp.try($q$select public.update_own_profile(pg_temp.id('org_a'), 'Hacked', '000')$q$), '42501', 'a disabled account cannot use update_own_profile');
select pg_temp.act_as('postgres');
insert into auth.users (id, email) values (pg_temp.id('u_noassign'), 'noassign@test.invalid');
insert into public.people (id, organization_id, first_name, last_name) values (pg_temp.id('p_noassign'), pg_temp.id('org_a'), 'No', 'Assign');
insert into public.accounts (organization_id, person_id, user_id) values (pg_temp.id('org_a'), pg_temp.id('p_noassign'), pg_temp.id('u_noassign'));
select pg_temp.act_as('u_noassign');
select is(pg_temp.try($q$select public.update_own_profile(pg_temp.id('org_a'), 'Hacked', '000')$q$), '42501', 'a user with an account but no role assignment cannot use update_own_profile');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.try($q$select public.update_own_profile(pg_temp.id('org_a'), 'Hacked', '000')$q$), '42501', 'org admin B (for org A) cannot use update_own_profile');
select pg_temp.act_as('postgres');
select is((select count(*) from public.people where preferred_name = 'Hacked' or phone = '000'), 0::bigint, 'and no row was changed');
set local role service_role;
select is(pg_temp.try($q$select public.update_own_profile(pg_temp.id('org_a'), 'x', 'y')$q$), '42501', 'service_role has no signed-in user, so update_own_profile refuses');
select pg_temp.act_as('postgres');
select * from finish();
rollback;
