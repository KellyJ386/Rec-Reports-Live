-- Tier rule (docs/SECURITY.md): who may create or remove role assignments, change
-- overrides, accounts and people. Allowed cases succeed too, so no test here can
-- pass just because everything is denied. Order matters: later sections use rows
-- that earlier ones leave alone.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(94);

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

-- A second org admin in A (to prove org admins cannot touch each other) and fresh people with no
-- assignments (p_t1..p_t3) so that sections do not depend on each other's grants.
insert into public.people (id, organization_id, first_name, last_name) values
  (pg_temp.id('p_orgadmin2_a'), pg_temp.id('org_a'), 'Otto', 'OrgAdmin2'),
  (pg_temp.id('p_t1'), pg_temp.id('org_a'), 'Tee', 'One'), (pg_temp.id('p_t2'), pg_temp.id('org_a'), 'Tee', 'Two'),
  (pg_temp.id('p_t3'), pg_temp.id('org_a'), 'Tee', 'Three');
insert into public.role_assignments (id, organization_id, person_id, role_id, location_id)
values (pg_temp.id('ra_orgadmin2_a'), pg_temp.id('org_a'), pg_temp.id('p_orgadmin2_a'), pg_temp.sys_role('admin'), null);


-- composite keys: cross-tenant references fail as foreign keys, even for the owner (RLS is not what stops them)
select pg_temp.act_as('postgres');
select is(pg_temp.try($q$insert into public.spaces (organization_id, location_id, space_kind_id, name) values (pg_temp.id('org_a'), pg_temp.id('loc_b1'), (select id from public.space_kinds where organization_id = pg_temp.id('org_a') and key = 'pool'), 'x')$q$), '23503', 'a space in org A cannot sit at a location of org B');
select is(pg_temp.try($q$insert into public.spaces (organization_id, location_id, space_kind_id, name) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), (select id from public.space_kinds where organization_id = pg_temp.id('org_b') and key = 'pool'), 'x')$q$), '23503', 'a space in org A cannot use a space kind of org B');
select is(pg_temp.try($q$insert into public.spaces (organization_id, location_id, space_kind_id, parent_space_id, name) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), (select id from public.space_kinds where organization_id = pg_temp.id('org_a') and key = 'pool'), pg_temp.id('space_a2'), 'x')$q$), '23503', 'a sub-space cannot have a parent at another location');
select is(pg_temp.try($q$insert into public.spaces (organization_id, location_id, space_kind_id, parent_space_id, name) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), (select id from public.space_kinds where organization_id = pg_temp.id('org_a') and key = 'pool'), pg_temp.id('space_b1'), 'x')$q$), '23503', 'a sub-space cannot have a parent in another organization');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_b1'), 1, '08:00', '09:00')$q$), '23503', 'space_hours cannot point at a space of org B');
select is(pg_temp.try($q$insert into public.space_closures (organization_id, location_id, space_id, starts_at, ends_at) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a2'), '2031-01-01', '2031-01-02')$q$), '23503', 'space_closures at A1 cannot point at a space of A2');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_b1'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '23503', 'a role assignment in org A cannot name a person of org B');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.sys_role('staff'), pg_temp.id('loc_b1'))$q$), '23503', 'a role assignment in org A cannot be at a location of org B');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.id('role_custom_b'), pg_temp.id('loc_a1'))$q$), '23503', 'a role assignment in org A cannot use a custom role of org B');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_staff_b1'), null, 'tasks', 'view')$q$), '23503', 'an override in org A cannot name a person of org B');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.id('loc_b1'), 'reports', 'view')$q$), '23503', 'an override in org A cannot be at a location of org B');
select is(pg_temp.try($q$insert into public.person_job_titles (organization_id, person_id, job_title_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('jt_b'), null)$q$), '23503', 'a job-title link in org A cannot use a job title of org B');
select is(pg_temp.try($q$insert into public.accounts (organization_id, person_id, user_id) values (pg_temp.id('org_b'), pg_temp.id('p_unassigned_a'), pg_temp.id('u_noaccount'))$q$), '23503', 'an account in org B cannot name a person of org A');

-- staff cannot change any assignment, including their own
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'staff A1 cannot create an assignment for someone else');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'staff A1 cannot give themselves manager');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.sys_role('admin'), pg_temp.id('loc_a1'))$q$), '42501', 'staff A1 cannot give themselves admin');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_staff_a1')$q$), 0::bigint, 'staff A1 cannot remove their own assignment');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_manager_a1')$q$), 0::bigint, 'staff A1 cannot remove someone else''s assignment');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'people_roles', 'admin')$q$), '42501', 'staff A1 cannot grant themselves people_roles = admin');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('loc_a1'), 'tasks', 'view')$q$), '42501', 'staff A1 cannot write an override for anyone');
select is(pg_temp.affected($q$update public.user_permissions set level = 'edit' where id = pg_temp.id('up_a')$q$), 0::bigint, 'staff A1 cannot raise their own override');
select is(pg_temp.affected($q$delete from public.user_permissions where id = pg_temp.id('up_a')$q$), 0::bigint, 'staff A1 cannot remove their own override');
select is(pg_temp.affected($q$update public.accounts set disabled_at = null where id = pg_temp.id('acct_staff_a1')$q$), 0::bigint, 'staff A1 cannot change their own account');
select is(pg_temp.affected($q$update public.people set last_name = 'Self' where id = pg_temp.id('p_staff_a1')$q$), 0::bigint, 'staff A1 cannot edit their own person row (no self edits)');
select is(pg_temp.affected($q$update public.people set last_name = 'Other' where id = pg_temp.id('p_manager_a1')$q$), 0::bigint, 'staff A1 cannot edit another person');
select is(pg_temp.try($q$insert into public.people (organization_id, first_name, last_name) values (pg_temp.id('org_a'), 'New', 'Person')$q$), '42501', 'staff A1 cannot create people');

-- location admin (rank 80 at A1)
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), 'ok', 'positive: location admin A1 can give staff at A1 to a new person');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), 'ok', 'positive: location admin A1 can promote staff A1 to manager at A1');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.id('role_custom_a'), pg_temp.id('loc_a1'))$q$), 'ok', 'positive: location admin A1 can give a custom role (rank 30) at A1');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.sys_role('admin'), pg_temp.id('loc_a1'))$q$), '42501', 'location admin A1 cannot grant admin at A1 (rank 80 is not below 80)');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.sys_role('admin'), null)$q$), '42501', 'location admin A1 cannot grant org-scope admin');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.sys_role('staff'), pg_temp.id('loc_a2'))$q$), '42501', 'location admin A1 cannot grant at A2');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_locadmin_a1'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'location admin A1 cannot change their own assignments');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_locadmin_a1'), pg_temp.sys_role('manager'), pg_temp.id('loc_a2'))$q$), '42501', 'location admin A1 cannot grant themselves anything at A2');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_locadmin_a1')$q$), 0::bigint, 'location admin A1 cannot remove their own admin assignment');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_orgadmin_a')$q$), 0::bigint, 'location admin A1 cannot remove an org admin''s assignment');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_staff_a2')$q$), 0::bigint, 'location admin A1 cannot remove an assignment at A2');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'tasks', 'edit')$q$), 'ok', 'positive: location admin A1 can write an override for staff A1 at A1');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), null, 'tasks', 'edit')$q$), '42501', 'location admin A1 cannot write an organization-wide override');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_locadmin_a1'), pg_temp.id('loc_a1'), 'audit_log', 'admin')$q$), '42501', 'location admin A1 cannot write an override for themselves');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_orgadmin_a'), pg_temp.id('loc_a1'), 'tasks', 'view')$q$), '42501', 'location admin A1 cannot write an override for the org admin');
select is(pg_temp.affected($q$update public.user_permissions set level = 'admin' where person_id = pg_temp.id('p_staff_a1') and location_id = pg_temp.id('loc_a1') and module_key = 'tasks'$q$), 1::bigint, 'positive: location admin A1 can change an A1-level override of an A1 person');
select is(pg_temp.affected($q$update public.user_permissions set level = 'edit' where id = pg_temp.id('up_a')$q$), 0::bigint, 'location admin A1 cannot change an organization-wide override');
select is(pg_temp.affected($q$update public.people set first_name = 'Samuel' where id = pg_temp.id('p_staff_a1')$q$), 1::bigint, 'positive: location admin A1 can edit an A1 person');
select is(pg_temp.affected($q$update public.people set first_name = 'Lou2' where id = pg_temp.id('p_locadmin_a1')$q$), 0::bigint, 'location admin A1 cannot edit themselves');
select is(pg_temp.affected($q$update public.people set first_name = 'Olive2' where id = pg_temp.id('p_orgadmin_a')$q$), 0::bigint, 'location admin A1 cannot edit the org admin');
select is(pg_temp.affected($q$update public.people set first_name = 'Sue2' where id = pg_temp.id('p_staff_a2')$q$), 0::bigint, 'location admin A1 cannot edit a person who is only at A2');
select is(pg_temp.affected($q$update public.accounts set disabled_at = now() where id = pg_temp.id('acct_orgadmin_a')$q$), 0::bigint, 'location admin A1 cannot disable the org admin''s account');
select is(pg_temp.affected($q$update public.accounts set disabled_at = now() where id = pg_temp.id('acct_locadmin_a1')$q$), 0::bigint, 'location admin A1 cannot disable their own account');
select is(pg_temp.affected($q$update public.accounts set disabled_at = now() where id = pg_temp.id('acct_manager_a1')$q$), 1::bigint, 'positive: location admin A1 can disable the manager''s account');
select is(pg_temp.affected($q$update public.accounts set disabled_at = null where id = pg_temp.id('acct_manager_a1')$q$), 1::bigint, 'positive: location admin A1 can re-enable it');
select is(pg_temp.try($q$insert into public.people (organization_id, first_name, last_name) values (pg_temp.id('org_a'), 'New', 'Hire')$q$), 'ok', 'positive: location admin A1 can create a person');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_manager_a1')$q$), 1::bigint, 'positive: location admin A1 can remove the manager''s assignment at A1');

-- manager with a people_roles = admin override at A1 (rank 50)
select pg_temp.act_as('postgres');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('loc_a1'), 'people_roles', 'admin')$q$), 'ok', '(setup) grant the manager people_roles = admin at A1');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1')) on conflict do nothing$q$), 'ok', '(setup) the manager''s own assignment is back');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), 'ok', 'positive: manager with the override can give staff at A1 (rank 10 < 50)');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('role_custom_a'), pg_temp.id('loc_a1'))$q$), 'ok', 'positive: manager with the override can also give a custom role of rank 30');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'manager with the override cannot grant manager (not below their own rank)');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.sys_role('admin'), pg_temp.id('loc_a1'))$q$), '42501', 'manager with the override cannot grant admin');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.sys_role('admin'), null)$q$), '42501', 'manager with the override cannot grant org admin');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.sys_role('staff'), pg_temp.id('loc_a2'))$q$), '42501', 'manager with the override cannot grant at A2');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_locadmin_a1')$q$), 0::bigint, 'manager with the override cannot remove a higher-ranked person''s assignment');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('role_custom_a'), pg_temp.id('loc_a1'))$q$), '42501', 'manager with the override cannot grant themselves anything');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), pg_temp.id('loc_a1'), 'tasks', 'view')$q$), '42501', 'manager with the override cannot write an override for someone they cannot see');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('loc_a1'), 'accidents', 'view')$q$), '42501', 'manager cannot grant accidents = view (their own level is none)');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('loc_a1'), 'audit_log', 'view')$q$), '42501', 'manager cannot grant audit_log = view (their own level is none)');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('loc_a1'), 'reports', 'edit')$q$), '42501', 'manager cannot grant reports = edit (their own level is view)');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('loc_a1'), 'reports', 'view')$q$), 'ok', 'positive: manager can grant reports = view (their own level)');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_t1'), pg_temp.id('loc_a1'), 'tasks', 'admin')$q$), 'ok', 'positive: manager can grant tasks = admin (their own level is admin)');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('loc_a1'), 'accidents', 'admin')$q$), '42501', 'manager cannot raise their own permissions');
select is(pg_temp.affected($q$update public.user_permissions set level = 'admin' where person_id = pg_temp.id('p_manager_a1') and module_key = 'people_roles'$q$), 0::bigint, 'manager cannot change their own override');
select is(pg_temp.affected($q$update public.user_permissions set level = 'admin' where id = pg_temp.id('up_a')$q$), 0::bigint, 'manager cannot change an organization-wide override');
select is(pg_temp.affected($q$update public.people set first_name = 'Sam3' where id = pg_temp.id('p_t1')$q$), 1::bigint, 'positive: manager with the override can edit a lower-ranked A1 person');
select is(pg_temp.affected($q$update public.people set first_name = 'Lou3' where id = pg_temp.id('p_locadmin_a1')$q$), 0::bigint, 'manager with the override cannot edit the location admin');

-- org admin (rank 90)
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t2'), pg_temp.sys_role('admin'), pg_temp.id('loc_a2'))$q$), 'ok', 'positive: org admin A can create a location admin (rank 80 < 90)');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), pg_temp.sys_role('manager'), pg_temp.id('loc_a2'))$q$), 'ok', 'positive: org admin A can promote staff at A2');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t3'), pg_temp.sys_role('admin'), null)$q$), '42501', 'org admin A cannot grant org admin (rank 90 is not below 90)');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.sys_role('admin'), null)$q$), '42501', 'org admin A cannot make an existing person org admin');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_orgadmin2_a')$q$), 0::bigint, 'org admin A cannot remove another org admin');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_orgadmin_a')$q$), 0::bigint, 'org admin A cannot remove their own org-admin assignment');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_orgadmin_a'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'org admin A cannot change their own assignments');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_orgadmin_a'), null, 'audit_log', 'view')$q$), '42501', 'org admin A cannot write an override for themselves');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_orgadmin2_a'), pg_temp.id('loc_a1'), 'tasks', 'view')$q$), '42501', 'org admin A cannot write an override for another org admin');
select is(pg_temp.try($q$insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), pg_temp.id('loc_a2'), 'tasks', 'view')$q$), 'ok', 'positive: org admin A can write an override at A2');
select is(pg_temp.affected($q$update public.people set first_name = 'Olive3' where id = pg_temp.id('p_orgadmin_a')$q$), 0::bigint, 'org admin A cannot edit their own person row');
select is(pg_temp.affected($q$update public.people set first_name = 'Otto3' where id = pg_temp.id('p_orgadmin2_a')$q$), 0::bigint, 'org admin A cannot edit another org admin');
select is(pg_temp.affected($q$update public.accounts set disabled_at = now() where id = pg_temp.id('acct_orgadmin_a')$q$), 0::bigint, 'org admin A cannot disable their own account');
select is(pg_temp.affected($q$update public.accounts set disabled_at = now() where id = pg_temp.id('acct_staff_a2')$q$), 1::bigint, 'positive: org admin A can disable a staff account');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_b1'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'org admin A cannot assign a person of org B');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_locadmin_a1')$q$), 1::bigint, 'positive: org admin A can remove a location admin (rank 80 < 90)');

-- platform admin and service_role may touch org admins
select pg_temp.act_as('u_platform');
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_t3'), pg_temp.sys_role('admin'), null)$q$), 'ok', 'positive: a platform admin can grant org admin');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_orgadmin2_a')$q$), 1::bigint, 'positive: a platform admin can remove an org admin');
select pg_temp.act_as('postgres');
set local role service_role;
select is(pg_temp.try($q$insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.sys_role('admin'), null)$q$), 'ok', 'positive: service_role can grant org admin');
select is(pg_temp.affected($q$delete from public.role_assignments where id = pg_temp.id('ra_orgadmin_a')$q$), 1::bigint, 'positive: service_role can remove an org admin');
select pg_temp.act_as('postgres');

select * from finish();
rollback;
