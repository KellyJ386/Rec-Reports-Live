-- Helper functions per role, membership rules, and anon denial (docs/SECURITY.md
-- "Membership", "Effective permission", "Helper functions").
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(
  118
  + 8 * (select count(*)::int from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p'))
);

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

-- Extra users for the membership edge cases, all in org A:
--   u_noassign: active account, no role assignment, plus a people_roles=admin override (grants nothing)
--   u_arch_person: staff @A1 but the person is archived
--   u_arch_role: staff @A1 through a custom role that is then archived
--   u_arch_loc: staff at a location that is then archived
insert into auth.users (id, email) values
  (pg_temp.id('u_noassign'), 'noassign@test.invalid'), (pg_temp.id('u_arch_person'), 'archperson@test.invalid'),
  (pg_temp.id('u_arch_role'), 'archrole@test.invalid'), (pg_temp.id('u_arch_loc'), 'archloc@test.invalid');
insert into public.people (id, organization_id, first_name, last_name) values
  (pg_temp.id('p_noassign'), pg_temp.id('org_a'), 'No', 'Assign'), (pg_temp.id('p_arch_person'), pg_temp.id('org_a'), 'Arch', 'Person'),
  (pg_temp.id('p_arch_role'), pg_temp.id('org_a'), 'Arch', 'Role'), (pg_temp.id('p_arch_loc'), pg_temp.id('org_a'), 'Arch', 'Loc');
insert into public.accounts (id, organization_id, person_id, user_id) values
  (pg_temp.id('acct_noassign'), pg_temp.id('org_a'), pg_temp.id('p_noassign'), pg_temp.id('u_noassign')),
  (pg_temp.id('acct_arch_person'), pg_temp.id('org_a'), pg_temp.id('p_arch_person'), pg_temp.id('u_arch_person')),
  (pg_temp.id('acct_arch_role'), pg_temp.id('org_a'), pg_temp.id('p_arch_role'), pg_temp.id('u_arch_role')),
  (pg_temp.id('acct_arch_loc'), pg_temp.id('org_a'), pg_temp.id('p_arch_loc'), pg_temp.id('u_arch_loc'));
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level)
values (pg_temp.id('org_a'), pg_temp.id('p_noassign'), null, 'people_roles', 'admin');
insert into public.roles (id, organization_id, key, name, rank) values
  (pg_temp.id('role_tmp_a'), pg_temp.id('org_a'), 'temp', 'Temp', 20);
insert into public.locations (id, organization_id, name, timezone) values
  (pg_temp.id('loc_a3'), pg_temp.id('org_a'), 'A3 Annex', 'America/New_York');
insert into public.role_assignments (organization_id, person_id, role_id, location_id) values
  (pg_temp.id('org_a'), pg_temp.id('p_arch_person'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1')),
  (pg_temp.id('org_a'), pg_temp.id('p_arch_role'), pg_temp.id('role_tmp_a'), pg_temp.id('loc_a1')),
  (pg_temp.id('org_a'), pg_temp.id('p_arch_loc'), pg_temp.sys_role('staff'), pg_temp.id('loc_a3'));
update public.people set archived_at = now() where id = pg_temp.id('p_arch_person');
update public.roles set archived_at = now() where id = pg_temp.id('role_tmp_a');
update public.locations set archived_at = now() where id = pg_temp.id('loc_a3');
-- Overrides for the manager at A1: a location row lowers a default, and beats an org-wide row.
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values
  (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('loc_a1'), 'tasks', 'view'),
  (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), null, 'documents', 'admin'),
  (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('loc_a1'), 'documents', 'view');

-- ===========================================================================
-- Positive paths: what each role gets from the helpers
-- ===========================================================================
select pg_temp.act_as('u_orgadmin_a');
select set_eq($$select public.auth_org_ids()$$, $$select pg_temp.id('org_a')$$, 'org admin A: auth_org_ids = {A}');
select set_eq($$select public.auth_location_ids()$$, $$values (pg_temp.id('loc_a1')), (pg_temp.id('loc_a2')), (pg_temp.id('loc_a3'))$$,
  'org admin A: auth_location_ids = every location of A (incl. archived)');
select is(public.current_person_id(pg_temp.id('org_a')), pg_temp.id('p_orgadmin_a'), 'org admin A: current_person_id(A) is their person');
select is(public.current_person_id(pg_temp.id('org_b')), null, 'org admin A: current_person_id(B) is null');
select ok(public.has_role(pg_temp.id('org_a'), null, 'admin') and public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'admin'),
  'org admin A: has admin at org scope and at A1');
select ok(not public.has_role(pg_temp.id('org_b'), null, 'admin') and not public.has_role(pg_temp.id('org_a'), null, 'manager'),
  'org admin A: no admin in B, no manager role in A');
select is(public.actor_rank(pg_temp.id('org_a'), null), 90, 'org admin A: rank 90 at org scope');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a2')), 90, 'org admin A: rank 90 at A2 too');
select is(public.actor_rank(pg_temp.id('org_b'), null), 0, 'org admin A: rank 0 in B');
select is(public.effective_permission(pg_temp.id('org_a'), null, 'people_roles'), 'admin', 'org admin A: people_roles = admin at org scope');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'audit_log'), 'admin', 'org admin A: audit_log = admin at A1');
select is(public.effective_permission(pg_temp.id('org_b'), null, 'people_roles'), 'none', 'org admin A: people_roles = none in B');
select ok(not public.is_platform_admin(), 'org admin A: not a platform admin');

select pg_temp.act_as('u_locadmin_a1');
select set_eq($$select public.auth_org_ids()$$, $$select pg_temp.id('org_a')$$, 'location admin A1: auth_org_ids = {A}');
select set_eq($$select public.auth_location_ids()$$, $$select pg_temp.id('loc_a1')$$, 'location admin A1: auth_location_ids = {A1}');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')), 80, 'location admin A1: rank 80 at A1');
select is(public.actor_rank(pg_temp.id('org_a'), null), 0, 'location admin A1: rank 0 at org scope');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a2')), 0, 'location admin A1: rank 0 at A2');
select ok(public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'admin')
          and not public.has_role(pg_temp.id('org_a'), null, 'admin')
          and not public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'admin'),
  'location admin A1: admin at A1 only, not at org scope or A2');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles'), 'admin', 'location admin A1: people_roles = admin at A1');
select is(public.effective_permission(pg_temp.id('org_a'), null, 'people_roles'), 'none', 'location admin A1: people_roles = none at org scope');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'people_roles'), 'none', 'location admin A1: people_roles = none at A2');

select pg_temp.act_as('u_manager_a1');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')), 50, 'manager A1: rank 50');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'locations_spaces'), 'edit', 'manager A1: locations_spaces = edit');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles'), 'edit', 'manager A1: people_roles = edit (job titles only)');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'audit_log'), 'none', 'manager A1: audit_log = none');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'accidents'), 'none', 'manager A1: accidents = none');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'locations_spaces'), 'none', 'manager A1: nothing at A2');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks'), 'view', 'override: a location row lowers the role default (admin -> view)');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'documents'), 'view', 'override: the location row beats the org-wide row');
select ok(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles', 'edit')
          and not public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles', 'admin'),
  'manager A1: has_permission edit yes, admin no');

select pg_temp.act_as('u_staff_a1');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')), 10, 'staff A1: rank 10');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'locations_spaces'), 'view', 'staff A1: locations_spaces = view');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'incidents'), 'edit', 'staff A1: incidents = edit');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles'), 'none', 'staff A1: people_roles = none');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'reports'), 'view', 'override: an org-wide row raises the default (none -> view)');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'reports'), 'none', 'override: no assignment at A2, so the org-wide override grants nothing there');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'locations_spaces'), 'none', 'staff A1: nothing at A2');

select pg_temp.act_as('u_staff_a2');
select set_eq($$select public.auth_location_ids()$$, $$select pg_temp.id('loc_a2')$$, 'staff A2: auth_location_ids = {A2}');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')), 0, 'staff A2: rank 0 at A1');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'locations_spaces'), 'view', 'staff A2: locations_spaces = view at A2');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'locations_spaces'), 'none', 'staff A2: none at A1');

select pg_temp.act_as('u_orgadmin_b');
select set_eq($$select public.auth_org_ids()$$, $$select pg_temp.id('org_b')$$, 'org admin B: auth_org_ids = {B}');
select set_eq($$select public.auth_location_ids()$$, $$select pg_temp.id('loc_b1')$$, 'org admin B: auth_location_ids = {B1}');
select is(public.actor_rank(pg_temp.id('org_a'), null), 0, 'org admin B: rank 0 in A');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'locations_spaces'), 'none', 'org admin B: nothing in A');
select ok(not public.has_role(pg_temp.id('org_a'), null, 'admin'), 'org admin B: not admin in A');

select pg_temp.act_as('u_platform');
select ok(public.is_platform_admin(), 'platform admin: is_platform_admin');
select ok((select array_agg(x) from public.auth_org_ids() x) @> array[pg_temp.id('org_a'), pg_temp.id('org_b')], 'platform admin: auth_org_ids includes A and B');
select ok((select array_agg(x) from public.auth_location_ids() x) @> array[pg_temp.id('loc_a1'), pg_temp.id('loc_a2'), pg_temp.id('loc_b1')],
  'platform admin: auth_location_ids includes A1, A2, B1');
select is(public.actor_rank(pg_temp.id('org_b'), null), 100, 'platform admin: rank 100');
select is(public.effective_permission(pg_temp.id('org_b'), null, 'audit_log'), 'admin', 'platform admin: admin on every module');
select ok(public.has_role(pg_temp.id('org_a'), null, 'staff'), 'platform admin: has_role is true everywhere');

select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from private.visible_person_ids() v join public.people p on p.id = v) , 11::bigint,
  'org admin A: visible_person_ids = all 11 people of A');
select is((select count(*) from private.visible_person_ids() v join public.people p on p.id = v where p.organization_id = pg_temp.id('org_b')), 0::bigint,
  'org admin A: visible_person_ids has nobody from B');

-- ===========================================================================
-- Members with no standing: not a member, so nothing from any helper
-- ===========================================================================

select pg_temp.act_as('u_noaccount');
select ok(not exists (select 1 from public.auth_org_ids()), 'u_noaccount (signed in with no account): auth_org_ids is empty');
select ok(not exists (select 1 from public.auth_location_ids()), 'u_noaccount: auth_location_ids is empty');
select ok(not public.has_role(pg_temp.id('org_a'), null, 'admin') and not public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff'),
  'u_noaccount: has_role is false');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')), 0, 'u_noaccount: actor_rank is 0');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles'), 'none', 'u_noaccount: effective_permission is none (an override alone grants nothing)');
select ok(not public.has_permission(pg_temp.id('org_a'), null, 'people_roles', 'view'), 'u_noaccount: has_permission is false');
select ok(not exists (select 1 from private.visible_person_ids()) and not exists (select 1 from private.people_admin_person_ids())
          and not exists (select 1 from private.permitted_org_ids('people_roles', 'view')) and not exists (select 1 from private.permitted_location_ids('people_roles', 'view')),
  'u_noaccount: the private policy helpers return nothing');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 2, '08:00', '09:00')$q$), '42501', 'u_noaccount: cannot write');
select cmp_ok(pg_temp.cnt(c.relname), '<=', 0::bigint, 'u_noaccount sees no rows in ' || c.relname) from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') order by c.relname;
select is(public.current_person_id(pg_temp.id('org_a')), null, 'u_noaccount: current_person_id is null');

select pg_temp.act_as('u_disabled_a');
select ok(not exists (select 1 from public.auth_org_ids()), 'u_disabled_a (disabled account): auth_org_ids is empty');
select ok(not exists (select 1 from public.auth_location_ids()), 'u_disabled_a: auth_location_ids is empty');
select ok(not public.has_role(pg_temp.id('org_a'), null, 'admin') and not public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff'),
  'u_disabled_a: has_role is false');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')), 0, 'u_disabled_a: actor_rank is 0');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles'), 'none', 'u_disabled_a: effective_permission is none (an override alone grants nothing)');
select ok(not public.has_permission(pg_temp.id('org_a'), null, 'people_roles', 'view'), 'u_disabled_a: has_permission is false');
select ok(not exists (select 1 from private.visible_person_ids()) and not exists (select 1 from private.people_admin_person_ids())
          and not exists (select 1 from private.permitted_org_ids('people_roles', 'view')) and not exists (select 1 from private.permitted_location_ids('people_roles', 'view')),
  'u_disabled_a: the private policy helpers return nothing');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 2, '08:00', '09:00')$q$), '42501', 'u_disabled_a: cannot write');
select cmp_ok(pg_temp.cnt(c.relname), '<=', 0::bigint, 'u_disabled_a sees no rows in ' || c.relname) from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') order by c.relname;
select is(public.current_person_id(pg_temp.id('org_a')), null, 'u_disabled_a: current_person_id is null');

select pg_temp.act_as('u_noassign');
select ok(not exists (select 1 from public.auth_org_ids()), 'u_noassign (active account, no role assignment (only a people_roles=admin override)): auth_org_ids is empty');
select ok(not exists (select 1 from public.auth_location_ids()), 'u_noassign: auth_location_ids is empty');
select ok(not public.has_role(pg_temp.id('org_a'), null, 'admin') and not public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff'),
  'u_noassign: has_role is false');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')), 0, 'u_noassign: actor_rank is 0');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles'), 'none', 'u_noassign: effective_permission is none (an override alone grants nothing)');
select ok(not public.has_permission(pg_temp.id('org_a'), null, 'people_roles', 'view'), 'u_noassign: has_permission is false');
select ok(not exists (select 1 from private.visible_person_ids()) and not exists (select 1 from private.people_admin_person_ids())
          and not exists (select 1 from private.permitted_org_ids('people_roles', 'view')) and not exists (select 1 from private.permitted_location_ids('people_roles', 'view')),
  'u_noassign: the private policy helpers return nothing');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 2, '08:00', '09:00')$q$), '42501', 'u_noassign: cannot write');
select cmp_ok(pg_temp.cnt(c.relname), '<=', 0::bigint, 'u_noassign sees no rows in ' || c.relname) from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') order by c.relname;

select pg_temp.act_as('u_arch_person');
select ok(not exists (select 1 from public.auth_org_ids()), 'u_arch_person (archived person): auth_org_ids is empty');
select ok(not exists (select 1 from public.auth_location_ids()), 'u_arch_person: auth_location_ids is empty');
select ok(not public.has_role(pg_temp.id('org_a'), null, 'admin') and not public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff'),
  'u_arch_person: has_role is false');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')), 0, 'u_arch_person: actor_rank is 0');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles'), 'none', 'u_arch_person: effective_permission is none (an override alone grants nothing)');
select ok(not public.has_permission(pg_temp.id('org_a'), null, 'people_roles', 'view'), 'u_arch_person: has_permission is false');
select ok(not exists (select 1 from private.visible_person_ids()) and not exists (select 1 from private.people_admin_person_ids())
          and not exists (select 1 from private.permitted_org_ids('people_roles', 'view')) and not exists (select 1 from private.permitted_location_ids('people_roles', 'view')),
  'u_arch_person: the private policy helpers return nothing');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 2, '08:00', '09:00')$q$), '42501', 'u_arch_person: cannot write');
select cmp_ok(pg_temp.cnt(c.relname), '<=', 0::bigint, 'u_arch_person sees no rows in ' || c.relname) from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') order by c.relname;
select is(public.current_person_id(pg_temp.id('org_a')), null, 'u_arch_person: current_person_id is null');

select pg_temp.act_as('u_arch_role');
select ok(not exists (select 1 from public.auth_org_ids()), 'u_arch_role (assignment on an archived role): auth_org_ids is empty');
select ok(not exists (select 1 from public.auth_location_ids()), 'u_arch_role: auth_location_ids is empty');
select ok(not public.has_role(pg_temp.id('org_a'), null, 'admin') and not public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff'),
  'u_arch_role: has_role is false');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')), 0, 'u_arch_role: actor_rank is 0');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles'), 'none', 'u_arch_role: effective_permission is none (an override alone grants nothing)');
select ok(not public.has_permission(pg_temp.id('org_a'), null, 'people_roles', 'view'), 'u_arch_role: has_permission is false');
select ok(not exists (select 1 from private.visible_person_ids()) and not exists (select 1 from private.people_admin_person_ids())
          and not exists (select 1 from private.permitted_org_ids('people_roles', 'view')) and not exists (select 1 from private.permitted_location_ids('people_roles', 'view')),
  'u_arch_role: the private policy helpers return nothing');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 2, '08:00', '09:00')$q$), '42501', 'u_arch_role: cannot write');
select cmp_ok(pg_temp.cnt(c.relname), '<=', 0::bigint, 'u_arch_role sees no rows in ' || c.relname) from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') order by c.relname;

select pg_temp.act_as('u_arch_loc');
select ok(not exists (select 1 from public.auth_org_ids()), 'u_arch_loc (assignment at an archived location): auth_org_ids is empty');
select ok(not exists (select 1 from public.auth_location_ids()), 'u_arch_loc: auth_location_ids is empty');
select ok(not public.has_role(pg_temp.id('org_a'), null, 'admin') and not public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff'),
  'u_arch_loc: has_role is false');
select is(public.actor_rank(pg_temp.id('org_a'), pg_temp.id('loc_a1')), 0, 'u_arch_loc: actor_rank is 0');
select is(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'people_roles'), 'none', 'u_arch_loc: effective_permission is none (an override alone grants nothing)');
select ok(not public.has_permission(pg_temp.id('org_a'), null, 'people_roles', 'view'), 'u_arch_loc: has_permission is false');
select ok(not exists (select 1 from private.visible_person_ids()) and not exists (select 1 from private.people_admin_person_ids())
          and not exists (select 1 from private.permitted_org_ids('people_roles', 'view')) and not exists (select 1 from private.permitted_location_ids('people_roles', 'view')),
  'u_arch_loc: the private policy helpers return nothing');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 2, '08:00', '09:00')$q$), '42501', 'u_arch_loc: cannot write');
select cmp_ok(pg_temp.cnt(c.relname), '<=', 0::bigint, 'u_arch_loc sees no rows in ' || c.relname) from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') order by c.relname;

-- ===========================================================================
-- anon: denied on every table and function
-- ===========================================================================
select pg_temp.act_as('anon');
select is(pg_temp.cnt(c.relname), -1::bigint, 'anon: permission denied reading ' || c.relname) from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') order by c.relname;
select is(pg_temp.affected('delete from public.' || quote_ident(c.relname)), -1::bigint, 'anon: permission denied deleting from ' || c.relname) from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') order by c.relname;
select throws_ok($$select public.is_platform_admin()$$, '42501', null, 'anon: is_platform_admin denied');
select throws_ok($$select * from public.auth_org_ids()$$, '42501', null, 'anon: auth_org_ids denied');
select throws_ok($$select * from public.auth_location_ids()$$, '42501', null, 'anon: auth_location_ids denied');
select throws_ok($$select public.current_person_id(pg_temp.id('org_a'))$$, '42501', null, 'anon: current_person_id denied');
select throws_ok($$select public.has_role(pg_temp.id('org_a'), null, 'admin')$$, '42501', null, 'anon: has_role denied');
select throws_ok($$select public.actor_rank(pg_temp.id('org_a'), null)$$, '42501', null, 'anon: actor_rank denied');
select throws_ok($$select public.effective_permission(pg_temp.id('org_a'), null, 'tasks')$$, '42501', null, 'anon: effective_permission denied');
select throws_ok($$select public.has_permission(pg_temp.id('org_a'), null, 'tasks', 'view')$$, '42501', null, 'anon: has_permission denied');
select throws_ok($$select public.create_person_with_assignment(pg_temp.id('org_a'), 'A', 'B', pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$$, '42501', null, 'anon: create_person_with_assignment denied');
select throws_ok($$select public.update_own_profile(pg_temp.id('org_a'), 'x', 'y')$$, '42501', null, 'anon: update_own_profile denied');
select throws_ok($$select * from private.visible_person_ids()$$, '42501', null, 'anon: private helpers denied');
select throws_ok($$select private.can_create_person(pg_temp.id('org_a'))$$, '42501', null, 'anon: private.can_create_person denied');

select pg_temp.act_as('postgres');
select * from finish();
rollback;
