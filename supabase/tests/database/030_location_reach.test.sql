-- Location reach (docs/SECURITY.md "Reads" and "Writes"): location-scoped users see
-- only people and assignments that touch their own locations, and write resources
-- only at locations where they hold locations_spaces >= edit.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(67);

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

-- ===========================================================================
-- Reads: people, assignments, accounts, overrides, job-title links
-- ===========================================================================
select pg_temp.act_as('u_staff_a1');
select set_eq($$select id from public.people where organization_id = pg_temp.id('org_a')$$,
  $$values (pg_temp.id('p_staff_a1')), (pg_temp.id('p_locadmin_a1')), (pg_temp.id('p_manager_a1')), (pg_temp.id('p_disabled_a'))$$,
  'staff A1 sees themselves and people assigned at A1; not the org admin, staff A2 or an unassigned person');
select set_eq($$select private.visible_person_ids()$$,
  $$values (pg_temp.id('p_staff_a1')), (pg_temp.id('p_locadmin_a1')), (pg_temp.id('p_manager_a1')), (pg_temp.id('p_disabled_a'))$$,
  'staff A1: visible_person_ids matches');
select set_eq($$select id from public.role_assignments$$,
  $$values (pg_temp.id('ra_staff_a1')), (pg_temp.id('ra_locadmin_a1')), (pg_temp.id('ra_manager_a1')), (pg_temp.id('ra_disabled_a'))$$,
  'staff A1 sees only assignments of those people (not the org admin''s, not staff A2''s)');
select set_eq($$select id from public.person_job_titles$$, $$select pg_temp.id('pjt_a')$$, 'staff A1 sees job-title links of visible people only');
select set_eq($$select id from public.accounts$$, $$select pg_temp.id('acct_staff_a1')$$, 'staff A1 sees only their own account');
select set_eq($$select id from public.user_permissions$$, $$select pg_temp.id('up_a')$$, 'staff A1 sees only their own overrides');
select set_eq($$select id from public.space_closures where organization_id = pg_temp.id('org_a')$$,
  $$values (pg_temp.id('closure_a1')), (pg_temp.id('closure_a2'))$$, 'positive: every member reads the whole organization''s closures (data class Public)');
select is((select count(*) from public.spaces where organization_id = pg_temp.id('org_a')), 3::bigint, 'positive: staff A1 reads all 3 spaces of org A, including A2''s');
select is((select count(*) from public.locations where organization_id = pg_temp.id('org_a')), 2::bigint, 'positive: staff A1 reads both locations of org A');

select pg_temp.act_as('u_staff_a2');
select set_eq($$select id from public.people where organization_id = pg_temp.id('org_a')$$, $$select pg_temp.id('p_staff_a2')$$,
  'staff A2 sees only themselves (nobody else is assigned at A2)');
select set_eq($$select id from public.role_assignments$$, $$select pg_temp.id('ra_staff_a2')$$, 'staff A2 sees only their own assignment');
select is((select count(*) from public.person_job_titles), 0::bigint, 'staff A2 sees no job-title links (staff A1''s person is invisible)');

select pg_temp.act_as('u_manager_a1');
select set_eq($$select id from public.people where organization_id = pg_temp.id('org_a')$$,
  $$values (pg_temp.id('p_staff_a1')), (pg_temp.id('p_locadmin_a1')), (pg_temp.id('p_manager_a1')), (pg_temp.id('p_disabled_a'))$$,
  'manager A1 sees the A1 people only');
select set_eq($$select id from public.accounts$$, $$select pg_temp.id('acct_manager_a1')$$, 'manager A1 (people_roles = edit) sees only their own account');
select is((select count(*) from public.user_permissions), 0::bigint, 'manager A1 sees no one else''s overrides');

select pg_temp.act_as('u_locadmin_a1');
select set_eq($$select id from public.people where organization_id = pg_temp.id('org_a')$$,
  $$values (pg_temp.id('p_staff_a1')), (pg_temp.id('p_locadmin_a1')), (pg_temp.id('p_manager_a1')), (pg_temp.id('p_disabled_a'))$$,
  'location admin A1 sees the A1 people only');
select set_eq($$select private.people_admin_person_ids()$$,
  $$values (pg_temp.id('p_staff_a1')), (pg_temp.id('p_locadmin_a1')), (pg_temp.id('p_manager_a1')), (pg_temp.id('p_disabled_a'))$$,
  'location admin A1 administers the A1 people only');
select set_eq($$select id from public.accounts$$,
  $$values (pg_temp.id('acct_staff_a1')), (pg_temp.id('acct_locadmin_a1')), (pg_temp.id('acct_manager_a1')), (pg_temp.id('acct_disabled_a'))$$,
  'location admin A1 sees the accounts of A1 people (not the org admin''s or staff A2''s)');
select set_eq($$select id from public.user_permissions$$, $$select pg_temp.id('up_a')$$, 'location admin A1 sees the overrides of A1 people');

select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.people where organization_id = pg_temp.id('org_a')), 7::bigint,
  'org admin A sees all 7 people of org A, including the unassigned one');
select is((select count(*) from public.accounts where organization_id = pg_temp.id('org_a')), 6::bigint, 'org admin A sees all 6 accounts of org A');

-- A person assigned at two locations is reachable from both.
select pg_temp.act_as('postgres');
insert into public.role_assignments (organization_id, person_id, role_id, location_id)
values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'));
select pg_temp.act_as('u_staff_a1');
select ok(exists (select 1 from public.people where id = pg_temp.id('p_staff_a2')),
  'positive: once staff A2 is also assigned at A1, staff A1 can see them');
select pg_temp.act_as('postgres');
delete from public.role_assignments where person_id = pg_temp.id('p_staff_a2') and location_id = pg_temp.id('loc_a1');

-- ===========================================================================
-- Writes: spaces, hours, closures, space kinds, locations
-- ===========================================================================
-- manager A1 (locations_spaces = edit at A1)
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try($q$insert into public.spaces (organization_id, location_id, space_kind_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), (select id from public.space_kinds where organization_id = pg_temp.id('org_a') and key = 'pool'), 'Manager A1 Space')$q$),
  'ok', 'positive: manager A1 can create a space at A1');
select is(pg_temp.try($q$insert into public.spaces (organization_id, location_id, space_kind_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a2'), (select id from public.space_kinds where organization_id = pg_temp.id('org_a') and key = 'pool'), 'Manager A1 Space')$q$),
  '42501', 'manager A1 cannot create a space at A2');
select is(pg_temp.affected($q$update public.spaces set name = 'Renamed by manager' where id = pg_temp.id('space_a1')$q$), 1::bigint, 'positive: manager A1 can rename a space at A1');
select is(pg_temp.affected($q$update public.spaces set name = 'Renamed by manager' where id = pg_temp.id('space_a2')$q$), 0::bigint, 'manager A1 cannot rename a space at A2');
select is(pg_temp.try($q$update public.spaces set location_id = pg_temp.id('loc_a2') where id = pg_temp.id('space_a1')$q$), '42501',
  'manager A1 cannot move a space to A2 (location_id is not updatable)');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 2, '08:00', '09:00')$q$), 'ok', 'positive: manager A1 can add hours at A1');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a2'), pg_temp.id('space_a2'), 2, '08:00', '09:00')$q$), '42501', 'manager A1 cannot add hours at A2');
select is(pg_temp.affected($q$update public.space_hours set opens_at = '07:00' where id = pg_temp.id('hours_a1')$q$), 1::bigint, 'positive: manager A1 can change hours at A1');
select is(pg_temp.affected($q$update public.space_hours set opens_at = '07:00' where id = pg_temp.id('hours_a2')$q$), 0::bigint, 'manager A1 cannot change hours at A2');
select is(pg_temp.affected($q$delete from public.space_hours where id = pg_temp.id('hours_a2')$q$), 0::bigint, 'manager A1 cannot delete hours at A2');
select is(pg_temp.affected($q$delete from public.space_hours where id = pg_temp.id('hours_a1')$q$), 1::bigint, 'positive: manager A1 can delete hours at A1');
select is(pg_temp.try($q$insert into public.space_closures (organization_id, location_id, space_id, starts_at, ends_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), null, '2031-01-01', '2031-01-02')$q$), 'ok', 'positive: manager A1 can close A1');
select is(pg_temp.try($q$insert into public.space_closures (organization_id, location_id, space_id, starts_at, ends_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a2'), null, '2031-01-01', '2031-01-02')$q$), '42501', 'manager A1 cannot close A2');
select is(pg_temp.affected($q$update public.space_closures set reason = 'x' where id = pg_temp.id('closure_a2')$q$), 0::bigint, 'manager A1 cannot change a closure at A2');
select is(pg_temp.affected($q$delete from public.space_closures where id = pg_temp.id('closure_a2')$q$), 0::bigint, 'manager A1 cannot delete a closure at A2');
select is(pg_temp.affected($q$delete from public.space_closures where id = pg_temp.id('closure_a1')$q$), 1::bigint, 'positive: manager A1 can delete a closure at A1');
-- Composite key: a row in A1 cannot point at A2's space even for someone allowed to write at A1 (foreign key, not RLS)
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a2'), 3, '08:00', '09:00')$q$), '23503',
  'manager A1: hours at A1 cannot reference a space of A2 (composite foreign key)');
select is(pg_temp.try($q$insert into public.space_kinds (organization_id, key, name) values (pg_temp.id('org_a'), 'mgr_kind', 'Mgr')$q$), '42501',
  'manager A1 cannot create space kinds (needs locations_spaces >= edit at organization scope)');
select is(pg_temp.try($q$insert into public.locations (organization_id, name, timezone) values (pg_temp.id('org_a'), 'Mgr Loc', 'UTC')$q$), '42501',
  'manager A1 cannot create locations');
select is(pg_temp.affected($q$update public.locations set name = 'Renamed' where id = pg_temp.id('loc_a1')$q$), 0::bigint, 'manager A1 cannot rename their own location (needs admin)');
select is(pg_temp.try($q$insert into public.job_titles (organization_id, name) values (pg_temp.id('org_a'), 'Mgr Title')$q$), '42501', 'manager A1 cannot create job titles (org-scope admin only)');
-- job-title links: people_roles >= edit in scope, person visible
select is(pg_temp.try($q$insert into public.person_job_titles (organization_id, person_id, job_title_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('jt_a'), pg_temp.id('loc_a1'))$q$), 'ok',
  'positive: manager A1 (people_roles = edit) can give a job title at A1');
select is(pg_temp.try($q$insert into public.person_job_titles (organization_id, person_id, job_title_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), pg_temp.id('jt_a'), pg_temp.id('loc_a2'))$q$), '42501', 'manager A1 cannot give a job title at A2');
select is(pg_temp.try($q$insert into public.person_job_titles (organization_id, person_id, job_title_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), pg_temp.id('jt_a'), pg_temp.id('loc_a1'))$q$), '42501',
  'manager A1 cannot give a job title to someone they cannot see (staff A2, only at A2)');
select is(pg_temp.try($q$insert into public.person_job_titles (organization_id, person_id, job_title_id, location_id)
  values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('jt_a'), null)$q$), '42501',
  'manager A1 cannot give an organization-wide job title (needs people_roles >= edit at org scope)');
select is(pg_temp.affected($q$delete from public.person_job_titles where id = pg_temp.id('pjt_a')$q$), 0::bigint, 'manager A1 cannot remove an organization-wide job-title link');
select is(pg_temp.affected($q$delete from public.person_job_titles where person_id = pg_temp.id('p_manager_a1') and location_id = pg_temp.id('loc_a1')$q$), 1::bigint,
  'positive: manager A1 can remove a job-title link at A1');

-- location admin A1 (admin at A1)
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try($q$insert into public.spaces (organization_id, location_id, space_kind_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), (select id from public.space_kinds where organization_id = pg_temp.id('org_a') and key = 'pool'), 'LocAdmin A1 Space')$q$),
  'ok', 'positive: location admin A1 can create a space at A1');
select is(pg_temp.try($q$insert into public.spaces (organization_id, location_id, space_kind_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a2'), (select id from public.space_kinds where organization_id = pg_temp.id('org_a') and key = 'pool'), 'LocAdmin A2 Space')$q$),
  '42501', 'location admin A1 cannot create a space at A2');
select is(pg_temp.affected($q$update public.locations set name = 'A1 Renamed' where id = pg_temp.id('loc_a1')$q$), 1::bigint, 'positive: location admin A1 can rename A1');
select is(pg_temp.affected($q$update public.locations set name = 'A2 Renamed' where id = pg_temp.id('loc_a2')$q$), 0::bigint, 'location admin A1 cannot rename A2');
select is(pg_temp.try($q$insert into public.locations (organization_id, name, timezone) values (pg_temp.id('org_a'), 'LocAdmin Loc', 'UTC')$q$), '42501',
  'location admin A1 cannot create a location (org-scope admin only)');
select is(pg_temp.try($q$insert into public.space_kinds (organization_id, key, name) values (pg_temp.id('org_a'), 'loc_kind', 'LK')$q$), '42501',
  'location admin A1 cannot create space kinds (organization scope)');
select is(pg_temp.try($q$insert into public.job_titles (organization_id, name) values (pg_temp.id('org_a'), 'LocAdmin Title')$q$), '42501',
  'location admin A1 cannot create job titles');
select is(pg_temp.affected($q$update public.organization_settings set week_starts_on = 1 where organization_id = pg_temp.id('org_a')$q$), 0::bigint,
  'location admin A1 cannot change organization settings');
select is(pg_temp.affected($q$update public.organizations set name = 'Hijacked' where id = pg_temp.id('org_a')$q$), 0::bigint, 'location admin A1 cannot rename the organization');

-- staff: view only
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try($q$insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a1'), 4, '08:00', '09:00')$q$), '42501', 'staff A1 cannot add hours even at A1 (view only)');
select is(pg_temp.affected($q$update public.spaces set name = 'Staff rename' where id = pg_temp.id('space_a1')$q$), 0::bigint, 'staff A1 cannot rename a space at A1');
select is(pg_temp.affected($q$delete from public.space_closures where id = pg_temp.id('closure_a1')$q$), 0::bigint, 'staff A1 cannot delete a closure at A1');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.try($q$insert into public.space_closures (organization_id, location_id, space_id, starts_at, ends_at)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), null, '2031-02-01', '2031-02-02')$q$), '42501', 'staff A2 cannot close A1');

-- org admin and platform admin reach every location
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($q$insert into public.spaces (organization_id, location_id, space_kind_id, name)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a2'), (select id from public.space_kinds where organization_id = pg_temp.id('org_a') and key = 'pool'), 'OrgAdmin A2 Space')$q$),
  'ok', 'positive: org admin A can create a space at A2');
select is(pg_temp.try($q$insert into public.locations (organization_id, name, timezone) values (pg_temp.id('org_a'), 'OrgAdmin Loc', 'UTC')$q$), 'ok', 'positive: org admin A can create a location');
select is(pg_temp.try($q$insert into public.space_kinds (organization_id, key, name) values (pg_temp.id('org_a'), 'oa_kind', 'OA')$q$), 'ok', 'positive: org admin A can create a space kind');
select is(pg_temp.try($q$insert into public.job_titles (organization_id, name) values (pg_temp.id('org_a'), 'OrgAdmin Title')$q$), 'ok', 'positive: org admin A can create a job title');
select pg_temp.act_as('u_platform');
select is(pg_temp.try($q$insert into public.spaces (organization_id, location_id, space_kind_id, name)
  values (pg_temp.id('org_b'), pg_temp.id('loc_b1'), (select id from public.space_kinds where organization_id = pg_temp.id('org_b') and key = 'pool'), 'Platform B1 Space')$q$),
  'ok', 'positive: a platform admin can write at any location');

select pg_temp.act_as('postgres');
select * from finish();
rollback;
