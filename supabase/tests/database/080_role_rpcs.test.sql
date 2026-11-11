-- public.person_effective_permission and public.replace_role_assignment (migration 20261111000600).
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(55);

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

create function pg_temp.try_msg(p_sql text) returns text language plpgsql as $f$
declare m text; d text; st text;
begin
  execute p_sql;
  return 'ok';
exception when others then
  get stacked diagnostics m = message_text, d = pg_exception_detail, st = returned_sqlstate;
  return st || ': ' || m || ' | ' || coalesce(d, '');
end $f$;
grant execute on function pg_temp.try_msg(text) to public;

-- Setup
insert into auth.users (id, email) values
  (pg_temp.id('u_arch_person'), 'archperson@test.invalid'), (pg_temp.id('u_arch_loc'), 'archloc@test.invalid');
insert into public.locations (id, organization_id, name, timezone) values
  (pg_temp.id('loc_a3'), pg_temp.id('org_a'), 'A3 Annex', 'America/New_York');
insert into public.people (id, organization_id, first_name, last_name) values
  (pg_temp.id('p_arch_person'), pg_temp.id('org_a'), 'Arch', 'Person'), (pg_temp.id('p_arch_loc'), pg_temp.id('org_a'), 'Arch', 'Loc'),
  (pg_temp.id('p_t2'), pg_temp.id('org_a'), 'Tee', 'Two'), (pg_temp.id('p_t4'), pg_temp.id('org_a'), 'Tee', 'Four'),
  (pg_temp.id('p_la2'), pg_temp.id('org_a'), 'Lou', 'Second'),
  (pg_temp.id('p_t6'), pg_temp.id('org_a'), 'Tee', 'Six'), (pg_temp.id('p_t7'), pg_temp.id('org_a'), 'Tee', 'Seven');
insert into public.accounts (organization_id, person_id, user_id) values
  (pg_temp.id('org_a'), pg_temp.id('p_arch_person'), pg_temp.id('u_arch_person')),
  (pg_temp.id('org_a'), pg_temp.id('p_arch_loc'), pg_temp.id('u_arch_loc'));
insert into public.role_assignments (id, organization_id, person_id, role_id, location_id) values
  (pg_temp.id('ra_arch_person'), pg_temp.id('org_a'), pg_temp.id('p_arch_person'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1')),
  (pg_temp.id('ra_arch_loc'), pg_temp.id('org_a'), pg_temp.id('p_arch_loc'), pg_temp.sys_role('staff'), pg_temp.id('loc_a3')),
  (pg_temp.id('ra_t2'), pg_temp.id('org_a'), pg_temp.id('p_t2'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1')),
  (pg_temp.id('ra_t4a'), pg_temp.id('org_a'), pg_temp.id('p_t4'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1')),
  (pg_temp.id('ra_t4b'), pg_temp.id('org_a'), pg_temp.id('p_t4'), pg_temp.id('role_custom_a'), pg_temp.id('loc_a1')),
  (pg_temp.id('ra_t6'), pg_temp.id('org_a'), pg_temp.id('p_t6'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1')),
  (pg_temp.id('ra_t7'), pg_temp.id('org_a'), pg_temp.id('p_t7'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1')),
  (pg_temp.id('ra_la2'), pg_temp.id('org_a'), pg_temp.id('p_la2'), pg_temp.sys_role('admin'), pg_temp.id('loc_a1'));
update public.people set archived_at = now() where id = pg_temp.id('p_arch_person');
update public.locations set archived_at = now() where id = pg_temp.id('loc_a3');
-- overrides so the comparison is not just role defaults: a location row lowering the manager's tasks, an org-wide raise for the location admin
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values
  (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('loc_a1'), 'tasks', 'view'),
  (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), null, 'accidents', 'edit'),
  (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'incidents', 'none');

-- ===========================================================================
-- person_effective_permission
-- ===========================================================================
-- What each person sees for themselves, for every module and scope (null, A1, A2, A3 archived).
create function pg_temp.module_keys() returns setof text language sql stable security definer set search_path = '' as $$ select key from public.modules $$;
grant execute on function pg_temp.module_keys() to public;
create temp table self_levels (actor text, loc uuid, module_key text, lvl public.permission_level);
grant all on self_levels to public;
select pg_temp.act_as('u_orgadmin_a');
insert into self_levels select 'u_orgadmin_a', v.l, m.key, public.effective_permission(pg_temp.id('org_a'), v.l, m.key)
from pg_temp.module_keys() m (key), (values (null::uuid), (pg_temp.id('loc_a1')), (pg_temp.id('loc_a2')), (pg_temp.id('loc_a3'))) v (l);
select pg_temp.act_as('u_locadmin_a1');
insert into self_levels select 'u_locadmin_a1', v.l, m.key, public.effective_permission(pg_temp.id('org_a'), v.l, m.key)
from pg_temp.module_keys() m (key), (values (null::uuid), (pg_temp.id('loc_a1')), (pg_temp.id('loc_a2')), (pg_temp.id('loc_a3'))) v (l);
select pg_temp.act_as('u_manager_a1');
insert into self_levels select 'u_manager_a1', v.l, m.key, public.effective_permission(pg_temp.id('org_a'), v.l, m.key)
from pg_temp.module_keys() m (key), (values (null::uuid), (pg_temp.id('loc_a1')), (pg_temp.id('loc_a2')), (pg_temp.id('loc_a3'))) v (l);
select pg_temp.act_as('u_staff_a1');
insert into self_levels select 'u_staff_a1', v.l, m.key, public.effective_permission(pg_temp.id('org_a'), v.l, m.key)
from pg_temp.module_keys() m (key), (values (null::uuid), (pg_temp.id('loc_a1')), (pg_temp.id('loc_a2')), (pg_temp.id('loc_a3'))) v (l);
select pg_temp.act_as('u_staff_a2');
insert into self_levels select 'u_staff_a2', v.l, m.key, public.effective_permission(pg_temp.id('org_a'), v.l, m.key)
from pg_temp.module_keys() m (key), (values (null::uuid), (pg_temp.id('loc_a1')), (pg_temp.id('loc_a2')), (pg_temp.id('loc_a3'))) v (l);
select pg_temp.act_as('u_disabled_a');
insert into self_levels select 'u_disabled_a', v.l, m.key, public.effective_permission(pg_temp.id('org_a'), v.l, m.key)
from pg_temp.module_keys() m (key), (values (null::uuid), (pg_temp.id('loc_a1')), (pg_temp.id('loc_a2')), (pg_temp.id('loc_a3'))) v (l);
select pg_temp.act_as('u_arch_person');
insert into self_levels select 'u_arch_person', v.l, m.key, public.effective_permission(pg_temp.id('org_a'), v.l, m.key)
from pg_temp.module_keys() m (key), (values (null::uuid), (pg_temp.id('loc_a1')), (pg_temp.id('loc_a2')), (pg_temp.id('loc_a3'))) v (l);
select pg_temp.act_as('u_arch_loc');
insert into self_levels select 'u_arch_loc', v.l, m.key, public.effective_permission(pg_temp.id('org_a'), v.l, m.key)
from pg_temp.module_keys() m (key), (values (null::uuid), (pg_temp.id('loc_a1')), (pg_temp.id('loc_a2')), (pg_temp.id('loc_a3'))) v (l);
select pg_temp.act_as('postgres');
select cmp_ok((select count(*) from self_levels), '>=', 8 * 22 * 4::bigint, '(setup) the self-computed levels cover 8 people x 22 modules x 4 scopes');
select cmp_ok((select count(distinct lvl) from self_levels), '>=', 3::bigint, '(setup) and they are not all the same level (admin, edit, view, none are in play)');
-- as the org admin: the RPC agrees with every person's own answer
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from self_levels s
           where public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id(replace(s.actor, 'u_', 'p_')), s.loc, s.module_key) is distinct from s.lvl), 0::bigint,
  'org admin A: person_effective_permission matches each person''s own effective_permission for every module and scope (8 people, 22 modules, 4 scopes)');
-- as a platform admin
select pg_temp.act_as('u_platform');
select is((select count(*) from self_levels s
           where public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id(replace(s.actor, 'u_', 'p_')), s.loc, s.module_key) is distinct from s.lvl), 0::bigint,
  'platform admin: the same answers');
-- as a location admin, for the people at A1 and the A1 scope
select pg_temp.act_as('u_locadmin_a1');
select is((select count(*) from self_levels s
           where s.actor in ('u_staff_a1', 'u_manager_a1', 'u_disabled_a', 'u_arch_person') and s.loc = pg_temp.id('loc_a1')
             and public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id(replace(s.actor, 'u_', 'p_')), s.loc, s.module_key) is distinct from s.lvl), 0::bigint,
  'location admin A1: the same answers for the people assigned at A1');
select is(public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('loc_a1'), 'tasks'), 'view', 'a location override is reflected (manager tasks lowered to view)');
select is(public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'tasks'), 'edit', 'and a role default (staff tasks = edit)');
select is(public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'incidents'), 'none', 'and an override that lowers to none');
-- none for people who are not members in that scope
select pg_temp.act_as('u_orgadmin_a');
select is(public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_arch_person'), pg_temp.id('loc_a1'), 'tasks'), 'none', 'an archived person gets none (their staff role would give edit)');
select is(public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_disabled_a'), pg_temp.id('loc_a1'), 'tasks'), 'none', 'a disabled account gets none');
select is(public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_arch_loc'), pg_temp.id('loc_a3'), 'tasks'), 'none', 'a person at an archived location gets none there');
select is(public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'tasks'), 'edit', 'control: an active member gets their level');
select is(public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_b1'), 'tasks'), 'none', 'a location of another organization gives none');
select is(public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), gen_random_uuid(), 'tasks'), 'none', 'a random location gives none');
select is(public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'), pg_temp.id('loc_a1'), 'tasks'), 'none', 'a person with no assignment gets none');
-- refusals: always 42501 'not allowed'
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('loc_a1'), 'tasks')$q$), '42501: not allowed | ', 'refused: staff cannot ask about a colleague');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'tasks')$q$), '42501: not allowed | ', 'refused: staff cannot ask about themselves either');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'tasks')$q$), '42501: not allowed | ', 'refused: a manager without the people_roles override cannot ask');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), pg_temp.id('loc_a2'), 'tasks')$q$), '42501: not allowed | ', 'refused: a location admin cannot ask about a person who is only at another location');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_orgadmin_a'), pg_temp.id('loc_a1'), 'tasks')$q$), '42501: not allowed | ', 'refused: a location admin cannot ask about the org admin');
select pg_temp.act_as('u_noaccount');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'tasks')$q$), '42501: not allowed | ', 'refused: a user with no account cannot ask');
select pg_temp.act_as('u_disabled_a');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'tasks')$q$), '42501: not allowed | ', 'refused: a disabled account cannot ask');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'tasks')$q$), '42501: not allowed | ', 'refused: another organization''s admin cannot ask about a person of org A');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_b1'), pg_temp.id('loc_b1'), 'tasks')$q$), '42501: not allowed | ', 'refused: an org admin cannot ask about a person of org B');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_b'), pg_temp.id('p_staff_b1'), pg_temp.id('loc_b1'), 'tasks')$q$), '42501: not allowed | ', 'refused: an org admin cannot ask about a person of org B through org B''s id');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), gen_random_uuid(), pg_temp.id('loc_a1'), 'tasks')$q$), '42501: not allowed | ', 'refused: a random person id is refused the same way');
select pg_temp.act_as('postgres');
set local role service_role;
select is(pg_temp.try_msg($q$select public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'tasks')$q$), '42501: not signed in | ', 'refused: service_role has no signed-in user');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- replace_role_assignment
-- ===========================================================================
select pg_temp.act_as('postgres');
create temp table rr (new_id uuid);
grant all on rr to public;
select pg_temp.act_as('u_locadmin_a1');
insert into rr select public.replace_role_assignment(pg_temp.id('ra_t2'), pg_temp.id('role_custom_a'), pg_temp.id('loc_a1'));
select pg_temp.act_as('postgres');
select is((select count(*) from public.role_assignments where person_id = pg_temp.id('p_t2')), 1::bigint, 'positive: a swap leaves the person with exactly one assignment');
select results_eq($$select role_id, location_id from public.role_assignments where id = (select new_id from rr)$$,
  $$select pg_temp.id('role_custom_a'), pg_temp.id('loc_a1')$$, 'the new assignment is the requested role and location, and its id is what the call returned');
select is((select count(*) from public.role_assignments where id = pg_temp.id('ra_t2')), 0::bigint, 'the old assignment is gone');
select results_eq($$select action::text, actor_user_id, actor_person_id, actor_role, organization_id, location_id from public.audit_log
    where table_name = 'role_assignments' and actor_role = 'authenticated'
      and row_id in ((select new_id::text from rr), pg_temp.id('ra_t2')::text) order by action$$,
  $$values ('delete'::text, pg_temp.id('u_locadmin_a1'), pg_temp.id('p_locadmin_a1'), 'authenticated'::text, pg_temp.id('org_a'), pg_temp.id('loc_a1')),
           ('insert'::text, pg_temp.id('u_locadmin_a1'), pg_temp.id('p_locadmin_a1'), 'authenticated'::text, pg_temp.id('org_a'), pg_temp.id('loc_a1'))$$,
  'exactly two audit rows (insert new, delete old), both with the real caller');
select pg_temp.act_as('u_locadmin_a1');
select is(public.replace_role_assignment(pg_temp.id('ra_t4b'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1')), pg_temp.id('ra_t4a'),
  'if the person already holds the replacement, the old row is removed and the existing id is returned');
select pg_temp.act_as('postgres');
select is((select count(*) from public.role_assignments where person_id = pg_temp.id('p_t4')), 1::bigint, 'and they keep exactly one assignment');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '22023: nothing to change | ', 'nothing to change: the same role and location is refused with a plain message');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), null, pg_temp.id('loc_a1'))$q$), '22023', 'a missing role is refused');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t6'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), 'ok', 'positive: an org admin can swap staff for manager');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_la2'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: a location admin cannot swap an equal-rank person''s (admin) assignment');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), pg_temp.sys_role('admin'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: a location admin cannot swap someone up to admin (equal rank)');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), pg_temp.sys_role('admin'), null)$q$), '42501', 'refused: a location admin cannot swap someone up to org admin');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), pg_temp.sys_role('manager'), pg_temp.id('loc_a2'))$q$), '42501', 'refused: a location admin cannot move an assignment to another location');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_staff_a2'), pg_temp.sys_role('manager'), pg_temp.id('loc_a2'))$q$), '42501', 'refused: a location admin cannot swap an assignment at another location');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_locadmin_a1'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: nobody can swap their own assignment');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_orgadmin_a'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: a location admin cannot swap the org admin''s assignment');
select is(pg_temp.try($q$select public.replace_role_assignment(gen_random_uuid(), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: a random assignment id is refused');
select is(pg_temp.try_msg($q$select public.replace_role_assignment(gen_random_uuid(), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501: not allowed | ', 'a random assignment id gets the same generic message as a forbidden one');
select is(pg_temp.try_msg($q$select public.replace_role_assignment(pg_temp.id('ra_staff_a2'), pg_temp.sys_role('manager'), pg_temp.id('loc_a2'))$q$), '42501: not allowed | ', 'a forbidden assignment gets that same generic message');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: staff cannot swap assignments');
select pg_temp.act_as('u_noaccount');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: a user with no account cannot swap assignments');
select pg_temp.act_as('u_disabled_a');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: a disabled account cannot swap assignments');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: another organization''s admin cannot swap assignments');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: a manager without the override cannot swap assignments');
select pg_temp.act_as('postgres');
set local role service_role;
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t4a'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$q$), '42501', 'refused: service_role has no signed-in user (it can write directly)');
select pg_temp.act_as('u_platform');
select is(pg_temp.try($q$select public.replace_role_assignment(pg_temp.id('ra_t7'), pg_temp.sys_role('admin'), null)$q$), 'ok', 'positive: a platform admin can swap to org admin');
select pg_temp.act_as('postgres');
select is((select count(*) from public.role_assignments where person_id = pg_temp.id('p_t4')), 1::bigint, 'every refused swap left p_t4 with exactly one assignment, unchanged');
select is((select count(*) from public.role_assignments where person_id in (pg_temp.id('p_t6'), pg_temp.id('p_t7'))), 2::bigint, 'and each allowed swap left its person with exactly one');
select * from finish();
rollback;
