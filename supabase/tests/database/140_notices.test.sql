-- Phase 2 / communications: notices. Audience resolution (organization-wide, location, job title), drafts invisible to
-- the audience, no publishing by column write, no edits after publish, who may create which audience, a job-title change
-- reveals only the matching notice, acknowledge is idempotent and refused outside the audience, acknowledgments are
-- append-only. Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(274);

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
grant execute on function pg_temp.try_msg(text), pg_temp.val(text) to public;

-- Extra people: staff A1b (no job title), a manager at A2, a person holding job title jt_x.
insert into auth.users (id, email) values (pg_temp.id('u_staff_a1b'), 'staff-a1b@test.invalid'), (pg_temp.id('u_manager_a2'), 'manager-a2@test.invalid');
insert into public.people (id, organization_id, first_name, last_name) values
  (pg_temp.id('p_staff_a1b'),  pg_temp.id('org_a'), 'Sid', 'StaffA1b'),
  (pg_temp.id('p_manager_a2'), pg_temp.id('org_a'), 'Mel', 'ManagerA2');
insert into public.accounts (id, organization_id, person_id, user_id) values
  (pg_temp.id('acct_staff_a1b'),  pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'),  pg_temp.id('u_staff_a1b')),
  (pg_temp.id('acct_manager_a2'), pg_temp.id('org_a'), pg_temp.id('p_manager_a2'), pg_temp.id('u_manager_a2'));
insert into public.role_assignments (organization_id, person_id, role_id, location_id) values
  (pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'),  pg_temp.sys_role('staff'),   pg_temp.id('loc_a1')),
  (pg_temp.id('org_a'), pg_temp.id('p_manager_a2'), pg_temp.sys_role('manager'), pg_temp.id('loc_a2'));
insert into public.job_titles (id, organization_id, name) values (pg_temp.id('jt_x'), pg_temp.id('org_a'), 'Zamboni driver');

-- ===========================================================================
-- 1. Who may create which notice; a notice is always a draft written by the caller; no publishing by column write
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$insert into public.notices (id, organization_id, location_id, title, body) values (pg_temp.id('n_a1'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Pool rules', 'Walk, do not run.')$$), 'ok', 'manager A1 creates a notice for A1');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'x', 'y')$$), '42501', 'manager A1 cannot create a notice for A2');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_a'), null, 'x', 'y')$$), '42501', 'manager A1 cannot create an organization-wide notice');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'x', 'y')$$), '42501', 'manager A1 cannot create a notice in org B');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body, status) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', 'y', 'published')$$), '42501', 'status cannot be set on insert (no column grant)');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body, published_at) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', 'y', now())$$), '42501', 'published_at cannot be set on insert');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body, author_person_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', 'y', pg_temp.id('p_staff_a1'))$$), '42501', 'the author cannot be chosen on insert');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body, published_by_person_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', 'y', pg_temp.id('p_staff_a1'))$$), '42501', 'published_by cannot be set on insert');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body, archived_at) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', 'y', now())$$), '42501', 'archived_at cannot be set on insert');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body, urgency) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', 'y', 'catastrophic')$$), '23514', 'an unknown urgency is refused');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), '   ', 'y')$$), '23514', 'a blank title is refused');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', repeat('b', 5001))$$), '23514', 'a body over 5000 characters is refused');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body, publish_at, expires_at) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', 'y', now() + interval '2 days', now() + interval '1 day')$$), '23514', 'expiring before it is published is refused');
select pg_temp.act_as('postgres');
select results_eq($$select status, author_person_id, published_at is null, published_by_person_id is null, archived_at is null from public.notices where id = pg_temp.id('n_a1')$$,
  $$select 'draft'::text, pg_temp.id('p_manager_a1'), true, true, true$$, 'the new notice is a draft, authored by the caller''s person, not published');
select is((select count(*) from public.notices), 1::bigint, 'only the one valid notice exists (every refused insert left nothing)');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'staff notice', 'y')$$), '42501', 'staff A1 cannot create a notice');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'staff notice', 'y')$$), '42501', 'staff A2 cannot create a notice');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try($$insert into public.notices (id, organization_id, location_id, title, body) values (pg_temp.id('n_la'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Loc admin notice', 'y')$$), 'ok', 'twin: location admin A1 creates a notice for A1');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_a'), null, 'x', 'y')$$), '42501', 'location admin A1 cannot create an organization-wide notice');
select pg_temp.act_as('u_orgadmin_a', 'aal1');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_a'), null, 'x', 'y')$$), '42501', 'org admin A at aal1 cannot create a notice');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($$insert into public.notices (id, organization_id, location_id, title, body, requires_acknowledgment) values (pg_temp.id('n_org'), pg_temp.id('org_a'), null, 'Org-wide notice', 'For everyone.', true)$$), 'ok', 'twin: org admin A (aal2) creates an organization-wide notice');
select is(pg_temp.try($$insert into public.notices (id, organization_id, location_id, title, body) values (pg_temp.id('n_a2'), pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'A2 notice', 'y')$$), 'ok', 'org admin A creates a notice for A2');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'x', 'y')$$), '42501', 'org admin A cannot create a notice in org B');
select pg_temp.act_as('u_platform');
select is(pg_temp.try($$insert into public.notices (id, organization_id, location_id, title, body) values (pg_temp.id('n_pl'), pg_temp.id('org_b'), null, 'Platform notice', 'y')$$), 'ok', 'a platform admin (aal2) can create a notice anywhere');
select pg_temp.act_as('u_platform', 'aal1');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_b'), null, 'x', 'y')$$), '42501', 'a platform admin at aal1 cannot');
select pg_temp.act_as('u_noaccount');
select is(pg_temp.try($$insert into public.notices (organization_id, location_id, title, body) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', 'y')$$), '42501', 'a user with no account cannot create a notice');
select pg_temp.act_as('anon');
select is(pg_temp.try($$insert into public.notices (organization_id, title, body) values (pg_temp.id('org_a'), 'x', 'y')$$), '42501', 'anon cannot create a notice');
select pg_temp.act_as('service_role');
select is(pg_temp.try($$insert into public.notices (organization_id, title, body) values (pg_temp.id('org_a'), 'x', 'y')$$), '42501', 'service_role cannot insert into notices (it reads only)');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 2. Audience rows: who may add or remove them, and where
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try($$insert into public.notice_audiences (id, organization_id, notice_id, location_id) values (pg_temp.id('aud_a1'), pg_temp.id('org_a'), pg_temp.id('n_a1'), pg_temp.id('loc_a1'))$$), 'ok', 'manager A1 adds "everyone at A1" to their A1 notice');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_a1'), pg_temp.id('loc_a2'))$$), '42501', 'a location notice cannot target another location');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_a1'), null)$$), '42501', 'a location notice cannot be widened to the whole organization');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id, job_title_id) values (pg_temp.id('org_a'), pg_temp.id('n_a1'), pg_temp.id('loc_a1'), pg_temp.id('jt_a'))$$), 'ok', 'twin: the same location with a job title is fine');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_a1'), pg_temp.id('loc_a1'))$$), '23505', 'the same audience row twice is refused (unique, nulls not distinct)');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id, job_title_id) values (pg_temp.id('org_a'), pg_temp.id('n_a1'), pg_temp.id('loc_a1'), pg_temp.id('jt_b'))$$), '23503', 'a job title of another organization is refused (composite key)');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_org'), pg_temp.id('loc_a1'))$$), '42501', 'manager A1 cannot add an audience to an organization-wide notice they cannot manage');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_a2'), pg_temp.id('loc_a2'))$$), '42501', 'manager A1 cannot add an audience to A2''s notice');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_b'), pg_temp.id('n_a1'), pg_temp.id('loc_a1'))$$), '42501', 'an audience row cannot claim another organization than its notice');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), gen_random_uuid(), pg_temp.id('loc_a1'))$$), '42501', 'an audience row for a notice that does not exist is refused the same way');
select is(pg_temp.try($$update public.notice_audiences set job_title_id = null where notice_id = pg_temp.id('n_a1')$$), '42501', 'audience rows cannot be updated (delete and add instead)');
select is((select count(*) from public.notice_audiences), 2::bigint, 'manager A1 reads the 2 audience rows of their notice');
select is(pg_temp.affected($$delete from public.notice_audiences where notice_id = pg_temp.id('n_a1') and job_title_id is not null$$), 1::bigint, 'manager A1 removes an audience row of their draft');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id, job_title_id) values (pg_temp.id('org_a'), pg_temp.id('n_a1'), pg_temp.id('loc_a1'), pg_temp.id('jt_a'))$$), 'ok', 'and adds it again');
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.notice_audiences), 0::bigint, 'staff A1 cannot read audience rows (even of notices they receive)');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_a1'), pg_temp.id('loc_a1'))$$), '42501', 'staff A1 cannot add audience rows');
select is(pg_temp.affected($$delete from public.notice_audiences$$), 0::bigint, 'staff A1 deletes no audience rows');
select pg_temp.act_as('u_manager_a2');
select is((select count(*) from public.notice_audiences), 0::bigint, 'manager A2 cannot read A1''s audience rows');
select is(pg_temp.affected($$delete from public.notice_audiences$$), 0::bigint, 'manager A2 cannot delete them');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($$insert into public.notice_audiences (id, organization_id, notice_id, location_id) values (pg_temp.id('aud_org_all'), pg_temp.id('org_a'), pg_temp.id('n_org'), null)$$), 'ok', 'org admin A adds "everyone in the organization" to the org-wide notice');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id, job_title_id) values (pg_temp.id('org_a'), pg_temp.id('n_org'), pg_temp.id('loc_a2'), pg_temp.id('jt_x'))$$), 'ok', 'an organization-wide notice can also target one location and title');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_org'), pg_temp.id('loc_b1'))$$), '23503', 'but not a location of another organization (composite key)');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_a2'), pg_temp.id('loc_a2'))$$), 'ok', 'org admin A adds the A2 audience');
select pg_temp.act_as('u_orgadmin_b');
select is((select count(*) from public.notice_audiences), 0::bigint, 'org B admin sees no org A audience rows');
select pg_temp.act_as('postgres');
-- n_la (location admin's notice) has no audience: it cannot be published
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_la'))$$), '22023 choose who the notice is for first', 'publish: a notice with no audience is refused (22023)');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 3. Audience resolution (the one rule, for any person) as a truth table
-- ===========================================================================
-- Build the notices for the table with the owner: each with its own audience rows.
insert into public.notices (id, organization_id, location_id, title, body) values
  (pg_temp.id('r_org_all'),  pg_temp.id('org_a'), null,                 'r_org_all',  'x'),
  (pg_temp.id('r_org_jt'),   pg_temp.id('org_a'), null,                 'r_org_jt',   'x'),
  (pg_temp.id('r_a1_all'),   pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'r_a1_all',   'x'),
  (pg_temp.id('r_a1_jt'),    pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'r_a1_jt',    'x'),
  (pg_temp.id('r_a1a2'),     pg_temp.id('org_a'), null,                 'r_a1a2',     'x'),
  (pg_temp.id('r_none'),     pg_temp.id('org_a'), null,                 'r_none',     'x');
insert into public.notice_audiences (organization_id, notice_id, location_id, job_title_id) values
  (pg_temp.id('org_a'), pg_temp.id('r_org_all'), null, null),
  (pg_temp.id('org_a'), pg_temp.id('r_org_jt'),  null, pg_temp.id('jt_a')),
  (pg_temp.id('org_a'), pg_temp.id('r_a1_all'),  pg_temp.id('loc_a1'), null),
  (pg_temp.id('org_a'), pg_temp.id('r_a1_jt'),   pg_temp.id('loc_a1'), pg_temp.id('jt_a')),
  (pg_temp.id('org_a'), pg_temp.id('r_a1a2'),    pg_temp.id('loc_a1'), null),
  (pg_temp.id('org_a'), pg_temp.id('r_a1a2'),    pg_temp.id('loc_a2'), pg_temp.id('jt_x'));
create temp table aud_people (n int, p text);
insert into aud_people values (1, 'p_staff_a1'), (2, 'p_staff_a2'), (3, 'p_manager_a1'), (4, 'p_locadmin_a1'), (5, 'p_orgadmin_a'), (6, 'p_disabled_a'), (7, 'p_unassigned_a'),
  (8, 'p_staff_a1b'), (9, 'p_manager_a2'), (10, 'p_staff_b1'), (11, 'p_orgadmin_b');
grant all on aud_people to public;
-- Spelled out per person to keep the table readable and exact:
create temp table aud_truth as
  select n.title as notice, p.n, p.p as person, private.person_in_notice_audience(n.id, pg_temp.id(p.p)) as got
  from public.notices n cross join aud_people p where n.title like 'r\_%';
grant all on aud_truth to public;
create temp table aud_want (notice text, person text, want boolean);
insert into aud_want
  select n, p, w from (values
    ('r_org_all','p_staff_a1',true),('r_org_all','p_staff_a2',true),('r_org_all','p_manager_a1',true),('r_org_all','p_locadmin_a1',true),('r_org_all','p_orgadmin_a',true),
    ('r_org_all','p_disabled_a',false),('r_org_all','p_unassigned_a',false),('r_org_all','p_staff_a1b',true),('r_org_all','p_manager_a2',true),('r_org_all','p_staff_b1',false),('r_org_all','p_orgadmin_b',false),
    ('r_org_jt','p_staff_a1',true),('r_org_jt','p_staff_a2',false),('r_org_jt','p_manager_a1',false),('r_org_jt','p_locadmin_a1',false),('r_org_jt','p_orgadmin_a',false),
    ('r_org_jt','p_disabled_a',false),('r_org_jt','p_unassigned_a',false),('r_org_jt','p_staff_a1b',false),('r_org_jt','p_manager_a2',false),('r_org_jt','p_staff_b1',false),('r_org_jt','p_orgadmin_b',false),
    ('r_a1_all','p_staff_a1',true),('r_a1_all','p_staff_a2',false),('r_a1_all','p_manager_a1',true),('r_a1_all','p_locadmin_a1',true),('r_a1_all','p_orgadmin_a',true),
    ('r_a1_all','p_disabled_a',false),('r_a1_all','p_unassigned_a',false),('r_a1_all','p_staff_a1b',true),('r_a1_all','p_manager_a2',false),('r_a1_all','p_staff_b1',false),('r_a1_all','p_orgadmin_b',false),
    ('r_a1_jt','p_staff_a1',true),('r_a1_jt','p_staff_a2',false),('r_a1_jt','p_manager_a1',false),('r_a1_jt','p_locadmin_a1',false),('r_a1_jt','p_orgadmin_a',false),
    ('r_a1_jt','p_disabled_a',false),('r_a1_jt','p_unassigned_a',false),('r_a1_jt','p_staff_a1b',false),('r_a1_jt','p_manager_a2',false),('r_a1_jt','p_staff_b1',false),('r_a1_jt','p_orgadmin_b',false),
    ('r_a1a2','p_staff_a1',true),('r_a1a2','p_staff_a2',false),('r_a1a2','p_manager_a1',true),('r_a1a2','p_locadmin_a1',true),('r_a1a2','p_orgadmin_a',true),
    ('r_a1a2','p_disabled_a',false),('r_a1a2','p_unassigned_a',false),('r_a1a2','p_staff_a1b',true),('r_a1a2','p_manager_a2',false),('r_a1a2','p_staff_b1',false),('r_a1a2','p_orgadmin_b',false),
    ('r_none','p_staff_a1',false),('r_none','p_staff_a2',false),('r_none','p_manager_a1',false),('r_none','p_locadmin_a1',false),('r_none','p_orgadmin_a',false),
    ('r_none','p_disabled_a',false),('r_none','p_unassigned_a',false),('r_none','p_staff_a1b',false),('r_none','p_manager_a2',false),('r_none','p_staff_b1',false),('r_none','p_orgadmin_b',false)
  ) v (n, p, w);
select is((select got from aud_truth t where t.notice = w.notice and t.person = w.person), w.want, 'audience ' || w.notice || ' includes ' || w.person || ': ' || w.want)
  from aud_want w order by w.notice, w.person;
-- a person given the Zamboni title at A2 now matches the "A2 + Zamboni" row of r_a1a2, and only through that row
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id)
values (pg_temp.id('pjt_m2'), pg_temp.id('org_a'), pg_temp.id('p_manager_a2'), pg_temp.id('jt_x'), pg_temp.id('loc_a2'));
select is(private.person_in_notice_audience(pg_temp.id('r_a1a2'), pg_temp.id('p_manager_a2')), true, 'audience: manager A2 with the Zamboni title at A2 matches the (A2, Zamboni) row');
select is(private.person_in_notice_audience(pg_temp.id('r_a1_all'), pg_temp.id('p_manager_a2')), false, 'audience: and that does not put them in an A1 audience');
select is(private.person_in_notice_audience(pg_temp.id('r_org_jt'), pg_temp.id('p_manager_a2')), false, 'audience: nor in the Lifeguard-only audience');
-- a title held at A2 does not match a row for A1
delete from public.person_job_titles where id = pg_temp.id('pjt_m2');
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id)
values (pg_temp.id('pjt_m2'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.id('jt_a'), pg_temp.id('loc_a2'));
select is(private.person_in_notice_audience(pg_temp.id('r_a1_jt'), pg_temp.id('p_staff_a1b')), false, 'audience: a title held only at A2 does not satisfy an (A1, title) row');
select is(private.person_in_notice_audience(pg_temp.id('r_org_jt'), pg_temp.id('p_staff_a1b')), true, 'audience: but it does satisfy an organization-wide (any location, title) row');
delete from public.person_job_titles where id = pg_temp.id('pjt_m2');
-- scope: a person with communications = none is not in any audience, even where the row names their location
insert into public.user_permissions (id, organization_id, person_id, location_id, module_key, level) values (pg_temp.id('up_comm'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), null, 'communications', 'none');
select is(private.person_in_notice_audience(pg_temp.id('r_a1_all'), pg_temp.id('p_staff_a1')), false, 'audience: communications = none removes the person from every audience');
select is(private.person_in_notice_audience(pg_temp.id('r_org_all'), pg_temp.id('p_staff_a1')), false, 'audience: also from the organization-wide one');
delete from public.user_permissions where id = pg_temp.id('up_comm');
-- an archived job title no longer selects anyone
update public.job_titles set archived_at = now() where id = pg_temp.id('jt_a');
select is(private.person_in_notice_audience(pg_temp.id('r_a1_jt'), pg_temp.id('p_staff_a1')), false, 'audience: an archived job title selects nobody');
select is(private.person_in_notice_audience(pg_temp.id('r_a1_all'), pg_temp.id('p_staff_a1')), true, 'audience: twin, the plain A1 audience still includes them');
update public.job_titles set archived_at = null where id = pg_temp.id('jt_a');
-- an archived person, an archived location, a disabled account
update public.people set archived_at = now() where id = pg_temp.id('p_staff_a1b');
select is(private.person_in_notice_audience(pg_temp.id('r_a1_all'), pg_temp.id('p_staff_a1b')), false, 'audience: an archived person is not in any audience');
update public.people set archived_at = null where id = pg_temp.id('p_staff_a1b');
select is(private.person_in_notice_audience(pg_temp.id('r_a1_all'), null), false, 'audience: a null person is in no audience');
select is(private.person_in_notice_audience(gen_random_uuid(), pg_temp.id('p_staff_a1')), false, 'audience: an unknown notice has no audience');

-- ===========================================================================
-- 4. Reading: drafts are invisible to the audience; live published notices are visible to exactly the audience
-- ===========================================================================
-- n_org (org-wide, requires acknowledgment, audience everyone), n_a1 (A1: everyone + Lifeguards), n_a2 (A2: everyone)
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.notices where id in (pg_temp.id('n_org'), pg_temp.id('n_a1'), pg_temp.id('n_a2'))), 0::bigint, 'drafts are invisible to the audience (staff A1 sees none of the three drafts)');
select pg_temp.act_as('u_manager_a1');
select is((select array_agg(id order by id) from public.notices where id in (pg_temp.id('n_org'), pg_temp.id('n_a1'), pg_temp.id('n_a2'))), array[pg_temp.id('n_a1')], 'manager A1 sees their own draft, not the org-wide or A2 drafts');
select pg_temp.act_as('u_manager_a2');
select is((select count(*) from public.notices where id = pg_temp.id('n_a1')), 0::bigint, 'manager A2 does not see A1''s draft');
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.notices where id in (pg_temp.id('n_org'), pg_temp.id('n_a1'), pg_temp.id('n_a2'))), 3::bigint, 'org admin A sees all the drafts of the organization');
select pg_temp.act_as('u_orgadmin_b');
select is((select count(*) from public.notices where organization_id = pg_temp.id('org_a')), 0::bigint, 'org admin B sees nothing of org A');
select pg_temp.act_as('postgres');
-- the draft cannot be published by a column write, by anyone
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try($$update public.notices set status = 'published' where id = pg_temp.id('n_a1')$$), '42501', 'status cannot be written directly (manager)');
select is(pg_temp.try($$update public.notices set published_at = now(), publish_at = now() where id = pg_temp.id('n_a1')$$), '42501', 'published_at cannot be written directly');
select is(pg_temp.try($$update public.notices set published_by_person_id = pg_temp.id('p_manager_a1') where id = pg_temp.id('n_a1')$$), '42501', 'published_by cannot be written directly');
select is(pg_temp.try($$update public.notices set author_person_id = pg_temp.id('p_staff_a1') where id = pg_temp.id('n_a1')$$), '42501', 'the author cannot be changed');
select is(pg_temp.try($$update public.notices set location_id = pg_temp.id('loc_a2') where id = pg_temp.id('n_a1')$$), '42501', 'the location cannot be changed');
select is(pg_temp.try($$update public.notices set organization_id = pg_temp.id('org_b') where id = pg_temp.id('n_a1')$$), '42501', 'the organization cannot be changed');
select is(pg_temp.try($$update public.notices set archived_at = now() where id = pg_temp.id('n_a1')$$), '42501', 'archived_at cannot be written directly');
select is(pg_temp.affected($$update public.notices set title = 'Pool rules (updated)', urgency = 'high', requires_acknowledgment = true, expires_at = now() + interval '30 days' where id = pg_temp.id('n_a1')$$), 1::bigint, 'twin: the manager edits their draft''s title, urgency, acknowledgment flag and expiry');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($$update public.notices set status = 'published' where id = pg_temp.id('n_org')$$), '42501', 'status cannot be written directly (org admin)');
select pg_temp.act_as('u_platform');
select is(pg_temp.try($$update public.notices set status = 'published' where id = pg_temp.id('n_org')$$), '42501', 'status cannot be written directly (platform admin)');
select pg_temp.act_as('service_role');
select is(pg_temp.try($$update public.notices set status = 'published' where id = pg_temp.id('n_org')$$), '42501', 'status cannot be written directly (service_role)');
select pg_temp.act_as('postgres');
select is(pg_temp.try($$update public.notices set status = 'published' where id = pg_temp.id('n_a1')$$), '23514', 'even the owner cannot publish without the dates (CHECK: published needs publish_at and published_at)');
select is((select status from public.notices where id = pg_temp.id('n_a1')), 'draft', 'n_a1 is still a draft');

-- ===========================================================================
-- 5. publish_notice / archive_notice
-- ===========================================================================
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_a1'))$$), '42501 not allowed', 'publish: staff cannot (and the draft is invisible to them: same answer)');
select pg_temp.act_as('u_manager_a2');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_a1'))$$), '42501 not allowed', 'publish: manager A2 cannot publish A1''s notice');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_org'))$$), '42501 not allowed', 'publish: manager A1 cannot publish an organization-wide notice');
select is(pg_temp.try_msg($$select public.publish_notice(gen_random_uuid())$$), '42501 not allowed', 'publish: an unknown notice gives the same answer');
select is(pg_temp.try_msg($$select public.publish_notice(null)$$), '42501 not allowed', 'publish: null gives the same answer');
select pg_temp.act_as('u_orgadmin_a', 'aal1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_org'))$$), '42501 not allowed', 'publish: org admin at aal1 gets the same answer');
select pg_temp.act_as('anon');
select is(pg_temp.try('select public.publish_notice(gen_random_uuid())'), '42501', 'publish: anon cannot call it');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_a1'))$$), '42501 not signed in', 'publish: the server key with no user is refused');
select pg_temp.act_as('postgres');
select is((select count(*) from public.notices where status <> 'draft'), 0::bigint, 'no notice was published by those refusals');
select is((select count(*) from public.outbox_events where type like 'notice.%'), 0::bigint, 'and no notice event was written');
-- expiry before the publish time rolls the whole call back
select pg_temp.act_as('u_manager_a1');
update public.notices set expires_at = now() + interval '1 hour' where id = pg_temp.id('n_a1');
-- Observation: the refusal is the table CHECK (23514), not a friendly 22023 from publish_notice.
select is(pg_temp.try($$select public.publish_notice(pg_temp.id('n_a1'), now() + interval '2 days')$$), '23514', 'publish: a publish time after the expiry is refused (CHECK 23514)');
select pg_temp.act_as('postgres');
select results_eq($$select status, published_at is null, publish_at is null from public.notices where id = pg_temp.id('n_a1')$$, $$select 'draft'::text, true, true$$, 'and the notice is still a plain draft (the call was rolled back)');
select is((select count(*) from public.outbox_events where type like 'notice.%'), 0::bigint, 'with no event');
update public.notices set expires_at = null where id = pg_temp.id('n_a1');
-- the real publish
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_a1'))$$), 'ok', 'twin: manager A1 publishes their notice');
select pg_temp.act_as('postgres');
select results_eq($$select status, publish_at = now(), published_at = now(), published_by_person_id, archived_at is null from public.notices where id = pg_temp.id('n_a1')$$,
  $$select 'published'::text, true, true, pg_temp.id('p_manager_a1'), true$$, 'published: status, publish time now, published_by the caller');
select results_eq($$select count(*), min(e.type), min(e.entity_table), min(e.organization_id::text), min(e.location_id::text), (min(e.next_attempt_at) = now()), min(e.payload ->> 'notice_id') from public.outbox_events e where e.type like 'notice.%'$$,
  $$select 1::bigint, 'notice.published'::text, 'notices'::text, pg_temp.id('org_a')::text, pg_temp.id('loc_a1')::text, true, pg_temp.id('n_a1')::text$$, 'exactly one notice.published event, for that notice, in its scope, due now');
select is((select count(*) from public.outbox_events e where e.type like 'notice.%' and (e.payload ? 'title' or e.payload ? 'body')), 0::bigint, 'the event carries ids and flags only, never the title or body');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_a1'))$$), '22023 only a draft can be published', 'publish: a second publish is 22023');
select is(pg_temp.affected($$update public.notices set title = 'changed after publish' where id = pg_temp.id('n_a1')$$), 0::bigint, 'a published notice cannot be edited (0 rows)');
select is(pg_temp.affected($$update public.notices set body = 'changed after publish', urgency = 'critical' where id = pg_temp.id('n_a1')$$), 0::bigint, 'nor its body or urgency');
select is(pg_temp.affected($$delete from public.notices where id = pg_temp.id('n_a1')$$), 0::bigint, 'nor deleted');
select is(pg_temp.affected($$delete from public.notice_audiences where notice_id = pg_temp.id('n_a1')$$), 0::bigint, 'its audience rows cannot be deleted after publish');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_a1'), pg_temp.id('loc_a1'))$$), '42501', 'nor added to after publish');
select is((select title from public.notices where id = pg_temp.id('n_a1')), 'Pool rules (updated)', 'the notice text is exactly what it was at publish');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.affected($$update public.notices set title = 'org admin edit' where id = pg_temp.id('n_a1')$$), 0::bigint, 'org admin cannot edit a published notice either');
select pg_temp.act_as('u_platform');
select is(pg_temp.affected($$update public.notices set title = 'platform edit' where id = pg_temp.id('n_a1')$$), 0::bigint, 'nor a platform admin');
select pg_temp.act_as('postgres');
-- publish with a past time means now; with a future time schedules it
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_org'), now() - interval '1 day')$$), 'ok', 'publish: a time in the past means now');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_a2'), now() + interval '1 day')$$), 'ok', 'publish: a time in the future schedules it');
select pg_temp.act_as('postgres');
select is((select publish_at = now() from public.notices where id = pg_temp.id('n_org')), true, 'a past publish time was changed to now');
select is((select publish_at = now() + interval '1 day' from public.notices where id = pg_temp.id('n_a2')), true, 'a future publish time is kept');
select is((select next_attempt_at = now() + interval '1 day' from public.outbox_events where entity_id = pg_temp.id('n_a2') and type = 'notice.published'), true, 'and the event is due at that time, not before');
-- scheduled notices are not visible to the audience until their time; managers see them
select pg_temp.act_as('u_staff_a2');
select is((select count(*) from public.notices where id = pg_temp.id('n_a2')), 0::bigint, 'a scheduled notice is invisible to its audience before its publish time');
select pg_temp.act_as('u_manager_a2');
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.notices where id = pg_temp.id('n_a2')), 1::bigint, 'twin: the org admin sees the scheduled notice');
select pg_temp.act_as('postgres');
update public.notices set publish_at = now() - interval '1 minute', published_at = now() - interval '1 minute' where id = pg_temp.id('n_a2');
select pg_temp.act_as('u_staff_a2');
select is((select count(*) from public.notices where id = pg_temp.id('n_a2')), 1::bigint, 'twin: once its time has come the audience sees it');
select pg_temp.act_as('postgres');
-- archive
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.archive_notice(pg_temp.id('n_a1'))$$), '42501 not allowed', 'archive: staff cannot');
select pg_temp.act_as('u_manager_a2');
select is(pg_temp.try_msg($$select public.archive_notice(pg_temp.id('n_a1'))$$), '42501 not allowed', 'archive: manager A2 cannot archive A1''s notice');
select is(pg_temp.try_msg($$select public.archive_notice(gen_random_uuid())$$), '42501 not allowed', 'archive: an unknown notice gets the same answer');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.archive_notice(pg_temp.id('n_la'))$$), 'ok', 'twin: manager A1 can archive a draft at A1 (a draft can be archived too)');
select pg_temp.act_as('postgres');
select is((select status from public.notices where id = pg_temp.id('n_la')), 'archived', 'the draft is archived');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.archive_notice(pg_temp.id('n_la'))$$), '22023 this notice is already archived', 'archive: archiving twice is 22023');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n_la'))$$), '22023 only a draft can be published', 'an archived notice cannot be published');
select is(pg_temp.affected($$update public.notices set title = 'x' where id = pg_temp.id('n_la')$$), 0::bigint, 'an archived notice cannot be edited');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'notice.archived' and entity_id = pg_temp.id('n_la')), 1::bigint, 'archiving wrote exactly one notice.archived event');
-- delete: drafts only
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($$insert into public.notices (id, organization_id, location_id, title, body) values (pg_temp.id('n_del'), pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'to delete', 'x')$$), 'ok', 'a throwaway draft');
select is(pg_temp.try($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_del'), pg_temp.id('loc_a2'))$$), 'ok', 'with an audience row');
select is(pg_temp.affected($$delete from public.notices where id = pg_temp.id('n_del')$$), 1::bigint, 'twin: a draft can be deleted');
select pg_temp.act_as('postgres');
select is((select count(*) from public.notice_audiences where notice_id = pg_temp.id('n_del')), 0::bigint, 'and its audience rows go with it');

-- ===========================================================================
-- 6. A live notice is read by exactly its audience (n_a1 is published to A1: everyone + Lifeguards)
-- ===========================================================================
create temp table readers (n int, who text, aal text, sees boolean, note text);
insert into readers values
  (1,  'u_staff_a1',     'aal2', true,  'staff at A1'),
  (2,  'u_staff_a1b',    'aal2', true,  'another staff member at A1'),
  (3,  'u_manager_a1',   'aal2', true,  'the manager (also manages it)'),
  (4,  'u_locadmin_a1',  'aal2', true,  'location admin A1'),
  (5,  'u_orgadmin_a',   'aal2', true,  'org admin A'),
  (6,  'u_staff_a2',     'aal2', false, 'staff at A2 (another location)'),
  (7,  'u_manager_a2',   'aal2', false, 'manager at A2'),
  (8,  'u_disabled_a',   'aal2', false, 'a disabled account at A1'),
  (9,  'u_noaccount',    'aal2', false, 'a user with no account'),
  (10, 'u_staff_b1',     'aal2', false, 'staff in org B'),
  (11, 'u_orgadmin_b',   'aal2', false, 'org admin B'),
  (12, 'u_orgadmin_a',   'aal1', false, 'org admin A at aal1 (admin tier suppressed)'),
  (13, 'u_platform',     'aal2', true,  'platform admin (manages everything)'),
  (14, 'u_platform',     'aal1', false, 'platform admin at aal1');
grant all on readers to public;
create temp table reader_got (n int, got bigint);
grant all on reader_got to public;
do $$
declare r record;
begin
  for r in select * from readers order by n loop
    perform pg_temp.act_as(r.who, r.aal);
    insert into reader_got select r.n, count(*) from public.notices where id = pg_temp.id('n_a1');
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select got from reader_got g where g.n = r.n), case when r.sees then 1::bigint else 0::bigint end, 'n_a1 (published to A1): ' || r.note || ' ' || case when r.sees then 'sees it' else 'does not see it' end)
  from readers r order by r.n;
select pg_temp.act_as('anon');
select is(pg_temp.try('select count(*) from public.notices'), '42501', 'anon cannot read notices');
select pg_temp.act_as('postgres');
-- expiry hides it from the audience, not from managers
update public.notices set expires_at = now() - interval '1 second', publish_at = now() - interval '1 day' where id = pg_temp.id('n_a1');
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.notices where id = pg_temp.id('n_a1')), 0::bigint, 'an expired notice is hidden from its audience');
select pg_temp.act_as('u_manager_a1');
select is((select count(*) from public.notices where id = pg_temp.id('n_a1')), 1::bigint, 'twin: a manager still sees it');
select pg_temp.act_as('postgres');
update public.notices set expires_at = null where id = pg_temp.id('n_a1');
-- an archived notice is hidden from the audience
update public.notices set status = 'archived', archived_at = now() where id = pg_temp.id('n_a2');
select pg_temp.act_as('u_staff_a2');
select is((select count(*) from public.notices where id = pg_temp.id('n_a2')), 0::bigint, 'an archived notice is hidden from its audience');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 7. A job-title change reveals only the matching notice and nothing else
-- ===========================================================================
-- three live A1 notices: for everyone, for Zamboni drivers (jt_x), for Lifeguards (jt_a)
insert into public.notices (id, organization_id, location_id, title, body, status, publish_at, published_at) values
  (pg_temp.id('j_all'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'j_all', 'x', 'draft', null, null),
  (pg_temp.id('j_x'),   pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'j_x',   'x', 'draft', null, null),
  (pg_temp.id('j_a'),   pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'j_a',   'x', 'draft', null, null);
insert into public.notice_audiences (organization_id, notice_id, location_id, job_title_id) values
  (pg_temp.id('org_a'), pg_temp.id('j_all'), pg_temp.id('loc_a1'), null),
  (pg_temp.id('org_a'), pg_temp.id('j_x'),   pg_temp.id('loc_a1'), pg_temp.id('jt_x')),
  (pg_temp.id('org_a'), pg_temp.id('j_a'),   pg_temp.id('loc_a1'), pg_temp.id('jt_a'));
update public.notices set status = 'published', publish_at = now() - interval '1 hour', published_at = now() - interval '1 hour' where title in ('j_all', 'j_x', 'j_a');
create temp table jt_seen (step text, titles text);
grant all on jt_seen to public;
create function pg_temp.jt_look(p_step text) returns void language plpgsql as $$
begin
  perform pg_temp.act_as('u_staff_a1b');
  insert into jt_seen select p_step, coalesce((select string_agg(title, ',' order by title) from public.notices where title like 'j\_%'), '');
  perform pg_temp.act_as('postgres');
end $$;
grant execute on function pg_temp.jt_look(text) to public;
select pg_temp.jt_look('before');
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id) values (pg_temp.id('pjt_j'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.id('jt_x'), pg_temp.id('loc_a1'));
select pg_temp.jt_look('x at A1');
delete from public.person_job_titles where id = pg_temp.id('pjt_j');
select pg_temp.jt_look('removed');
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id) values (pg_temp.id('pjt_j'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.id('jt_x'), pg_temp.id('loc_a2'));
select pg_temp.jt_look('x at A2');
delete from public.person_job_titles where id = pg_temp.id('pjt_j');
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id) values (pg_temp.id('pjt_j'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.id('jt_a'), null);
select pg_temp.jt_look('a everywhere');
select is((select titles from jt_seen where step = 'before'), 'j_all', 'job titles: with no title the staff member sees only the notice for everyone');
select is((select titles from jt_seen where step = 'x at A1'), 'j_all,j_x', 'job titles: given Zamboni at A1 they see exactly the Zamboni notice more (not the Lifeguard one)');
select is((select titles from jt_seen where step = 'removed'), 'j_all', 'job titles: and when the title is removed the notice is hidden again');
select is((select titles from jt_seen where step = 'x at A2'), 'j_all', 'job titles: a title held at another location reveals nothing at A1');
select is((select titles from jt_seen where step = 'a everywhere'), 'j_a,j_all', 'job titles: a title held everywhere reveals exactly the matching notice (Lifeguard), not the Zamboni one');
delete from public.person_job_titles where id = pg_temp.id('pjt_j');

-- ===========================================================================
-- 8. acknowledge_notice
-- ===========================================================================
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.acknowledge_notice(pg_temp.id('n_a1'))$$), 'ok', 'acknowledge: staff A1 acknowledges the notice published to them');
select pg_temp.act_as('postgres');
select is((select count(*) from public.acknowledgments where notice_id = pg_temp.id('n_a1')), 1::bigint, 'one acknowledgment row');
select results_eq($$select person_id, organization_id from public.acknowledgments where notice_id = pg_temp.id('n_a1')$$, $$select pg_temp.id('p_staff_a1'), pg_temp.id('org_a')$$, 'it is for the caller''s own person');
select is((select count(*) from public.outbox_events where type = 'notice.acknowledged' and entity_id = pg_temp.id('n_a1')), 1::bigint, 'and one notice.acknowledged event (ids only)');
select is((select payload ->> 'person_id' from public.outbox_events where type = 'notice.acknowledged' and entity_id = pg_temp.id('n_a1')), pg_temp.id('p_staff_a1')::text, 'naming the person');
create temp table ack1 as select id, acknowledged_at from public.acknowledgments where notice_id = pg_temp.id('n_a1');
grant all on ack1 to public;
select pg_temp.act_as('u_staff_a1');
select is(public.acknowledge_notice(pg_temp.id('n_a1')), (select acknowledged_at from ack1), 'acknowledge is idempotent: the second call returns the first time');
select is(public.acknowledge_notice(pg_temp.id('n_a1')), (select acknowledged_at from ack1), 'and so does a third');
select pg_temp.act_as('postgres');
select is((select count(*) from public.acknowledgments where notice_id = pg_temp.id('n_a1')), 1::bigint, 'still exactly one acknowledgment row');
select is((select id from public.acknowledgments where notice_id = pg_temp.id('n_a1')), (select id from ack1), 'with the same id');
select is((select count(*) from public.outbox_events where type = 'notice.acknowledged' and entity_id = pg_temp.id('n_a1')), 1::bigint, 'and still exactly one notice.acknowledged event (only the first call emits)');
-- refused outside the audience, all with the same uniform answer
create temp table ackref (n int, who text, aal text, notice text, label text);
insert into ackref values
  (1, 'u_staff_a2',    'aal2', 'n_a1',  'staff at another location'),
  (2, 'u_manager_a2',  'aal2', 'n_a1',  'a manager at another location'),
  (3, 'u_staff_b1',    'aal2', 'n_a1',  'a user of another organization'),
  (4, 'u_noaccount',   'aal2', 'n_a1',  'a user with no account'),
  (5, 'u_disabled_a',  'aal2', 'n_a1',  'a disabled account'),
  (6, 'u_staff_a1',    'aal2', 'n_la',  'an archived notice'),
  (7, 'u_staff_a1',    'aal2', 'n_a2',  'a notice for another location (archived too)'),
  (8, 'u_staff_a1',    'aal2', 'r_a1_all', 'a draft addressed to them'),
  (9, 'u_staff_a1',    'aal2', 'r_org_jt', 'a draft for a title they hold'),
  (10, 'u_orgadmin_a', 'aal1', 'n_a1',  'org admin A at aal1'),
  (11, 'u_platform',   'aal2', 'n_a1',  'a platform admin (not a member, no person)'),
  (12, 'u_staff_a1',   'aal2', null,    'a notice that does not exist'),
  (13, 'u_staff_a1b',  'aal2', 'j_x',   'a notice for a title they do not hold');
create temp table ackref_res (n int, res text);
grant all on ackref_res to public;
do $$
declare r record;
begin
  for r in select * from ackref order by n loop
    perform pg_temp.act_as(r.who, r.aal);
    insert into ackref_res values (r.n, pg_temp.try_msg(format('select public.acknowledge_notice(%L)', coalesce(pg_temp.id(r.notice), gen_random_uuid()))));
    perform pg_temp.act_as('postgres');
  end loop;
end $$;
select is((select res from ackref_res a where a.n = r.n), '42501 not allowed', 'acknowledge refused (uniform 42501): ' || r.label) from ackref r order by r.n;
select is((select count(*) from public.acknowledgments), 1::bigint, 'none of those refusals wrote an acknowledgment');
select pg_temp.act_as('anon');
select is(pg_temp.try('select public.acknowledge_notice(gen_random_uuid())'), '42501', 'acknowledge: anon cannot call it');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select public.acknowledge_notice(pg_temp.id('n_a1'))$$), '42501 not signed in', 'acknowledge: the server key with no user is refused');
select pg_temp.act_as('postgres');
-- twins: others in the audience can; an expired notice cannot be acknowledged
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.acknowledge_notice(pg_temp.id('n_a1'))$$), 'ok', 'twin: manager A1 (in the audience) can acknowledge');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.acknowledge_notice(pg_temp.id('n_a1'))$$), 'ok', 'twin: org admin A at aal2 (in the audience) can acknowledge');
select pg_temp.act_as('u_staff_a1b');
select is(pg_temp.try_msg($$select public.acknowledge_notice(pg_temp.id('j_all'))$$), 'ok', 'twin: staff A1b acknowledges the notice for everyone');
select pg_temp.act_as('postgres');
update public.notices set expires_at = now() - interval '1 second', publish_at = now() - interval '1 day' where id = pg_temp.id('j_all');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.acknowledge_notice(pg_temp.id('j_all'))$$), '42501 not allowed', 'acknowledge: an expired notice cannot be acknowledged');
select pg_temp.act_as('postgres');
-- nobody can write acknowledgments any other way
select pg_temp.act_as('postgres');
create temp table ackw (who text, op text, res text);
grant all on ackw to public;
do $$
declare w text;
begin
  foreach w in array array['u_staff_a1', 'u_staff_a2', 'u_manager_a1', 'u_locadmin_a1', 'u_orgadmin_a', 'u_platform', 'u_orgadmin_b', 'anon', 'service_role'] loop
    perform pg_temp.act_as(w);
    insert into ackw values
      (w, 'insert for self', pg_temp.try($q$insert into public.acknowledgments (organization_id, notice_id, person_id) values (pg_temp.id('org_a'), pg_temp.id('n_a2'), pg_temp.id('p_staff_a1'))$q$)),
      (w, 'insert for someone else', pg_temp.try($q$insert into public.acknowledgments (organization_id, notice_id, person_id) values (pg_temp.id('org_a'), pg_temp.id('n_a1'), pg_temp.id('p_staff_a2'))$q$)),
      (w, 'update', pg_temp.try($q$update public.acknowledgments set acknowledged_at = now() where notice_id = pg_temp.id('n_a1')$q$)),
      (w, 'update person', pg_temp.try($q$update public.acknowledgments set person_id = pg_temp.id('p_staff_a2') where notice_id = pg_temp.id('n_a1')$q$)),
      (w, 'delete', pg_temp.try($q$delete from public.acknowledgments where notice_id = pg_temp.id('n_a1')$q$)),
      (w, 'truncate', pg_temp.try('truncate public.acknowledgments cascade'));
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select string_agg(distinct res, ',') from ackw where who = w.who), '42501', w.who || ': cannot insert, update, delete or truncate acknowledgments (6 attempts)')
  from (values ('u_staff_a1'), ('u_staff_a2'), ('u_manager_a1'), ('u_locadmin_a1'), ('u_orgadmin_a'), ('u_platform'), ('u_orgadmin_b'), ('anon'), ('service_role')) w (who);
select is((select count(*) from public.acknowledgments), 4::bigint, 'and the 4 real acknowledgments (staff A1, manager A1, org admin A, staff A1b) are all still there');
select is(pg_temp.try($$update public.acknowledgments set acknowledged_at = now() - interval '1 year'$$), '42501', 'append-only: even the owner cannot update an acknowledgment (trigger)');
select is(pg_temp.try($$update public.acknowledgments set person_id = pg_temp.id('p_staff_a2')$$), '42501', 'append-only: nor change who acknowledged');
select is(pg_temp.try($$insert into public.acknowledgments (organization_id, notice_id, person_id) values (pg_temp.id('org_a'), pg_temp.id('n_a1'), pg_temp.id('p_staff_a1'))$$), '23505', 'one acknowledgment per person and notice (unique)');
select is(pg_temp.try($$insert into public.acknowledgments (organization_id, notice_id, person_id) values (pg_temp.id('org_b'), pg_temp.id('n_a1'), pg_temp.id('p_staff_b1'))$$), '23503', 'an acknowledgment cannot cross organizations (composite key)');
select ok(not has_table_privilege('authenticated', 'public.acknowledgments', 'insert,update,delete,truncate') and not has_any_column_privilege('authenticated', 'public.acknowledgments', 'insert,update'), 'authenticated holds no write privilege of any kind on acknowledgments');
select ok(not has_table_privilege('service_role', 'public.acknowledgments', 'insert,update,delete,truncate'), 'service_role holds no write privilege on acknowledgments');
-- who reads acknowledgments
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.acknowledgments), 1::bigint, 'staff A1 reads only their own acknowledgment');
select pg_temp.act_as('u_staff_a1b');
select is((select count(*) from public.acknowledgments), 1::bigint, 'staff A1b reads only their own acknowledgment');
select pg_temp.act_as('u_staff_a2');
select is((select count(*) from public.acknowledgments), 0::bigint, 'staff A2 reads none');
select pg_temp.act_as('u_manager_a1');
select is((select count(*) from public.acknowledgments where notice_id = pg_temp.id('n_a1')), 3::bigint, 'manager A1 (manages n_a1) sees every acknowledgment of n_a1: who acknowledged');
select is((select count(*) from public.acknowledgments where notice_id = pg_temp.id('j_all')), 1::bigint, 'and those of notices they manage at A1 (j_all)');
select pg_temp.act_as('u_manager_a2');
select is((select count(*) from public.acknowledgments where notice_id in (pg_temp.id('n_a1'), pg_temp.id('j_all'))), 0::bigint, 'manager A2 sees no acknowledgments of A1 notices');
select pg_temp.act_as('u_orgadmin_b');
select is((select count(*) from public.acknowledgments), 0::bigint, 'org admin B sees none');
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.acknowledgments), 4::bigint, 'org admin A sees all 4');
select pg_temp.act_as('u_orgadmin_a', 'aal1');
select is((select count(*) from public.acknowledgments), 0::bigint, 'org admin A at aal1 sees none');
select pg_temp.act_as('postgres');

select pg_temp.act_as('postgres');
select * from finish();
rollback;
