-- Phase 2 review fixes (000600 R9, R10, R15): voluntary MFA (a verified factor forces aal2), platform-admin accounts must be active,
-- rate-limit keys are normalised, and can_resend_person_invite. Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(108);

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

create function pg_temp.f(p_sql text) returns text language plpgsql as $$
declare r text;
begin
  execute p_sql into r;
  return coalesce(r, 'null');
exception when others then return sqlstate || ' ' || sqlerrm;
end $$;
grant execute on function pg_temp.f(text) to public;
-- the level private.person_effective_level gives for <target> when <who> is signed in (set as claims, evaluated as the owner)
create function pg_temp.lvl(p_who text, p_aal text, p_target text, p_module text default 'tasks') returns text language plpgsql as $$
declare r text;
begin
  perform set_config('request.jwt.claims', jsonb_build_object('sub', pg_temp.id(p_who), 'role', 'authenticated', 'aal', p_aal)::text, true);
  r := coalesce(private.person_effective_level(pg_temp.id('org_a'), pg_temp.id(p_target), pg_temp.id('loc_a1'), p_module)::text, 'null');
  perform set_config('request.jwt.claims', '', true);
  return r;
end $$;
grant execute on function pg_temp.lvl(text, text, text, text) to public;

-- ===========================================================================
-- 1. Voluntary MFA: a verified factor makes the user a non-member until they are at aal2
-- ===========================================================================
-- staff A1 has no factor yet
select pg_temp.act_as('u_staff_a1', 'aal1');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), '1', 'no factor, aal1: staff A1 is a member of one organization');
select is(pg_temp.f($$select public.session_needs_mfa()$$), 'false', 'no factor, aal1: no second step is needed');
select is(pg_temp.f($$select public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks', 'view')$$), 'true', 'no factor, aal1: staff A1 can view tasks');
select pg_temp.act_as('postgres');
-- an unverified factor (enrolment started, not finished) changes nothing
insert into auth.mfa_factors (id, user_id, factor_type, status, created_at, updated_at) values (pg_temp.id('f_unver'), pg_temp.id('u_staff_a1'), 'totp', 'unverified', now(), now());
select pg_temp.act_as('u_staff_a1', 'aal1');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), '1', 'unverified factor, aal1: still a member');
select is(pg_temp.f($$select public.session_needs_mfa()$$), 'false', 'unverified factor, aal1: no second step is needed');
select is(pg_temp.f($$select public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks', 'view')$$), 'true', 'unverified factor, aal1: still has the permission');
select pg_temp.act_as('postgres');
-- verify the factor
update auth.mfa_factors set status = 'verified' where id = pg_temp.id('f_unver');
select is(private.user_has_verified_mfa(pg_temp.id('u_staff_a1')), true, 'user_has_verified_mfa: true for a verified factor');
select is(private.user_has_verified_mfa(pg_temp.id('u_staff_a2')), false, 'user_has_verified_mfa: false for a user with none');
select is(private.user_has_verified_mfa(null), false, 'user_has_verified_mfa: false for null');
select is(private.user_has_verified_mfa(gen_random_uuid()), false, 'user_has_verified_mfa: false for an unknown user');
select pg_temp.act_as('u_staff_a1', 'aal1');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), '0', 'verified factor, aal1: staff A1 is a member of nothing (the password alone no longer opens the account)');
select is(pg_temp.f($$select public.session_needs_mfa()$$), 'true', 'verified factor, aal1: the second step is required');
select is(pg_temp.f($$select public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks', 'view')$$), 'false', 'verified factor, aal1: no permission');
select is(pg_temp.f($$select count(*) from public.people$$), '0', 'verified factor, aal1: no people rows are visible');
select is(pg_temp.f($$select count(*) from public.locations$$), '0', 'verified factor, aal1: no locations are visible');
select is(pg_temp.f($$select count(*) from public.my_notices(pg_temp.id('org_a'))$$), '0', 'verified factor, aal1: my_notices is empty');
select is(pg_temp.f($$select public.can_resend_person_invite(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'))$$), 'false', 'verified factor, aal1: nothing to resend either');
select pg_temp.act_as('u_staff_a1', 'aal2');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), '1', 'verified factor, aal2: a member again');
select is(pg_temp.f($$select public.session_needs_mfa()$$), 'false', 'verified factor, aal2: no second step is needed');
select is(pg_temp.f($$select public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks', 'view')$$), 'true', 'verified factor, aal2: full access');
select cmp_ok((select count(*) from public.people), '>', 0::bigint, 'verified factor, aal2: people are visible again');
-- the factor belongs to one user only
select pg_temp.act_as('u_staff_a2', 'aal1');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), '1', 'twin: staff A2 (no factor) at aal1 is unaffected by staff A1''s factor');
select pg_temp.act_as('u_manager_a1', 'aal1');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), '1', 'twin: manager A1 (no factor) at aal1 is unaffected too');
-- a session with no aal claim at all counts as aal1
select pg_temp.act_as('u_staff_a1', 'none');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), '0', 'verified factor, no aal claim: treated as aal1');
select pg_temp.act_as('postgres');
-- seen from someone else's session the factor changes nothing: an org admin at aal2 still has a level over staff A1
select isnt(pg_temp.lvl('u_orgadmin_a', 'aal2', 'p_staff_a1'), 'null', 'an org admin at aal2 reads staff A1''s level (the factor only restricts staff A1''s own session)');
select is(pg_temp.lvl('u_staff_a1', 'aal1', 'p_staff_a1'), 'null', 'staff A1 at aal1 with a verified factor has no level on their own person');
select isnt(pg_temp.lvl('u_staff_a1', 'aal2', 'p_staff_a1'), 'null', 'twin: at aal2 they have one');
select isnt(pg_temp.lvl('u_manager_a1', 'aal1', 'p_manager_a1'), 'null', 'twin: manager A1 with no factor has a level at aal1');
-- other factor types and a removed factor
insert into auth.mfa_factors (id, user_id, factor_type, status, created_at, updated_at) values (pg_temp.id('f_web'), pg_temp.id('u_staff_a2'), 'webauthn', 'verified', now(), now());
select pg_temp.act_as('u_staff_a2', 'aal1');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), '0', 'a verified webauthn factor counts the same');
select pg_temp.act_as('postgres');
delete from auth.mfa_factors where id = pg_temp.id('f_web');
select pg_temp.act_as('u_staff_a2', 'aal1');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), '1', 'twin: once the factor is removed the person is a member at aal1 again');
select pg_temp.act_as('postgres');
-- an admin with no factor: admin tier still needs aal2 (unchanged rule), a verified factor changes nothing there
select pg_temp.act_as('u_orgadmin_a', 'aal1');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), '0', 'admin tier at aal1 is a non-member (unchanged)');
select is(pg_temp.f($$select public.session_needs_mfa()$$), 'true', 'and needs the second step (unchanged)');
select pg_temp.act_as('postgres');
-- user_has_verified_mfa is not a public API
select is(has_function_privilege('authenticated', 'private.user_has_verified_mfa(uuid)', 'execute'), false, 'authenticated cannot call user_has_verified_mfa');
select is(has_function_privilege('anon', 'private.user_has_verified_mfa(uuid)', 'execute'), false, 'anon cannot call it either');
select is(has_table_privilege('authenticated', 'auth.mfa_factors', 'select'), false, 'and authenticated cannot read the factor table');
-- no factor table at all: the helper treats it as "no factor" (checked as the owner against a dropped table in this transaction)
-- On hosted Supabase the table belongs to supabase_auth_admin and the test role cannot drop it; there the
-- two checks below are skipped or assert the unchanged state, and the stand-in run covers the missing-table path.
create temp table mfa_drop (ok boolean);
do $$
begin
  begin
    drop table auth.mfa_factors cascade;
    insert into mfa_drop values (true);
  exception when insufficient_privilege then
    insert into mfa_drop values (false);
  end;
end
$$;
select ok as mfa_dropped from mfa_drop \gset
select case when :'mfa_dropped'::boolean
  then is(private.user_has_verified_mfa(pg_temp.id('u_staff_a1')), false, 'with no factor table the answer is false (nothing can be verified)')
  else skip('the factor table cannot be dropped by this role', 1) end;
select pg_temp.act_as('u_staff_a1', 'aal1');
select is(pg_temp.f($$select count(*) from public.auth_org_ids()$$), case when :'mfa_dropped'::boolean then '1' else '0' end,
  'staff A1 is a member at aal1 again only when the factor table is gone');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 2. A platform admin who is also a person: a disabled account or archived person gets no level
-- ===========================================================================
insert into public.people (id, organization_id, first_name, last_name) values (pg_temp.id('p_plat'), pg_temp.id('org_a'), 'Pat', 'PlatformA');
insert into public.accounts (id, organization_id, person_id, user_id) values (pg_temp.id('acct_plat'), pg_temp.id('org_a'), pg_temp.id('p_plat'), pg_temp.id('u_platform'));
select is(pg_temp.lvl('u_platform', 'aal2', 'p_plat'), 'admin', 'platform admin with an active account and person: admin level');
select is(pg_temp.lvl('u_platform', 'aal1', 'p_plat'), 'null', 'at aal1: no level');
select is(pg_temp.lvl('u_orgadmin_a', 'aal2', 'p_plat'), 'admin', 'seen by an org admin: still admin (the platform admin''s own aal does not matter for someone else''s view)');
update public.accounts set disabled_at = now() where id = pg_temp.id('acct_plat');
select is(pg_temp.lvl('u_platform', 'aal2', 'p_plat'), 'null', 'disabled account: no level');
select is(pg_temp.lvl('u_orgadmin_a', 'aal2', 'p_plat'), 'null', 'disabled account, seen by an org admin: no level');
update public.accounts set disabled_at = null where id = pg_temp.id('acct_plat');
select is(pg_temp.lvl('u_platform', 'aal2', 'p_plat'), 'admin', 'twin: re-enabled: admin again');
update public.people set archived_at = now() where id = pg_temp.id('p_plat');
select is(pg_temp.lvl('u_platform', 'aal2', 'p_plat'), 'null', 'archived person: no level');
select is(pg_temp.lvl('u_orgadmin_a', 'aal2', 'p_plat'), 'null', 'archived person, seen by an org admin: no level');
update public.people set archived_at = null where id = pg_temp.id('p_plat');
select is(pg_temp.lvl('u_platform', 'aal2', 'p_plat'), 'admin', 'twin: unarchived: admin again');
-- a non-platform person for contrast is unaffected by the platform rule

-- ===========================================================================
-- 3. Rate-limit keys are normalised
-- ===========================================================================
select is(private.normalize_rate_limit_key(E'  A B​C\t\n　﻿ '), 'abc', 'normalize: whitespace of every kind and zero-width characters are removed, then lower case');
select is(private.normalize_rate_limit_key('Mixed.Case@Example.COM'), 'mixed.case@example.com', 'normalize: lower case');
select is(private.normalize_rate_limit_key(E'  '), '', 'normalize: only whitespace gives the empty string');
select is(private.normalize_rate_limit_key(null), null, 'normalize: null stays null');
select pg_temp.act_as('service_role');
select is(pg_temp.f($$select public.consume_rate_limit('norm', 'victim@x.test', 1, 60)$$), 'true', 'the first hit for victim@x.test is allowed');
select is(pg_temp.f(format('select public.consume_rate_limit(%L, %L, 1, 60)', 'norm', v.k)), 'false', 'rate limit: ' || v.label || ' is the same key (refused)')
from (values (1, 'VICTIM@X.TEST', 'upper case'), (2, ' victim@x.test', 'a leading space'), (3, E'victim@x.test\n', 'a trailing newline'), (4, E'vic tim@x.test', 'a space inside'),
             (5, E'victim@x.test ', 'a trailing no-break space'), (6, E'victim@​x.test', 'a zero-width space inside'), (7, E'　victim@x.test', 'an ideographic space'),
             (8, E'victim@x.test﻿', 'a byte-order mark'), (9, E'victim\t@x.test', 'a tab'), (10, E'victim@x.test ', 'a line separator'),
             (11, E' vi ctim@x.test', 'thin and figure spaces'), (12, E'victim@x.test ', 'a narrow no-break space'), (13, E'victim@x.test⁠', 'a word joiner')) v (n, k, label) order by v.n;
select is(pg_temp.f($$select public.consume_rate_limit('norm', 'victim2@x.test', 1, 60)$$), 'true', 'twin: a really different key has its own count');
select is(pg_temp.f($$select public.consume_rate_limit('norm2', 'victim@x.test', 1, 60)$$), 'true', 'twin: the same key in another bucket has its own count');
select is(pg_temp.f(format('select public.consume_rate_limit(%L, %L, 1, 60)', 'norm', k)), '22023 invalid key', 'a key of only whitespace is refused: ' || label)
from (values (E' ', 'a space'), (E'\t\n', 'tab and newline'), (E' ', 'no-break space'), (E'​', 'zero-width space'), (E'　﻿', 'ideographic space and BOM'), ('', 'empty')) v (k, label);
select is(pg_temp.f($$select public.consume_rate_limit('norm', null, 1, 60)$$), '22023 invalid key', 'a null key is refused');
select is(pg_temp.f(format('select public.consume_rate_limit(%L, %L, 1, 60)', 'norm', repeat('a', 513))), '22023 invalid key', 'a key of 513 characters is refused');
select is(pg_temp.f(format('select public.consume_rate_limit(%L, %L, 5, 60)', 'norm', repeat('a', 512))), 'true', 'twin: 512 characters is fine');
select is(pg_temp.f(format('select public.consume_rate_limit(%L, %L, 5, 60)', 'norm', repeat(' ', 40) || repeat('a', 512))), 'true', 'the length is checked after normalising: padding does not push a 512 character key over the limit (and counts as the same key)');
select is(pg_temp.f($$select public.consume_rate_limit('Bad Bucket', 'k', 1, 60)$$), '22023 invalid bucket', 'the bucket is not normalised: an invalid bucket is refused');
select pg_temp.act_as('postgres');
select is((select count(*) from private.rate_limit_counters where bucket = 'norm'), 3::bigint, 'the 13 spellings produced one counter in all: three rows for the bucket (victim, victim2, the long key)') ;

-- ===========================================================================
-- 4. can_resend_person_invite
-- ===========================================================================
create temp table rs (n int, who text, aal text, org text, target text, expect text, note text);
insert into rs values
  (1,  'u_orgadmin_a',  'aal2', 'org_a', 'p_staff_a1',     'true',  'org admin, staff with a pending invite'),
  (2,  'u_orgadmin_a',  'aal2', 'org_a', 'p_manager_a1',   'true',  'org admin, manager with a pending invite'),
  (3,  'u_platform',    'aal2', 'org_a', 'p_staff_a1',     'true',  'platform admin'),
  (4,  'u_locadmin_a1', 'aal2', 'org_a', 'p_staff_a1',     'true',  'location admin A1, staff at A1'),
  (5,  'u_locadmin_a1', 'aal2', 'org_a', 'p_staff_a2',     'false', 'location admin A1, staff at A2 (outside their location)'),
  (6,  'u_manager_a1',  'aal2', 'org_a', 'p_staff_a1',     'false', 'a manager cannot manage accounts'),
  (7,  'u_staff_a1',    'aal2', 'org_a', 'p_staff_a2',     'false', 'staff'),
  (8,  'u_orgadmin_a',  'aal2', 'org_a', 'p_orgadmin_a',   'false', 'an org admin for themselves (not outranked)'),
  (9,  'u_locadmin_a1', 'aal2', 'org_a', 'p_orgadmin_a',   'false', 'a location admin for the org admin (outranked)'),
  (10, 'u_orgadmin_a',  'aal1', 'org_a', 'p_staff_a1',     'false', 'org admin at aal1'),
  (11, 'u_orgadmin_b',  'aal2', 'org_a', 'p_staff_a1',     'false', 'an org admin of another organization'),
  (12, 'u_orgadmin_a',  'aal2', 'org_b', 'p_staff_b1',     'false', 'org admin A for organization B''s person'),
  (13, 'u_orgadmin_a',  'aal2', 'org_a', 'p_staff_b1',     'false', 'a person of organization B named with organization A'),
  (14, 'u_orgadmin_a',  'aal2', 'org_a', 'p_unassigned_a', 'false', 'a person with no account'),
  (15, 'u_orgadmin_a',  'aal2', 'org_a', 'p_disabled_a',   'false', 'a person whose account is disabled'),
  (16, 'u_orgadmin_a',  'aal2', 'org_a', 'p_nobody',       'false', 'a person who does not exist'),
  (17, 'anon',          'aal2', 'org_a', 'p_staff_a1',     '42501 permission denied for function can_resend_person_invite', 'anon (no execute right)'),
  (18, 'service_role',  'aal2', 'org_a', 'p_staff_a1',     'false', 'the server key with no user'),
  (19, 'u_noaccount',   'aal2', 'org_a', 'p_staff_a1',     'false', 'a user with no account');
-- p_nobody has no fixed id row: pg_temp.id is a hash of the name, so it names a person that does not exist
grant all on rs to public;
create temp table rs_got (n int, got text);
grant all on rs_got to public;
do $$
declare r record;
begin
  for r in select * from rs order by n loop
    perform pg_temp.act_as(r.who, r.aal);
    insert into rs_got values (r.n, pg_temp.f(format('select public.can_resend_person_invite(%L, %L)', pg_temp.id(r.org), pg_temp.id(r.target))));
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select got from rs_got g where g.n = r.n), r.expect, 'can_resend_person_invite: ' || r.note) from rs r order by r.n;
select is(pg_temp.f($$select public.can_resend_person_invite(null, null)$$), 'false', 'null arguments (as the owner, with no user): false');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.f($$select public.can_resend_person_invite(null, pg_temp.id('p_staff_a1'))$$), 'false', 'a null organization: false');
select is(pg_temp.f($$select public.can_resend_person_invite(pg_temp.id('org_a'), null)$$), 'false', 'a null person: false');
select pg_temp.act_as('postgres');
-- the invite state
update auth.users set last_sign_in_at = now() where id = pg_temp.id('u_staff_a1');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.f($$select public.can_resend_person_invite(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'))$$), 'false', 'after the person has signed in: false');
select pg_temp.act_as('postgres');
update auth.users set last_sign_in_at = null, email_confirmed_at = now() where id = pg_temp.id('u_staff_a1');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.f($$select public.can_resend_person_invite(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'))$$), 'false', 'after the address is confirmed: false');
select is(pg_temp.f($$select public.can_resend_person_invite(pg_temp.id('org_a'), pg_temp.id('p_staff_a2'))$$), 'true', 'twin: another person who has done neither: true');
select pg_temp.act_as('postgres');
update public.people set archived_at = now() where id = pg_temp.id('p_staff_a2');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.f($$select public.can_resend_person_invite(pg_temp.id('org_a'), pg_temp.id('p_staff_a2'))$$), 'false', 'an archived person: false');
select pg_temp.act_as('postgres');
update public.people set archived_at = null where id = pg_temp.id('p_staff_a2');
update public.accounts set disabled_at = now() where id = pg_temp.id('acct_staff_a2');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.f($$select public.can_resend_person_invite(pg_temp.id('org_a'), pg_temp.id('p_staff_a2'))$$), 'false', 'a disabled account: false');
select pg_temp.act_as('postgres');
update public.accounts set disabled_at = null where id = pg_temp.id('acct_staff_a2');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.f($$select public.can_resend_person_invite(pg_temp.id('org_a'), pg_temp.id('p_staff_a2'))$$), 'true', 'twin: re-enabled: true');
select pg_temp.act_as('postgres');
select is(has_function_privilege('anon', 'public.can_resend_person_invite(uuid, uuid)', 'execute'), false, 'anon has no execute right on it');
select is(has_function_privilege('authenticated', 'public.can_resend_person_invite(uuid, uuid)', 'execute'), true, 'authenticated does (the invite screen asks it)');

select * from finish();
rollback;
