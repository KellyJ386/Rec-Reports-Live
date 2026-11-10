-- Immutable columns (organization_id and friends) and the append-only audit log
-- (docs/DATA_MODEL.md "Audit log", docs/SECURITY.md "Audit log").
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(56 + 2 * (select count(*)::int from pg_trigger g where g.tgname = 'zz_audit' and not g.tgisinternal and g.tgrelid in (select c.oid from pg_class c where c.relnamespace = 'public'::regnamespace)) + 4 * (select count(*)::int from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p')
    and c.relname not in ('audit_log', 'modules', 'platform_admins')));

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

-- ===========================================================================
-- Immutability
-- ===========================================================================
-- Per table that has organization_id (organizations: id) the column cannot change.
--   authenticated: no column grant (42501).
--   service_role bypasses RLS and grants, so the trigger stops it (23514).
--   role_default_permissions derives organization_id from the immutable role_id by trigger, so the
--   attempt is a silent no-op there; the rows must stay where they are either way.
create temp view it as
  select c.relname, case when c.relname = 'organizations' then 'id' else 'organization_id' end as col
  from pg_class c
  where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') and c.relname not in ('audit_log', 'modules', 'platform_admins')
    and (c.relname = 'organizations'
         or exists (select 1 from pg_attribute a where a.attrelid = c.oid and a.attname = 'organization_id' and not a.attisdropped));
grant select on it to public;
create function pg_temp.move_sql(p_table text, p_col text, p_from uuid, p_to uuid) returns text language sql immutable as $$
  select format('update public.%I set %I = %L where %I = %L', p_table, p_col, p_to, p_col, p_from)
$$;
grant execute on function pg_temp.move_sql(text, text, uuid, uuid) to public;
create temp table before_counts as
  select i.relname, pg_temp.cnt(i.relname, format('%I = %L', i.col, pg_temp.id('org_a'))) as n_a,
         pg_temp.cnt(i.relname, format('%I = %L', i.col, pg_temp.id('org_b'))) as n_b from it i;

select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try(pg_temp.move_sql(i.relname, i.col, pg_temp.id('org_a'), pg_temp.id('org_b'))), '42501',
  'org admin A cannot change ' || i.relname || '.' || i.col) from pg_temp.it i order by i.relname;
select pg_temp.act_as('postgres');
set local role service_role;
select is(pg_temp.try(pg_temp.move_sql(i.relname, i.col, pg_temp.id('org_a'), pg_temp.id('org_b'))),
  case when i.relname = 'role_default_permissions' then 'ok' else '23514' end,
  'service_role cannot change ' || i.relname || '.' || i.col || ' either') from pg_temp.it i order by i.relname;
select pg_temp.act_as('postgres');
select is(pg_temp.cnt(i.relname, format('%I = %L', i.col, pg_temp.id('org_a'))), (select b.n_a from before_counts b where b.relname = i.relname),
  i.relname || ': the org A rows are all still in org A') from pg_temp.it i order by i.relname;
select is(pg_temp.cnt(i.relname, format('%I = %L', i.col, pg_temp.id('org_b'))), (select b.n_b from before_counts b where b.relname = i.relname),
  i.relname || ': no row moved into org B') from pg_temp.it i order by i.relname;

-- Other immutable columns, for service_role (authenticated has no grant on them).
set local role service_role;
select is(pg_temp.try($q$update public.spaces set location_id = pg_temp.id('loc_a2') where id = pg_temp.id('space_a1')$q$), '23514', 'spaces.location_id is immutable');
select is(pg_temp.try($q$update public.space_hours set space_id = pg_temp.id('space_a2') where id = pg_temp.id('hours_a1')$q$), '23514', 'space_hours.space_id is immutable');
select is(pg_temp.try($q$update public.space_closures set location_id = pg_temp.id('loc_a2') where id = pg_temp.id('closure_a1')$q$), '23514', 'space_closures.location_id is immutable');
select is(pg_temp.try($q$update public.space_kinds set key = 'renamed' where organization_id = pg_temp.id('org_a') and key = 'pool'$q$), '23514', 'space_kinds.key is immutable');
select is(pg_temp.try($q$update public.roles set key = 'renamed' where id = pg_temp.id('role_custom_a')$q$), '23514', 'roles.key is immutable');
select is(pg_temp.try($q$update public.role_assignments set person_id = pg_temp.id('p_staff_a2') where id = pg_temp.id('ra_staff_a1')$q$), '23514', 'role_assignments.person_id is immutable');
select is(pg_temp.try($q$update public.user_permissions set module_key = 'tasks' where id = pg_temp.id('up_a')$q$), '23514', 'user_permissions.module_key is immutable');
select is(pg_temp.try($q$update public.accounts set user_id = pg_temp.id('u_noaccount') where id = pg_temp.id('acct_staff_a1')$q$), '23514', 'accounts.user_id is immutable');
select is(pg_temp.try($q$update public.people set id = gen_random_uuid() where id = pg_temp.id('p_staff_a1')$q$), '23514', 'people.id is immutable');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try($q$update public.spaces set id = gen_random_uuid() where id = pg_temp.id('space_a1')$q$), '42501', 'authenticated cannot change spaces.id');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- audit_log is append-only for everyone
-- ===========================================================================
select ok(has_table_privilege('authenticated', 'public.audit_log', 'select') and not has_table_privilege('authenticated', 'public.audit_log', 'insert,update,delete,truncate'),
  'authenticated: select on audit_log only');
select ok(has_table_privilege('service_role', 'public.audit_log', 'select') and not has_table_privilege('service_role', 'public.audit_log', 'insert,update,delete,truncate,trigger,references'),
  'service_role: select on audit_log, nothing else');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($q$update public.audit_log set action = 'insert'$q$), '42501', 'org admin A cannot update audit_log');
select is(pg_temp.try($q$delete from public.audit_log$q$), '42501', 'org admin A cannot delete from audit_log');
select is(pg_temp.try($q$truncate public.audit_log$q$), '42501', 'org admin A cannot truncate audit_log');
select is(pg_temp.try($q$insert into public.audit_log (actor_role, action, table_schema, table_name) values ('authenticated', 'insert', 'public', 'x')$q$), '42501', 'org admin A cannot insert into audit_log');
select pg_temp.act_as('u_platform');
select is(pg_temp.try($q$delete from public.audit_log$q$), '42501', 'a platform admin cannot delete from audit_log');
select pg_temp.act_as('anon');
select is(pg_temp.try($q$select count(*) from public.audit_log$q$), '42501', 'anon cannot read audit_log');
select pg_temp.act_as('postgres');
set local role service_role;
select is(pg_temp.try($q$update public.audit_log set action = 'insert'$q$), '42501', 'service_role cannot update audit_log');
select is(pg_temp.try($q$delete from public.audit_log$q$), '42501', 'service_role cannot delete from audit_log');
select is(pg_temp.try($q$truncate public.audit_log$q$), '42501', 'service_role cannot truncate audit_log');
select is(pg_temp.try($q$insert into public.audit_log (actor_role, action, table_schema, table_name, row_id) values ('service_role', 'insert', 'public', 'sensitive_view', 'r1')$q$), '42501',
  'service_role cannot insert into audit_log either (rows come only from the audit trigger)');
select pg_temp.act_as('postgres');
-- the owner is stopped by the trigger, not by privileges
select throws_ok($q$update public.audit_log set action = 'delete'$q$, '42501', 'audit_log is append-only (UPDATE blocked)', 'the owner cannot update audit_log (trigger)');
select throws_ok($q$delete from public.audit_log$q$, '42501', 'audit_log is append-only (DELETE blocked)', 'the owner cannot delete from audit_log (trigger)');
select throws_ok($q$truncate public.audit_log$q$, '42501', 'audit_log is append-only (TRUNCATE blocked)', 'the owner cannot truncate audit_log (trigger)');
select is((select count(*) from public.audit_log where table_name = 'sensitive_view' and row_id = 'r1'), 0::bigint, 'and no forged row is there');

-- ===========================================================================
-- Nobody can TRUNCATE an audited table (generated from the catalog)
-- ===========================================================================
create temp view audited as
  select c.relname from pg_trigger g join pg_class c on c.oid = g.tgrelid
  where g.tgname = 'zz_audit' and not g.tgisinternal and c.relnamespace = 'public'::regnamespace;
grant select on audited to public;
set local role service_role;
select is(pg_temp.try('truncate table public.' || quote_ident(a.relname)), '42501', 'service_role cannot truncate ' || a.relname) from pg_temp.audited a order by a.relname;
select pg_temp.act_as('postgres');
-- CASCADE so that foreign keys do not refuse first (0A000); the guard triggers then raise 42501.
select is(pg_temp.try('truncate table public.' || quote_ident(a.relname) || ' cascade'), '42501', 'the owner cannot truncate ' || a.relname || ' (guard trigger)') from pg_temp.audited a order by a.relname;
select ok((select bool_and(pg_temp.cnt(a.relname) > 0 or a.relname in ('platform_admins')) from pg_temp.audited a) , 'no audited table was emptied by those attempts');

-- ===========================================================================
-- A tenant write produces exactly one audit row, with the right actor, org and location
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
insert into public.spaces (id, organization_id, location_id, space_kind_id, name)
values (pg_temp.id('space_new'), pg_temp.id('org_a'), pg_temp.id('loc_a1'),
        (select id from public.space_kinds where organization_id = pg_temp.id('org_a') and key = 'pool'), 'Audited Space');
select pg_temp.act_as('postgres');
select is((select count(*) from public.audit_log where table_name = 'spaces' and row_id = pg_temp.id('space_new')::text), 1::bigint, 'an insert writes exactly one audit row');
select results_eq($$select action, organization_id, location_id, actor_user_id, actor_person_id, actor_role, table_schema, old_row is null, new_row ->> 'name', changed_columns
    from public.audit_log where table_name = 'spaces' and row_id = pg_temp.id('space_new')::text$$,
  $$select 'insert'::text, pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('u_manager_a1'), pg_temp.id('p_manager_a1'), 'authenticated'::text, 'public'::text, true, 'Audited Space'::text, null::text[]$$,
  'insert audit row: action, org, location, actor user and person, role, schema, new_row, no old_row, no changed_columns');

select pg_temp.act_as('u_manager_a1');
update public.spaces set name = 'Audited Space 2', capacity = 12 where id = pg_temp.id('space_new');
select pg_temp.act_as('postgres');
select results_eq($$select action, changed_columns, old_row ->> 'name', new_row ->> 'name', location_id, actor_person_id
    from public.audit_log where table_name = 'spaces' and row_id = pg_temp.id('space_new')::text and action = 'update'$$,
  $$select 'update'::text, array['capacity', 'name']::text[], 'Audited Space'::text, 'Audited Space 2'::text, pg_temp.id('loc_a1'), pg_temp.id('p_manager_a1')$$,
  'an update writes exactly one row listing the changed columns (not updated_at) with old and new values');

select pg_temp.act_as('u_manager_a1');
update public.spaces set name = 'Audited Space 2' where id = pg_temp.id('space_new');
select pg_temp.act_as('postgres');
select is((select count(*) from public.audit_log where table_name = 'spaces' and row_id = pg_temp.id('space_new')::text), 2::bigint, 'a no-op update writes no audit row');

select pg_temp.act_as('u_manager_a1');
delete from public.space_hours where id = pg_temp.id('hours_a1');
select pg_temp.act_as('postgres');
select results_eq($$select action, old_row is not null, new_row is null, changed_columns is null, location_id, organization_id
    from public.audit_log where table_name = 'space_hours' and row_id = pg_temp.id('hours_a1')::text and action = 'delete'$$,
  $$select 'delete'::text, true, true, true, pg_temp.id('loc_a1'), pg_temp.id('org_a')$$, 'a delete writes one audit row with the old row');

-- a failed statement leaves no audit row
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try($q$insert into public.space_hours (id, organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
  values (pg_temp.id('hours_fail'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('space_a2'), 1, '08:00', '09:00')$q$), '23503', '(setup) a write that fails a foreign key');
select pg_temp.act_as('postgres');
select is((select count(*) from public.audit_log where table_name = 'space_hours' and row_id = pg_temp.id('hours_fail')::text), 0::bigint, 'a failed write leaves no audit row');

-- Org-level and location-level rows take their organization/location from the row itself.
select pg_temp.act_as('u_locadmin_a1');
update public.locations set phone = '555-0100' where id = pg_temp.id('loc_a1');
select pg_temp.act_as('u_orgadmin_a');
update public.organizations set name = 'Test Org A Renamed' where id = pg_temp.id('org_a');
select pg_temp.act_as('postgres');
select results_eq($$select organization_id, location_id, actor_person_id, changed_columns from public.audit_log
    where table_name = 'locations' and row_id = pg_temp.id('loc_a1')::text and action = 'update'$$,
  $$select pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.id('p_locadmin_a1'), array['phone']::text[]$$, 'locations audit row: location_id is the location itself');
select results_eq($$select organization_id, location_id, actor_person_id, changed_columns from public.audit_log
    where table_name = 'organizations' and row_id = pg_temp.id('org_a')::text and action = 'update'$$,
  $$select pg_temp.id('org_a'), null::uuid, pg_temp.id('p_orgadmin_a'), array['name']::text[]$$, 'organizations audit row: organization_id is the row''s own id, no location');

-- Other actors: service_role (no JWT), the owner, and a platform admin with no account in the org.
set local role service_role;
update public.job_titles set name = 'Lifeguard (service)' where id = pg_temp.id('jt_a');
select pg_temp.act_as('postgres');
select results_eq($$select actor_role, actor_user_id, actor_person_id, organization_id, location_id from public.audit_log
    where table_name = 'job_titles' and row_id = pg_temp.id('jt_a')::text and action = 'update'$$,
  $$select 'service_role'::text, null::uuid, null::uuid, pg_temp.id('org_a'), null::uuid$$, 'service_role write: actor_role service_role, no user or person');
update public.job_titles set name = 'Lifeguard (owner)' where id = pg_temp.id('jt_b');
select results_eq($$select actor_role, actor_user_id, organization_id from public.audit_log where table_name = 'job_titles' and row_id = pg_temp.id('jt_b')::text and action = 'update'$$,
  $$select (session_user::text collate "default"), null::uuid, pg_temp.id('org_b')$$, 'owner write: actor_role is the session user, no JWT user');
select pg_temp.act_as('u_platform');
insert into public.job_titles (id, organization_id, name) values (pg_temp.id('jt_by_platform'), pg_temp.id('org_b'), 'Added by platform');
select pg_temp.act_as('postgres');
select results_eq($$select actor_user_id, actor_person_id, actor_role from public.audit_log where table_name = 'job_titles' and row_id = pg_temp.id('jt_by_platform')::text$$,
  $$select pg_temp.id('u_platform'), null::uuid, 'authenticated'::text$$, 'platform admin write: actor user recorded, no person in that org');

-- Redaction: columns passed to private.enable_audit are never stored.
create table public.zz_audit_demo (id uuid primary key default gen_random_uuid(), organization_id uuid not null, note text, secret text);
select private.enable_audit('public.zz_audit_demo', 'id', array['secret']);
insert into public.zz_audit_demo (id, organization_id, note, secret) values (pg_temp.id('demo'), pg_temp.id('org_a'), 'n1', 'hunter2');
update public.zz_audit_demo set secret = 'hunter3', note = 'n2' where id = pg_temp.id('demo');
select is((select count(*) from public.audit_log where table_name = 'zz_audit_demo' and (new_row::text like '%hunter%' or old_row::text like '%hunter%')), 0::bigint,
  'redacted column values never reach audit_log');
select results_eq($$select changed_columns, new_row ->> 'secret' from public.audit_log where table_name = 'zz_audit_demo' and action = 'update'$$,
  $$select array['note', 'secret']::text[], '[redacted]'::text$$, 'a redacted column still appears in changed_columns');

-- ===========================================================================
-- Who can read the audit log
-- ===========================================================================
select pg_temp.act_as('postgres');
do $$ begin
  perform set_config('t.n_org_a', (select count(*) from public.audit_log where organization_id = pg_temp.id('org_a'))::text, true);
  perform set_config('t.n_org_b', (select count(*) from public.audit_log where organization_id = pg_temp.id('org_b'))::text, true);
  perform set_config('t.n_loc_a1', (select count(*) from public.audit_log where location_id = pg_temp.id('loc_a1'))::text, true);
  perform set_config('t.n_all', (select count(*) from public.audit_log)::text, true);
end $$;
select cmp_ok(current_setting('t.n_loc_a1')::bigint, '>', 0::bigint, 'fixture: A1 has audit rows');
select cmp_ok(current_setting('t.n_org_a')::bigint, '>', current_setting('t.n_loc_a1')::bigint, 'fixture: org A has audit rows beyond A1''s (org-level and A2)');
select cmp_ok((select count(*) from public.audit_log where organization_id is null), '>', 0::bigint, 'fixture: there are platform-level audit rows (null organization)');

select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.audit_log), current_setting('t.n_org_a')::bigint, 'org admin A reads every audit row of org A, and nothing else (no B rows, no platform rows)');
select pg_temp.act_as('u_orgadmin_b');
select is((select count(*) from public.audit_log), current_setting('t.n_org_b')::bigint, 'org admin B reads every audit row of org B, and nothing else');
select pg_temp.act_as('u_platform');
select is((select count(*) from public.audit_log), current_setting('t.n_all')::bigint, 'a platform admin reads every audit row, platform rows included');
select pg_temp.act_as('u_locadmin_a1');
select is((select count(*) from public.audit_log), current_setting('t.n_loc_a1')::bigint, 'location admin A1 reads exactly the rows whose location is A1');
select is((select count(*) from public.audit_log where location_id is distinct from pg_temp.id('loc_a1')), 0::bigint, 'location admin A1 sees no org-level, A2 or B rows');
select pg_temp.act_as('u_manager_a1');
select is((select count(*) from public.audit_log), 0::bigint, 'manager A1 (audit_log = none) reads nothing');
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.audit_log), 0::bigint, 'staff A1 reads nothing');
select pg_temp.act_as('u_staff_a2');
select is((select count(*) from public.audit_log), 0::bigint, 'staff A2 reads nothing');
select pg_temp.act_as('u_noaccount');
select is((select count(*) from public.audit_log), 0::bigint, 'a user with no account reads nothing');
select pg_temp.act_as('u_disabled_a');
select is((select count(*) from public.audit_log), 0::bigint, 'a disabled account reads nothing');
-- an audit_log override at A1 lets a manager read A1's rows, and only those
select pg_temp.act_as('postgres');
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level)
values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('loc_a1'), 'audit_log', 'view');
do $$ begin
  perform set_config('t.n_loc_a1', (select count(*) from public.audit_log where location_id = pg_temp.id('loc_a1'))::text, true);
end $$;
select pg_temp.act_as('u_manager_a1');
select is((select count(*) from public.audit_log), current_setting('t.n_loc_a1')::bigint, 'positive: a manager with audit_log = view at A1 reads A1''s rows');
select is((select count(*) from public.audit_log where location_id is distinct from pg_temp.id('loc_a1')), 0::bigint, 'that override reaches no other location or org-level row');

select pg_temp.act_as('postgres');
select * from finish();
rollback;
