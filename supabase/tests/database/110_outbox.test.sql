-- Phase 2 / transactional outbox and durable jobs (ADR-0003): who can write and read outbox_events, retry gating by
-- audit_log permission and scope, the flat-payload rule, and the claim / complete / fail lifecycle (backoff, dead
-- letter after 8 attempts, lock expiry and reclaim, worker ownership, the handler ledger, retry_dead_outbox_event).
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(194);

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

create function pg_temp.val(p_expr text) returns text language plpgsql as $$
declare v text;
begin
  execute 'select (' || p_expr || ')::text' into v;
  return coalesce(v, 'null');
exception when others then return 'ERR ' || sqlstate;
end $$;
create function pg_temp.try_msg(p_sql text) returns text language plpgsql as $$
begin
  execute p_sql;
  return 'ok';
exception when others then return sqlstate || ' ' || sqlerrm;
end $$;
-- owner-side event factory: a pending event (not due for a day unless a due time is given), fixed id
create function pg_temp.ev(p_name text, p_org text, p_loc text, p_type text default 'task.created', p_payload jsonb default '{}',
                           p_due timestamptz default now() + interval '1 day') returns uuid language sql as $$
  insert into public.outbox_events (id, organization_id, location_id, type, entity_table, entity_id, correlation_id, payload, next_attempt_at)
  values (pg_temp.id(p_name), pg_temp.id(p_org), case when p_loc is null then null else pg_temp.id(p_loc) end, p_type, 'tasks', pg_temp.id('ent_' || p_name),
          pg_temp.id(p_name), p_payload, p_due)
  returning id
$$;
grant execute on function pg_temp.val(text), pg_temp.try_msg(text), pg_temp.ev(text, text, text, text, jsonb, timestamptz) to public;

-- Events used by the read and retry tests (all dead, so they can be retried; not due, so no claim picks them up).
select pg_temp.ev('e_a1', 'org_a', 'loc_a1');
select pg_temp.ev('e_a2', 'org_a', 'loc_a2');
select pg_temp.ev('e_aw', 'org_a', null, 'notice.published');
select pg_temp.ev('e_b1', 'org_b', 'loc_b1');
update public.outbox_events set status = 'dead', attempts = 8, last_error = 'x' where id in (pg_temp.id('e_a1'), pg_temp.id('e_a2'), pg_temp.id('e_aw'), pg_temp.id('e_b1'));
insert into public.outbox_event_handlers (event_id, handler, organization_id) values
  (pg_temp.id('e_a1'), 'tasks', pg_temp.id('org_a')), (pg_temp.id('e_a1'), 'notify', pg_temp.id('org_a')), (pg_temp.id('e_b1'), 'tasks', pg_temp.id('org_b'));

-- ===========================================================================
-- 1. Nobody writes outbox rows through the API: not insert, update, delete, truncate, not emit_event, for any role.
-- ===========================================================================
create temp table writers (n int, who text);
insert into writers values (1, 'u_orgadmin_a'), (2, 'u_locadmin_a1'), (3, 'u_manager_a1'), (4, 'u_staff_a1'), (5, 'u_platform'), (6, 'u_orgadmin_b'), (7, 'anon'), (8, 'service_role');
grant all on writers to public;
do $$
declare w record; t text;
begin
  create temp table writer_results (who text, tbl text, op text, res text);
  grant all on writer_results to public;
  for w in select who from writers order by n loop
    perform pg_temp.act_as(w.who);
    foreach t in array array['outbox_events', 'outbox_event_handlers'] loop
      insert into writer_results values
        (w.who, t, 'insert', pg_temp.try(format('insert into public.%I select * from public.%I limit 1', t, t))),
        (w.who, t, 'insert_new', case when t = 'outbox_events'
           then pg_temp.try($q$insert into public.outbox_events (organization_id, location_id, type, entity_table, entity_id, correlation_id)
                values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), gen_random_uuid())$q$)
           else pg_temp.try($q$insert into public.outbox_event_handlers (event_id, handler, organization_id) values (pg_temp.id('e_a2'), 'forged', pg_temp.id('org_a'))$q$) end),
        (w.who, t, 'update', pg_temp.try(format('update public.%I set organization_id = organization_id', t))),
        (w.who, t, 'delete', pg_temp.try(format('delete from public.%I', t))),
        (w.who, t, 'truncate', pg_temp.try(format('truncate public.%I', t)));
    end loop;
    insert into writer_results values
      (w.who, 'emit_event', 'call', pg_temp.try($q$select private.emit_event(pg_temp.id('org_a'), null, 'task.created', 'tasks', gen_random_uuid())$q$)),
      (w.who, 'status', 'update', pg_temp.try($q$update public.outbox_events set status = 'done', processed_at = now() where id = pg_temp.id('e_a2')$q$));
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select string_agg(distinct res, ',') from writer_results where who = w.who), '42501', w.who || ': every write to outbox_events / outbox_event_handlers and emit_event is refused with 42501')
  from writers w order by w.n;
select is((select count(*) from writer_results), 8 * 12::bigint, 'the write matrix ran every attempt (8 roles x 12)');
select is((select count(*) from public.outbox_events), 4::bigint, 'and nothing was added to or removed from outbox_events');
select is((select status from public.outbox_events where id = pg_temp.id('e_a2')), 'dead', 'and the event a role tried to mark done is unchanged');
select is((select count(*) from public.outbox_event_handlers), 3::bigint, 'and nothing changed in outbox_event_handlers');
-- service_role holds no write grant, only select
select ok(has_table_privilege('service_role', 'public.outbox_events', 'select') and not has_table_privilege('service_role', 'public.outbox_events', 'insert,update,delete,truncate'),
  'service_role: select on outbox_events and nothing else (writes go through the worker functions)');
select ok(not has_any_column_privilege('authenticated', 'public.outbox_events', 'insert,update,references'), 'authenticated: no insert/update column grant on outbox_events');

-- ===========================================================================
-- 2. Reads: gated by the audit_log module and its scope
-- ===========================================================================
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.outbox_events), 3::bigint, 'org admin A (audit_log admin, organization scope) sees the 3 org A events and not org B''s');
select is((select count(*) from public.outbox_event_handlers), 2::bigint, 'org admin A sees the handler ledger of org A events only');
select is((select count(*) from public.outbox_events where organization_id = pg_temp.id('org_b')), 0::bigint, 'org admin A sees nothing of org B');
select pg_temp.act_as('u_orgadmin_b');
select is((select array_agg(id) from public.outbox_events), array[pg_temp.id('e_b1')], 'org admin B sees only the org B event');
select pg_temp.act_as('u_locadmin_a1');
select is((select array_agg(id) from public.outbox_events), array[pg_temp.id('e_a1')], 'location admin A1 sees only the events of location A1 (not A2''s, not the organization-wide one)');
select is((select count(*) from public.outbox_event_handlers), 2::bigint, 'location admin A1 sees the ledger rows of the A1 event');
select pg_temp.act_as('u_manager_a1');
select is((select count(*) from public.outbox_events), 0::bigint, 'manager A1 (audit_log none) sees no events');
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.outbox_events), 0::bigint, 'staff A1 sees no events');
select is((select count(*) from public.outbox_event_handlers), 0::bigint, 'staff A1 sees no ledger rows');
select pg_temp.act_as('u_noaccount');
select is((select count(*) from public.outbox_events), 0::bigint, 'a signed-in user with no account sees no events');
select pg_temp.act_as('anon');
select is(pg_temp.try('select count(*) from public.outbox_events'), '42501', 'anon cannot read outbox_events');
select pg_temp.act_as('u_platform', 'aal2');
select is((select count(*) from public.outbox_events), 4::bigint, 'a platform admin at aal2 sees every event');
select pg_temp.act_as('u_platform', 'aal1');
select is((select count(*) from public.outbox_events), 0::bigint, 'a platform admin at aal1 sees none');
select pg_temp.act_as('service_role');
select is((select count(*) from public.outbox_events), 4::bigint, 'service_role reads every event (the worker)');
-- permission-driven. Reach stays bound to where the person is a member: staff A1 given audit_log view
-- organization-wide still only reaches location A1 (an override does not widen reach).
select pg_temp.act_as('postgres');
insert into public.user_permissions (id, organization_id, person_id, location_id, module_key, level)
values (pg_temp.id('up_audit'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), null, 'audit_log', 'view');
select pg_temp.act_as('u_staff_a1');
select is((select array_agg(id) from public.outbox_events), array[pg_temp.id('e_a1')], 'staff A1 with audit_log view (organization-wide override) sees only the events of their own location A1');
select pg_temp.act_as('postgres');
delete from public.user_permissions where id = pg_temp.id('up_audit');
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.outbox_events), 0::bigint, 'and none again once the permission is gone');
-- an organization-scope admin whose audit_log level is lowered to view by a per-person override (only the admin
-- role can be given at organization scope)
select pg_temp.act_as('postgres');
insert into auth.users (id, email) values (pg_temp.id('u_audit'), 'audit@test.invalid');
insert into public.people (id, organization_id, first_name, last_name) values (pg_temp.id('p_audit'), pg_temp.id('org_a'), 'Aud', 'Itor');
insert into public.accounts (id, organization_id, person_id, user_id) values (pg_temp.id('acct_audit'), pg_temp.id('org_a'), pg_temp.id('p_audit'), pg_temp.id('u_audit'));
insert into public.role_assignments (id, organization_id, person_id, role_id, location_id) values (pg_temp.id('ra_audit'), pg_temp.id('org_a'), pg_temp.id('p_audit'), pg_temp.sys_role('admin'), null);
insert into public.user_permissions (id, organization_id, person_id, location_id, module_key, level)
values (pg_temp.id('up_audit2'), pg_temp.id('org_a'), pg_temp.id('p_audit'), null, 'audit_log', 'view');
select pg_temp.act_as('u_audit');
select is((select count(*) from public.outbox_events), 3::bigint, 'an organization-scope member with audit_log view (override) sees all 3 org A events (including the organization-wide one)');
select is((select count(*) from public.outbox_events where organization_id = pg_temp.id('org_b')), 0::bigint, 'and nothing of org B');
select is((select count(*) from public.outbox_event_handlers), 2::bigint, 'and the org A ledger rows');

-- ===========================================================================
-- 3. retry_dead_outbox_event: gating, uniform refusal, state errors, reset
-- ===========================================================================
-- view only (no admin): can read, cannot retry; with audit_log admin can
select pg_temp.act_as('u_audit');
select is((select count(*) from public.outbox_events), 3::bigint, 'view-only auditor can read the events...');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a1'))$$), '42501 not allowed', '...but cannot retry one (audit_log needs admin)');
select pg_temp.act_as('postgres');
update public.user_permissions set level = 'admin' where id = pg_temp.id('up_audit2');
select pg_temp.act_as('u_audit');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a2'))$$), 'ok', 'twin: the same person with audit_log admin at organization scope can retry a dead event');
select is((select status from public.outbox_events where id = pg_temp.id('e_a2')), 'pending', 'that event is pending again');
select pg_temp.act_as('postgres');
update public.user_permissions set level = 'view' where id = pg_temp.id('up_audit2');
update public.outbox_events set status = 'dead', attempts = 8, retried_at = null, retried_by_person_id = null where id = pg_temp.id('e_a2');

-- uniform refusal: unknown event, another organization's event, and no permission all say the same thing
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(gen_random_uuid())$$), '42501 not allowed', 'retry: an event that does not exist -> 42501 not allowed');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_b1'))$$), '42501 not allowed', 'retry: another organization''s event -> the same message');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(null)$$), '42501 not allowed', 'retry: null id -> the same message');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a1'))$$), '42501 not allowed', 'retry: a manager (no audit_log) -> the same message');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a1'))$$), '42501 not allowed', 'retry: staff -> the same message');
select pg_temp.act_as('u_noaccount');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a1'))$$), '42501 not allowed', 'retry: a user with no account -> the same message');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a1'))$$), '42501 not allowed', 'retry: org admin B on an org A event -> the same message');
select pg_temp.act_as('anon');
select is(pg_temp.try('select public.retry_dead_outbox_event(gen_random_uuid())'), '42501', 'retry: anon cannot call it');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a1'))$$), '42501 not signed in', 'retry: the server key with no user is refused (it is the admin screen''s function)');
select pg_temp.act_as('u_orgadmin_a', 'aal1');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a1'))$$), '42501 not allowed', 'retry: the org admin at aal1 -> the same message');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where status = 'dead'), 4::bigint, 'none of those attempts retried anything');
-- location scope
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a2'))$$), '42501 not allowed', 'retry: location admin A1 cannot retry an event at location A2');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_aw'))$$), '42501 not allowed', 'retry: location admin A1 cannot retry an organization-wide event');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_b1'))$$), '42501 not allowed', 'retry: location admin A1 cannot retry another organization''s event');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a1'))$$), 'ok', 'twin: location admin A1 can retry an event at A1');
select pg_temp.act_as('postgres');
select results_eq($$select status, attempts, retried_by_person_id, (retried_at = now()), (next_attempt_at <= now()) from public.outbox_events where id = pg_temp.id('e_a1')$$,
  $$select 'pending'::text, 0, pg_temp.id('p_locadmin_a1'), true, true$$,
  'retry resets the event: pending, attempts 0, due now, retried_at set, retried_by = the caller''s person');
select is((select array_agg(handler order by handler) from public.outbox_event_handlers where event_id = pg_temp.id('e_a1')), array['notify', 'tasks'],
  'retry keeps the handler ledger (finished handlers are not redone)');
select is((select last_error from public.outbox_events where id = pg_temp.id('e_a1')), 'x', 'retry keeps the last error for the record');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a1'))$$), '22023 only failed events can be retried', 'retrying twice: the second call is a state error (22023), the event is no longer dead');
-- org admin and platform admin
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_aw'))$$), 'ok', 'org admin A (organization scope) can retry an organization-wide event');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_a2'))$$), 'ok', 'org admin A can retry an event at any location of the organization');
select pg_temp.act_as('u_platform');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('e_b1'))$$), 'ok', 'platform admin at aal2 can retry any organization''s event');
select pg_temp.act_as('postgres');
select is((select retried_by_person_id from public.outbox_events where id = pg_temp.id('e_b1')), null, 'a platform admin has no person in the organization: retried_by_person_id stays null');
select is((select count(*) from public.outbox_events where status = 'pending' and retried_at is not null), 4::bigint, 'all four events were retried once');

-- ===========================================================================
-- 4. Payload shape: a small flat object of ids and scalars
-- ===========================================================================
create temp table payload_cases (n int, label text, payload text, ok boolean);
insert into payload_cases values
  (1,  'empty object',                         '{}', true),
  (2,  'ids, numbers, booleans, null',         '{"task_id":"7a3f1c2e-0000-4000-8000-000000000001","n":5,"flag":true,"nothing":null}', true),
  (3,  'array of ids',                         '{"ids":["a","b"]}', true),
  (4,  'a nested object',                      '{"a":{"b":1}}', false),
  (5,  'an array of objects',                  '{"a":[{"b":1}]}', false),
  (6,  'an array holding a number',            '{"a":[1,2]}', false),
  (7,  'an array holding an array',            '{"a":[["x"]]}', false),
  (8,  'a string of 200 characters',           '{"a":"' || repeat('x', 200) || '"}', true),
  (9,  'a string of 201 characters',           '{"a":"' || repeat('x', 201) || '"}', false),
  (10, 'an array element of 64 characters',    '{"a":["' || repeat('x', 64) || '"]}', true),
  (11, 'an array element of 65 characters',    '{"a":["' || repeat('x', 65) || '"]}', false),
  (12, 'an array of 100 ids',                  '{"a":[' || (select string_agg('"i"', ',') from generate_series(1, 100)) || ']}', true),
  (13, 'an array of 101 ids',                  '{"a":[' || (select string_agg('"i"', ',') from generate_series(1, 101)) || ']}', false),
  (14, 'a key with an uppercase letter',       '{"Task":"x"}', false),
  (15, 'a key starting with a digit',          '{"1a":"x"}', false),
  (16, 'a key with a dash',                    '{"a-b":"x"}', false),
  (17, '32 keys',                              (select jsonb_object_agg('k' || g, 1)::text from generate_series(1, 32) g), true),
  (18, '33 keys',                              (select jsonb_object_agg('k' || g, 1)::text from generate_series(1, 33) g), false),
  (19, 'more than 8 kB as text',               '{"a":[' || (select string_agg('"' || repeat('y', 60) || '"', ',') from generate_series(1, 100)) || '],"b":[' || (select string_agg('"' || repeat('y', 60) || '"', ',') from generate_series(1, 30)) || ']}', false),
  (20, 'a top-level array',                    '[]', false),
  (21, 'a top-level string',                   '"x"', false),
  (22, 'a free text comment as a string value (<= 200) is allowed by shape, so handlers must keep ids only', '{"note":"hello there"}', true);
select is(pg_temp.try_msg(format($$select private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), %L::jsonb)$$, c.payload)),
          case when c.ok then 'ok' else '22023 event payload must be a small flat object of ids and scalars' end,
          'emit_event payload: ' || c.label || case when c.ok then ' is accepted' else ' is refused (22023)' end)
  from (select * from payload_cases order by n) c;
select is(pg_temp.try(format($$insert into public.outbox_events (organization_id, location_id, type, entity_table, entity_id, correlation_id, payload)
          values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), gen_random_uuid(), %L::jsonb)$$, c.payload)),
          case when c.ok then 'ok' else '23514' end,
          'the table CHECK agrees (even the owner cannot store): ' || c.label)
  from (select * from payload_cases order by n) c;
select is(pg_temp.try_msg($$select private.emit_event(pg_temp.id('org_a'), null, 'task.created', 'tasks', gen_random_uuid(), null)$$), 'ok', 'emit_event: a null payload is stored as {}');
select is(pg_temp.try_msg($$select private.emit_event(null, null, 'task.created', 'tasks', gen_random_uuid())$$), '22023 event is missing required fields', 'emit_event: no organization -> 22023');
select is(pg_temp.try_msg($$select private.emit_event(pg_temp.id('org_a'), null, null, 'tasks', gen_random_uuid())$$), '22023 event is missing required fields', 'emit_event: no type -> 22023');
select is(pg_temp.try_msg($$select private.emit_event(pg_temp.id('org_a'), null, 'task.created', 'tasks', null)$$), '22023 event is missing required fields', 'emit_event: no entity id -> 22023');
select is(pg_temp.try($$select private.emit_event(pg_temp.id('org_a'), null, 'Task.Created', 'tasks', gen_random_uuid())$$), '23514', 'emit_event: a type that is not dotted lower-case is refused by the CHECK');
select is(pg_temp.try($$select private.emit_event(pg_temp.id('org_a'), null, 'task', 'tasks', gen_random_uuid())$$), '23514', 'emit_event: a type without a dot is refused');
select is(pg_temp.try($$select private.emit_event(pg_temp.id('org_a'), null, 'task.created', 'Tasks', gen_random_uuid())$$), '23514', 'emit_event: a bad table name is refused');
select is(pg_temp.try($$select private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_b1'), 'task.created', 'tasks', gen_random_uuid())$$), '23503', 'emit_event: a location of another organization is refused (composite key)');
select is(pg_temp.try($$select private.emit_event(gen_random_uuid(), null, 'task.created', 'tasks', gen_random_uuid())$$), '23503', 'emit_event: an unknown organization is refused');
-- scheduling and correlation
select pg_temp.act_as('postgres');
create temp table emitted as
  select private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}', 1, null, now() + interval '2 hours') as later,
         private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}', 1, null, now() - interval '2 hours') as past,
         private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}', 1, pg_temp.id('corr_x')) as follow;
select is((select next_attempt_at from public.outbox_events where id = (select later from emitted)), now() + interval '2 hours', 'emit_event: available_at in the future schedules the event');
select is((select next_attempt_at from public.outbox_events where id = (select past from emitted)), now(), 'emit_event: available_at in the past means now');
select is((select correlation_id from public.outbox_events where id = (select later from emitted)), (select later from emitted), 'emit_event: the correlation id defaults to the event''s own id');
select is((select correlation_id from public.outbox_events where id = (select follow from emitted)), pg_temp.id('corr_x'), 'emit_event: a follow-on event keeps the source correlation id');

-- ===========================================================================
-- 5. Immutability and row checks (even the owner)
-- ===========================================================================
select is(pg_temp.try($$update public.outbox_events set payload = '{"x":1}' where id = pg_temp.id('e_a1')$$), '23514', 'the payload of an event cannot be rewritten');
select is(pg_temp.try($$update public.outbox_events set type = 'task.done' where id = pg_temp.id('e_a1')$$), '23514', 'the type of an event cannot be changed');
select is(pg_temp.try($$update public.outbox_events set entity_id = gen_random_uuid() where id = pg_temp.id('e_a1')$$), '23514', 'the entity of an event cannot be changed');
select is(pg_temp.try($$update public.outbox_events set correlation_id = gen_random_uuid() where id = pg_temp.id('e_a1')$$), '23514', 'the correlation id cannot be changed');
select is(pg_temp.try($$update public.outbox_events set location_id = pg_temp.id('loc_a2') where id = pg_temp.id('e_a1')$$), '23514', 'the location of an event cannot be changed');
select is(pg_temp.try($$update public.outbox_events set organization_id = pg_temp.id('org_b') where id = pg_temp.id('e_a1')$$), '23514', 'the organization of an event cannot be changed');
select is(pg_temp.try($$update public.outbox_events set status = 'processing' where id = pg_temp.id('e_a1')$$), '23514', 'status processing without a lock owner violates the CHECK');
select is(pg_temp.try($$update public.outbox_events set status = 'done' where id = pg_temp.id('e_a1')$$), '23514', 'status done without processed_at violates the CHECK');
select is(pg_temp.try($$update public.outbox_events set status = 'weird' where id = pg_temp.id('e_a1')$$), '23514', 'an unknown status is refused');
select is(pg_temp.try($$update public.outbox_event_handlers set handler = 'other' where event_id = pg_temp.id('e_a1') and handler = 'tasks'$$), '23514', 'a ledger row cannot be renamed');
select is(pg_temp.try($$insert into public.outbox_event_handlers (event_id, handler, organization_id) values (pg_temp.id('e_a1'), 'tasks', pg_temp.id('org_a'))$$), '23505', 'the ledger has one row per (event, handler)');
select is(pg_temp.try($$insert into public.outbox_event_handlers (event_id, handler, organization_id) values (pg_temp.id('e_a1'), 'Bad Name', pg_temp.id('org_a'))$$), '23514', 'a ledger handler name must be lower-case slug');
select is(pg_temp.try($$insert into public.outbox_event_handlers (event_id, handler, organization_id) values (pg_temp.id('e_a1'), 'x', pg_temp.id('org_b'))$$), '23503', 'a ledger row cannot name another organization than its event (composite key)');

-- ===========================================================================
-- 6. The worker lifecycle (as service_role)
-- ===========================================================================
select pg_temp.act_as('postgres');
select pg_temp.ev('life', 'org_a', 'loc_a1', 'task.created', '{}', now());
select pg_temp.ev('life_future', 'org_a', 'loc_a1', 'task.created', '{}', now() + interval '1 hour');
-- park every other event so only 'life' is due
update public.outbox_events set next_attempt_at = now() + interval '1 day' where id <> pg_temp.id('life') and status = 'pending';
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select * from public.claim_outbox_events('w1', 0, 60)$$), '22023 invalid limit', 'claim: limit 0 is refused');
select is(pg_temp.try_msg($$select * from public.claim_outbox_events('w1', 501, 60)$$), '22023 invalid limit', 'claim: limit above 500 is refused');
select is(pg_temp.try_msg($$select * from public.claim_outbox_events('w1', null, 60)$$), '22023 invalid limit', 'claim: null limit is refused');
select is(pg_temp.try_msg($$select * from public.claim_outbox_events('', 1, 60)$$), '22023 invalid worker', 'claim: an empty worker name is refused');
select is(pg_temp.try_msg($$select * from public.claim_outbox_events(null, 1, 60)$$), '22023 invalid worker', 'claim: a null worker name is refused');
select is(pg_temp.try_msg($$select * from public.claim_outbox_events(repeat('w', 101), 1, 60)$$), '22023 invalid worker', 'claim: a worker name of 101 characters is refused');
select is(pg_temp.try_msg($$select * from public.claim_outbox_events('w1', 1, 4)$$), '22023 invalid lock time', 'claim: a lock under 5 seconds is refused');
select is(pg_temp.try_msg($$select * from public.claim_outbox_events('w1', 1, 3601)$$), '22023 invalid lock time', 'claim: a lock over an hour is refused');
select is((select count(*) from public.outbox_events where status = 'processing'), 0::bigint, 'those refused claims claimed nothing');

select is((select id from public.claim_outbox_events('w1', 10, 60)), pg_temp.id('life'), 'claim: only the due event is claimed (not the future ones)');
select results_eq($$select status, attempts, locked_by, (lock_expires_at = now() + interval '60 seconds'), locked_at is not null from public.outbox_events where id = pg_temp.id('life')$$,
  $$select 'processing'::text, 1, 'w1'::text, true, true$$, 'claim: status processing, attempt counted, locked by w1 for the lock time');
select is((select count(*) from public.claim_outbox_events('w2', 10, 60)), 0::bigint, 'claim: a second worker does not get an event that is locked');
select is(public.complete_outbox_event(pg_temp.id('life'), 'w2'), false, 'complete: a worker that does not hold the claim cannot complete the event');
select is(public.fail_outbox_event(pg_temp.id('life'), 'w2', 'nope'), null, 'fail: a worker that does not hold the claim gets null and changes nothing');
select is(public.complete_outbox_event(pg_temp.id('life'), null), false, 'complete: a null worker cannot complete either');
select is(public.complete_outbox_event(gen_random_uuid(), 'w1'), false, 'complete: an unknown event is just false');
select is((select status from public.outbox_events where id = pg_temp.id('life')), 'processing', 'still processing after the refused calls');
select is(public.fail_outbox_event(pg_temp.id('life'), 'w1', 'timeout talking to the mail server'), 'pending', 'fail: the holder fails it -> back to pending');
select results_eq($$select status, attempts, (next_attempt_at = now() + interval '1 minute'), locked_by is null, lock_expires_at is null, last_error from public.outbox_events where id = pg_temp.id('life')$$,
  $$select 'pending'::text, 1, true, true, true, 'timeout talking to the mail server'::text$$, 'fail: after attempt 1 the retry is due in 1 minute, the lock is released, the error is kept');
select is((select count(*) from public.claim_outbox_events('w1', 10, 60)), 0::bigint, 'claim: not claimed again before its backoff has passed');
-- walk the whole backoff table: attempts 2..7 each wait 2^(n-1) minutes, attempt 8 is dead
select pg_temp.act_as('postgres');
create temp table backoff_seen (attempts int, status text, wait interval);
grant all on backoff_seen to public;
do $$
declare i int; s text; w interval; a int;
begin
  for i in 2 .. 8 loop
    perform pg_temp.act_as('postgres');
    update public.outbox_events set next_attempt_at = now() where id = pg_temp.id('life');   -- time passes
    perform pg_temp.act_as('service_role');
    perform 1 from public.claim_outbox_events('w1', 10, 60);
    s := public.fail_outbox_event(pg_temp.id('life'), 'w1', 'attempt ' || i);
    perform pg_temp.act_as('postgres');
    select e.attempts, e.next_attempt_at - now() into a, w from public.outbox_events e where e.id = pg_temp.id('life');
    insert into backoff_seen values (a, s, w);
  end loop;
end $$;
select is((select string_agg(attempts || ':' || status || ':' || wait, ' ' order by attempts) from backoff_seen where attempts between 2 and 7),
  '2:pending:00:02:00 3:pending:00:04:00 4:pending:00:08:00 5:pending:00:16:00 6:pending:00:32:00 7:pending:01:04:00',
  'backoff after attempts 2..7 doubles: 2, 4, 8, 16, 32, 64 minutes');
select is((select status || ':' || attempts from backoff_seen where attempts = 8), 'dead:8', 'the 8th failed attempt makes the event dead (max attempts 8)');
select results_eq($$select status, attempts, last_error, locked_by is null from public.outbox_events where id = pg_temp.id('life')$$,
  $$select 'dead'::text, 8, 'attempt 8'::text, true$$, 'a dead event keeps its last error and holds no lock');
select is(private.outbox_max_attempts(), 8, 'the maximum number of attempts is 8');
select is((select (array_agg(private.outbox_backoff(n) order by n))::text from generate_series(0, 10) n), '{00:01:00,00:01:00,00:02:00,00:04:00,00:08:00,00:16:00,00:32:00,01:04:00,02:08:00,04:16:00,06:00:00}',
  'backoff function: 1,1,2,4,8,16,32,64,128,256 minutes, capped at 6 hours');
select pg_temp.act_as('postgres');
update public.outbox_events set next_attempt_at = now() where id = pg_temp.id('life');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('w1', 10, 60)), 0::bigint, 'claim: a dead event is never claimed, even when "due"');
select is(public.fail_outbox_event(pg_temp.id('life'), 'w1', 'again'), null, 'fail: a dead event cannot be failed again');
select is(public.complete_outbox_event(pg_temp.id('life'), 'w1'), false, 'complete: a dead event cannot be completed');
-- retry brings it back (the admin screen), then it completes
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('life'))$$), 'ok', 'a dead event is retried by an org admin');
select pg_temp.act_as('service_role');
select is((select id from public.claim_outbox_events('w1', 10, 60)), pg_temp.id('life'), 'after the retry the event is claimed again');
select results_eq($$select attempts from public.outbox_events where id = pg_temp.id('life')$$, $$select 1$$, 'and its attempt count started again from 0 (this is attempt 1)');
select is(public.complete_outbox_event(pg_temp.id('life'), 'w1'), true, 'complete: the holder completes it');
select results_eq($$select status, processed_at = now(), locked_by is null, lock_expires_at is null from public.outbox_events where id = pg_temp.id('life')$$,
  $$select 'done'::text, true, true, true$$, 'a done event: processed_at set, lock cleared');
select is(public.complete_outbox_event(pg_temp.id('life'), 'w1'), false, 'complete: a second complete is false (nothing to do)');
select is(public.fail_outbox_event(pg_temp.id('life'), 'w1', 'late'), null, 'fail: a done event cannot be failed');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.retry_dead_outbox_event(pg_temp.id('life'))$$), '22023 only failed events can be retried', 'a done event cannot be "retried"');

-- error text: trimmed to 2000 characters; empty means "unknown error"
select pg_temp.act_as('postgres');
select pg_temp.ev('err', 'org_a', 'loc_a1', 'task.created', '{}', now());
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('w1', 10, 60)), 1::bigint, 'claim: the "err" event is claimed');
select is(public.fail_outbox_event(pg_temp.id('err'), ' w1 ', repeat('e', 5000)), 'pending', 'fail: worker names are trimmed on both sides');
select pg_temp.act_as('postgres');
select is((select char_length(last_error) from public.outbox_events where id = pg_temp.id('err')), 2000, 'the error text is cut to 2000 characters');
update public.outbox_events set next_attempt_at = now() where id = pg_temp.id('err');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('w1', 10, 60)), 1::bigint, 'claim: and claimed again');
select is(public.fail_outbox_event(pg_temp.id('err'), 'w1', '   '), 'pending', 'fail: a blank error is accepted');
select pg_temp.act_as('postgres');
select is((select last_error from public.outbox_events where id = pg_temp.id('err')), 'unknown error', 'a blank error is stored as "unknown error"');

-- lock expiry: a crashed worker's event is reclaimed by another worker; the crashed worker can no longer finish it
select pg_temp.ev('crash', 'org_a', 'loc_a1', 'task.created', '{}', now());
update public.outbox_events set next_attempt_at = now() + interval '1 day' where id = pg_temp.id('err');
select pg_temp.act_as('service_role');
select is((select id from public.claim_outbox_events('w1', 10, 5)), pg_temp.id('crash'), 'lock expiry: w1 claims the event with a 5 second lock, then "crashes"');
select is((select count(*) from public.claim_outbox_events('w2', 10, 60)), 0::bigint, 'lock expiry: while the lock is live nobody else gets it');
select pg_temp.act_as('postgres');
update public.outbox_events set lock_expires_at = now() - interval '1 second' where id = pg_temp.id('crash');   -- 6 seconds pass
select pg_temp.act_as('service_role');
select is((select id from public.claim_outbox_events('w2', 10, 60)), pg_temp.id('crash'), 'lock expiry: after the lock expired w2 reclaims the event');
select results_eq($$select status, attempts, locked_by from public.outbox_events where id = pg_temp.id('crash')$$, $$select 'processing'::text, 2, 'w2'::text$$,
  'the reclaim counts as attempt 2 and w2 holds it');
select is(public.complete_outbox_event(pg_temp.id('crash'), 'w1'), false, 'the crashed worker w1 cannot complete the event it no longer holds');
select is(public.fail_outbox_event(pg_temp.id('crash'), 'w1', 'late'), null, 'the crashed worker w1 cannot fail it either');
select is(public.complete_outbox_event(pg_temp.id('crash'), 'w2'), true, 'twin: the new holder w2 completes it');
-- an expired lock on the last attempt goes dead instead of being claimed again
select pg_temp.act_as('postgres');
select pg_temp.ev('lastlock', 'org_a', 'loc_a1', 'task.created', '{}', now());
update public.outbox_events set status = 'processing', attempts = 8, locked_by = 'w9', locked_at = now() - interval '2 minutes', lock_expires_at = now() - interval '1 minute',
  last_error = 'earlier error' where id = pg_temp.id('lastlock');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('w1', 10, 60)), 0::bigint, 'last attempt, expired lock: not claimed again');
select pg_temp.act_as('postgres');
select results_eq($$select status, attempts, last_error, locked_by is null from public.outbox_events where id = pg_temp.id('lastlock')$$,
  $$select 'dead'::text, 8, 'earlier error | lock expired on the last attempt'::text, true$$, 'it was moved to dead with the reason appended');
-- a live lock on attempt 8 is left alone (the worker may still finish)
select pg_temp.ev('livelast', 'org_a', 'loc_a1', 'task.created', '{}', now());
update public.outbox_events set status = 'processing', attempts = 8, locked_by = 'w9', locked_at = now(), lock_expires_at = now() + interval '1 minute' where id = pg_temp.id('livelast');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('w1', 10, 60)), 0::bigint, 'a live lock is never touched');
select is(public.complete_outbox_event(pg_temp.id('livelast'), 'w9'), true, 'and its holder can still complete it');

-- claim order and limit: oldest due first, never more than the limit
select pg_temp.act_as('postgres');
update public.outbox_events set next_attempt_at = now() + interval '1 day' where status = 'pending';
select pg_temp.ev('o1', 'org_a', 'loc_a1', 'task.created', '{}', now() - interval '3 minutes');
select pg_temp.ev('o2', 'org_a', 'loc_a1', 'task.created', '{}', now() - interval '2 minutes');
select pg_temp.ev('o3', 'org_a', 'loc_a1', 'task.created', '{}', now() - interval '1 minutes');
select pg_temp.act_as('service_role');
select is((select array_agg(id order by next_attempt_at) from public.claim_outbox_events('w1', 2, 60)), array[pg_temp.id('o1'), pg_temp.id('o2')], 'claim: limit 2 returns the two oldest due events');
select is((select array_agg(id) from public.claim_outbox_events('w1', 2, 60)), array[pg_temp.id('o3')], 'claim: the next call returns the remaining one');

-- the handler ledger
select is(public.record_outbox_handler(pg_temp.id('o1'), 'tasks'), true, 'ledger: the first record of (event, handler) is new');
select is(public.record_outbox_handler(pg_temp.id('o1'), 'tasks'), false, 'ledger: the second is not (idempotent)');
select is(public.record_outbox_handler(pg_temp.id('o1'), 'notify'), true, 'ledger: another handler of the same event is new');
select is((select array_agg(h) from public.outbox_handlers_done(pg_temp.id('o1')) h), array['notify', 'tasks'], 'ledger: handlers done are listed, sorted');
select is(pg_temp.try_msg($$select public.record_outbox_handler(gen_random_uuid(), 'tasks')$$), '22023 no such event', 'ledger: an unknown event is refused');
select is(pg_temp.try($$select public.record_outbox_handler(pg_temp.id('o1'), 'Bad Handler')$$), '23514', 'ledger: a bad handler name is refused');
select is((select organization_id from public.outbox_event_handlers where event_id = pg_temp.id('o1') and handler = 'tasks'), pg_temp.id('org_a'), 'ledger: the row takes the event''s organization');
select is((select count(*) from public.outbox_events), (select count(*) from public.outbox_events), 'sanity: the table is readable by the worker');

select pg_temp.act_as('postgres');
select * from finish();
rollback;
