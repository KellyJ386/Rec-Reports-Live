-- Phase 2 review fixes (000600 R4, R9d, R14, R16): overdue escalation, who acknowledged (notice_acknowledgment_status), my_notices,
-- append-only guards that still let a cascade through, the manual retry cap, a failed delivery keeping its next_attempt_at, and
-- publish_notice validation. Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(142);

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
-- statement that returns nothing: 'ok' or 'sqlstate message'
create function pg_temp.run(p_sql text) returns text language plpgsql as $$
begin
  execute p_sql;
  return 'ok';
exception when others then return sqlstate || ' ' || sqlerrm;
end $$;
grant execute on function pg_temp.run(text) to public;
create temp table ids (k text primary key, v uuid);
grant all on ids to public;
create function pg_temp.gid(p_k text) returns uuid language sql stable as $$ select v from ids where k = p_k $$;
grant execute on function pg_temp.gid(text) to public;

-- ===========================================================================
-- 1. escalate_overdue_task
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
insert into ids select 't1', public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Overdue one', null, now() + interval '1 hour', 'normal', null, pg_temp.id('p_staff_a1'), null);
insert into ids select 't2', public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Overdue two', null, now() + interval '1 hour', 'normal', null, pg_temp.id('p_staff_a1'), null);
insert into ids select 't3', public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Not due yet', null, now() + interval '1 hour', 'normal', null, pg_temp.id('p_staff_a1'), null);
insert into ids select 't4', public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Assignee acted', null, now() + interval '1 hour', 'normal', null, pg_temp.id('p_staff_a1'), null);
insert into ids select 't5', public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Finished', null, now() + interval '1 hour', 'normal', null, pg_temp.id('p_staff_a1'), null);
select pg_temp.act_as('postgres');
update public.tasks set due_at = now() - interval '2 hours' where id in (pg_temp.gid('t1'), pg_temp.gid('t2'), pg_temp.gid('t4'), pg_temp.gid('t5'));
update public.tasks set status = 'done', completed_at = now(), completed_by_person_id = pg_temp.id('p_staff_a1') where id = pg_temp.gid('t5');
insert into public.task_events (organization_id, location_id, task_id, kind, actor_person_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), pg_temp.gid('t4'), 'started', pg_temp.id('p_staff_a1'));
create function pg_temp.overdue_event(p_task text) returns uuid language sql as $$
  select private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.overdue', 'tasks', pg_temp.gid(p_task),
                            jsonb_build_object('due_at', (select due_at from public.tasks where id = pg_temp.gid(p_task))))
$$;
grant execute on function pg_temp.overdue_event(text) to public;
insert into ids select 'e1', pg_temp.overdue_event('t1');
insert into ids select 'e1b', pg_temp.overdue_event('t1');
insert into ids select 'e2', pg_temp.overdue_event('t2');
insert into ids select 'e3', pg_temp.overdue_event('t3');
insert into ids select 'e4', pg_temp.overdue_event('t4');
insert into ids select 'e5', pg_temp.overdue_event('t5');
insert into ids select 'e_other', private.emit_event(pg_temp.id('org_b'), null, 'task.overdue', 'tasks', pg_temp.gid('t2'), jsonb_build_object('due_at', (select due_at from public.tasks where id = pg_temp.gid('t2'))));
insert into ids select 'e_type', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', pg_temp.gid('t2'), '{}');
insert into ids select 'e_table', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.overdue', 'notices', pg_temp.gid('t2'), '{}');

select is((select array_agg(r order by r) from private.task_escalation_recipients(pg_temp.id('org_a'), pg_temp.id('loc_a1')) r),
          (select array_agg(p order by p) from unnest(array[pg_temp.id('p_orgadmin_a'), pg_temp.id('p_locadmin_a1'), pg_temp.id('p_manager_a1')]) p),
  'sanity: the people who hear about an overdue task at A1 are the org admin, the A1 admin and manager A1 (not staff, not the other location)');
select pg_temp.act_as('service_role');
select is((select array_agg(x order by x) from public.escalate_overdue_task(pg_temp.gid('e1')) x),
          (select array_agg(p order by p) from unnest(array[pg_temp.id('p_orgadmin_a'), pg_temp.id('p_locadmin_a1'), pg_temp.id('p_manager_a1')]) p),
  'escalate_overdue_task: an overdue task nobody has touched is escalated to those three');
select pg_temp.act_as('postgres');
select results_eq($$select kind, actor_person_id, from_status, to_status, source_event_id from public.task_events where task_id = pg_temp.gid('t1') and kind = 'escalated'$$,
  $$values ('escalated'::text, null::uuid, 'open'::text, 'open'::text, pg_temp.gid('e1'))$$, 'one "escalated" task event is recorded (no actor, status unchanged, naming the source event)');
select is((select escalated_for from public.tasks where id = pg_temp.gid('t1')), (select due_at from public.tasks where id = pg_temp.gid('t1')), 'and the task remembers which due time it was escalated for');
select pg_temp.act_as('service_role');
select is((select count(*) from public.escalate_overdue_task(pg_temp.gid('e1'))), 3::bigint, 'the same event again (a retry): the same three, so a crashed handler can finish notifying');
select pg_temp.act_as('postgres');
select is((select count(*) from public.task_events where task_id = pg_temp.gid('t1') and kind = 'escalated'), 1::bigint, 'and no second task event is written');
select pg_temp.act_as('service_role');
select is((select count(*) from public.escalate_overdue_task(pg_temp.gid('e1b'))), 0::bigint, 'a second overdue event for the same due time: nobody (once per task per due time)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.task_events where task_id = pg_temp.gid('t1') and kind = 'escalated'), 1::bigint, 'still one escalation');
-- the due time moves and is missed again: a new escalation
update public.tasks set due_at = now() - interval '1 hour' where id = pg_temp.gid('t1');
insert into ids select 'e1c', pg_temp.overdue_event('t1');
select pg_temp.act_as('service_role');
select is((select count(*) from public.escalate_overdue_task(pg_temp.gid('e1c'))), 3::bigint, 'twin: a new due time that is also missed is escalated again');
select pg_temp.act_as('postgres');
select is((select count(*) from public.task_events where task_id = pg_temp.gid('t1') and kind = 'escalated'), 2::bigint, 'two escalations in all');
select pg_temp.act_as('service_role');
select is((select count(*) from public.escalate_overdue_task(pg_temp.gid('e1'))), 3::bigint, 'a replay of the first event is still answered (it was already escalated by that event)');
select is((select count(*) from public.escalate_overdue_task(pg_temp.gid('e1b'))), 0::bigint, 'but a different event carrying the old due time no longer matches the task: nobody');
select is((select count(*) from public.escalate_overdue_task(pg_temp.gid('e3'))), 0::bigint, 'a task that is not overdue yet: nobody');
select is((select count(*) from public.escalate_overdue_task(pg_temp.gid('e4'))), 0::bigint, 'an assignee who has already started it: nobody');
select is((select count(*) from public.escalate_overdue_task(pg_temp.gid('e5'))), 0::bigint, 'a finished task: nobody');
select is((select count(*) from public.escalate_overdue_task(pg_temp.gid('e_other'))), 0::bigint, 'a forged overdue event of another organization naming the task: nobody');
select pg_temp.act_as('postgres');
select is((select count(*) from public.task_events where kind = 'escalated' and task_id in (pg_temp.gid('t3'), pg_temp.gid('t4'), pg_temp.gid('t5'))), 0::bigint, 'none of those were recorded as escalated');
select is((select count(*) from public.task_events where task_id = pg_temp.gid('t2') and kind = 'escalated'), 0::bigint, 'and the forged event recorded nothing on the task');
select pg_temp.act_as('service_role');
select is(pg_temp.f(format('select count(*) from public.escalate_overdue_task(%L)', pg_temp.gid('e_type'))), '22023 not a task.overdue event', 'an event of another type is refused (22023)');
select is(pg_temp.f(format('select count(*) from public.escalate_overdue_task(%L)', pg_temp.gid('e_table'))), '22023 not a task.overdue event', 'an overdue event that is not about a task is refused (22023)');
select is(pg_temp.f(format('select count(*) from public.escalate_overdue_task(%L)', gen_random_uuid())), '22023 not a task.overdue event', 'an unknown event is refused (22023)');
select is((select count(*) from public.escalate_overdue_task(pg_temp.gid('e2'))), 3::bigint, 'twin: the other overdue task (untouched) is escalated');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 2. notice_acknowledgment_status and my_notices
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
insert into public.notices (id, organization_id, location_id, title, body, requires_acknowledgment) values
  (pg_temp.id('n_ack'),  pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Please acknowledge', 'b', true),
  (pg_temp.id('n_two'),  pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Second live notice', 'b', false),
  (pg_temp.id('n_draft'),pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Draft', 'b', false),
  (pg_temp.id('n_arch'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Archived', 'b', false);
insert into public.notice_audiences (organization_id, notice_id, location_id)
select pg_temp.id('org_a'), pg_temp.id(k), pg_temp.id(l) from (values ('n_ack', 'loc_a1'), ('n_two', 'loc_a1'), ('n_draft', 'loc_a1'), ('n_arch', 'loc_a1')) v (k, l);
select public.publish_notice(pg_temp.id('n_ack'));
select public.publish_notice(pg_temp.id('n_two'));
select public.publish_notice(pg_temp.id('n_arch'));
select public.archive_notice(pg_temp.id('n_arch'));
select pg_temp.act_as('u_orgadmin_a');
insert into public.notices (id, organization_id, location_id, title, body) values (pg_temp.id('n_a2'), pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'For A2 only', 'b');
insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n_a2'), pg_temp.id('loc_a2'));
select public.publish_notice(pg_temp.id('n_a2'));
select pg_temp.act_as('postgres');
-- the audience of n_ack is staff/manager/admins at A1 (4 people). Staff A1 acknowledges.
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.run($$select public.acknowledge_notice(pg_temp.id('n_ack'))$$), 'ok', 'staff A1 acknowledges the notice');
select pg_temp.act_as('postgres');

create temp table st (n int, who text, aal text, note text, expect text);
insert into st values
  (1, 'u_manager_a1',  'aal2', 'manager A1 (manages notices at A1)',          '3 rows, 1 acknowledged'),
  (2, 'u_orgadmin_a',  'aal2', 'org admin A',                                   '4 rows, 1 acknowledged'),
  (3, 'u_platform',    'aal2', 'platform admin',                                '4 rows, 1 acknowledged'),
  (4, 'u_locadmin_a1', 'aal2', 'location admin A1',                             '3 rows, 1 acknowledged'),
  (5, 'u_staff_a1',    'aal2', 'staff A1 (the person who acknowledged)',        '42501 not allowed'),
  (6, 'u_staff_a2',    'aal2', 'staff A2',                                      '42501 not allowed'),
  (7, 'u_orgadmin_b',  'aal2', 'org admin B',                                   '42501 not allowed'),
  (8, 'u_orgadmin_a',  'aal1', 'org admin A at aal1',                           '42501 not allowed'),
  (9, 'u_noaccount',   'aal2', 'a user with no account',                        '42501 not allowed'),
  (10, 'anon',         'aal2', 'anon',                                          '42501 permission denied for function notice_acknowledgment_status');
grant all on st to public;
create temp table st_got (n int, got text);
grant all on st_got to public;
do $$
declare r record; v text;
begin
  for r in select * from st order by n loop
    perform pg_temp.act_as(r.who, r.aal);
    v := pg_temp.f($q$select count(*)::text || ' rows, ' || count(acknowledged_at)::text || ' acknowledged' from public.notice_acknowledgment_status(pg_temp.id('n_ack'))$q$);
    insert into st_got values (r.n, v);
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select got from st_got g where g.n = r.n), r.expect, 'notice_acknowledgment_status: ' || r.note) from st r order by r.n;
select pg_temp.act_as('u_manager_a1');
select is((select person_id from public.notice_acknowledgment_status(pg_temp.id('n_ack')) offset 2), pg_temp.id('p_staff_a1'), 'people who have not acknowledged come first; the one who has comes last');
select is((select count(*) from public.notice_acknowledgment_status(pg_temp.id('n_ack')) where acknowledged_at is null and person_id = pg_temp.id('p_staff_a1')), 0::bigint, 'staff A1''s acknowledged_at is set');
select is(pg_temp.f(format('select count(*) from public.notice_acknowledgment_status(%L)', gen_random_uuid())), '42501 not allowed', 'a notice that does not exist: the same refusal as for one the caller does not manage');
select is((select count(*) from public.notice_acknowledgment_status(pg_temp.id('n_draft'))), 3::bigint, 'twin: a draft the manager manages can be asked about too (the audience as set)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.f($$select count(*) from public.notice_acknowledgment_status(pg_temp.id('n_a2'))$$), '42501 not allowed', 'a notice of another location (A2) that the manager does not manage: refused');
select pg_temp.act_as('postgres');
-- a person who acknowledged and then left the audience (archived) is still listed to someone who can see them
update public.people set archived_at = now() where id = pg_temp.id('p_staff_a1');
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.notice_acknowledgment_status(pg_temp.id('n_ack')) where person_id = pg_temp.id('p_staff_a1') and acknowledged_at is not null), 1::bigint, 'staff A1 archived after acknowledging: still listed, with the acknowledgment');
select is((select count(*) from public.notice_acknowledgment_status(pg_temp.id('n_ack'))), 4::bigint, 'and nobody else changed');
select pg_temp.act_as('postgres');
update public.people set archived_at = null where id = pg_temp.id('p_staff_a1');
-- a person with a disabled account who has not acknowledged drops out of the audience
update public.accounts set disabled_at = now() where id = pg_temp.id('acct_manager_a1');
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.notice_acknowledgment_status(pg_temp.id('n_ack'))), 3::bigint, 'a person with a disabled account who has not acknowledged drops out of the list (manager A1)');
select pg_temp.act_as('postgres');
update public.accounts set disabled_at = null where id = pg_temp.id('acct_manager_a1');
update public.accounts set disabled_at = now() where id = pg_temp.id('acct_staff_a1');
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.notice_acknowledgment_status(pg_temp.id('n_ack'))), 4::bigint, 'twin: one who acknowledged before being disabled stays listed');
select pg_temp.act_as('postgres');
update public.accounts set disabled_at = null where id = pg_temp.id('acct_staff_a1');

-- my_notices
update public.notices set publish_at = now() - interval '1 hour', published_at = now() - interval '1 hour' where id = pg_temp.id('n_two');
create temp table mn (n int, who text, aal text, org text, lim text, note text, expect text);
insert into mn values
  (1, 'u_staff_a1',    'aal2', null,    null, 'staff A1: the two live notices addressed to A1 (not the draft, the archived one or the A2 one)', 'Please acknowledge,Second live notice'),
  (2, 'u_staff_a2',    'aal2', null,    null, 'staff A2: only the A2 notice', 'For A2 only'),
  (3, 'u_staff_a1',    'aal2', 'org_b', null, 'staff A1 asking for organization B', ''),
  (4, 'u_staff_a1',    'aal2', 'org_a', null, 'staff A1 asking for organization A', 'Please acknowledge,Second live notice'),
  (5, 'u_staff_a1',    'aal2', null,    '1',  'a limit of 1', 'Please acknowledge'),
  (6, 'u_staff_a1',    'aal2', null,    '0',  'a limit of 0 is raised to 1', 'Please acknowledge'),
  (7, 'u_staff_a1',    'aal2', null,    '-5', 'a negative limit is raised to 1', 'Please acknowledge'),
  (8, 'u_staff_a1',    'aal2', null,    '5000', 'a huge limit still returns what exists', 'Please acknowledge,Second live notice'),
  (9, 'u_manager_a1',  'aal2', null,    null, 'manager A1: sees what is addressed to them (the A1 notices), not the A2 one', 'Please acknowledge,Second live notice'),
  (10, 'u_orgadmin_a', 'aal1', null,    null, 'org admin at aal1 (a non-member)', ''),
  (11, 'u_orgadmin_b', 'aal2', null,    null, 'org admin B (nothing is addressed to them)', ''),
  (12, 'u_noaccount',  'aal2', null,    null, 'a user with no account', ''),
  (13, 'anon',         'aal2', null,    null, 'anon', '42501 permission denied for function my_notices');
grant all on mn to public;
create temp table mn_got (n int, got text);
grant all on mn_got to public;
do $$
declare r record; v text;
begin
  for r in select * from mn order by n loop
    perform pg_temp.act_as(r.who, r.aal);
    v := pg_temp.f(format($q$select coalesce(string_agg(title, ',' order by title), '') from public.my_notices(%L::uuid, %L::int)$q$, case when r.org is null then null else pg_temp.id(r.org)::text end, r.lim));
    insert into mn_got values (r.n, v);
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select got from mn_got g where g.n = r.n), r.expect, 'my_notices: ' || r.note) from mn r order by r.n;
select pg_temp.act_as('u_staff_a1');
select is((select acknowledged_at is not null from public.my_notices() where title = 'Please acknowledge'), true, 'my_notices: the acknowledged one carries acknowledged_at');
select is((select acknowledged_at is null from public.my_notices() where title = 'Second live notice'), true, 'and the other has none');
select is((select requires_acknowledgment from public.my_notices() where title = 'Please acknowledge'), true, 'and requires_acknowledgment is shown');
select is((select title from public.my_notices() order by publish_at desc, notice_id limit 1), (select title from public.my_notices() limit 1), 'newest first');
select pg_temp.act_as('postgres');
update public.notices set expires_at = now() - interval '1 second', publish_at = now() - interval '2 hours', published_at = now() - interval '2 hours' where id = pg_temp.id('n_two');
select pg_temp.act_as('u_staff_a1');
select is((select coalesce(string_agg(title, ','), '') from public.my_notices()), 'Please acknowledge', 'twin: a notice whose time is up drops out of my_notices');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 3. Append-only guards (task_events, acknowledgments): UPDATE, DELETE, TRUNCATE; the cascade still works
-- ===========================================================================
create temp table ao (n int, tbl text, op text, sql text);
insert into ao values
  (1, 'task_events', 'update', $$update public.task_events set body = 'x'$$),
  (2, 'task_events', 'delete', $$delete from public.task_events$$),
  (3, 'task_events', 'truncate', $$truncate public.task_events$$),
  (4, 'acknowledgments', 'update', $$update public.acknowledgments set acknowledged_at = now()$$),
  (5, 'acknowledgments', 'delete', $$delete from public.acknowledgments$$),
  (6, 'acknowledgments', 'truncate', $$truncate public.acknowledgments$$);
grant all on ao to public;
create temp table ao_got (n int, who text, got text);
grant all on ao_got to public;
do $$
declare r record; w text;
begin
  for r in select * from ao order by n loop
    foreach w in array array['postgres', 'service_role', 'u_orgadmin_a', 'u_platform', 'anon'] loop
      perform pg_temp.act_as(w);
      insert into ao_got values (r.n, w, pg_temp.run(r.sql));
    end loop;
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select ok((select got from ao_got g where g.n = r.n and g.who = w.who) like '42501%', r.tbl || ': ' || r.op || ' is refused for ' || w.who)
  from ao r cross join (values ('postgres'), ('service_role'), ('u_orgadmin_a'), ('u_platform'), ('anon')) w (who) order by r.n, w.who;
select ok((select got from ao_got g where g.n = 2 and g.who = 'postgres') like '%append-only%', 'the owner''s refusal names the table: "task_events is append-only"');
select ok((select got from ao_got g where g.n = 5 and g.who = 'postgres') like '%append-only%', 'and for acknowledgments');
select cmp_ok((select count(*) from public.task_events), '>', 0::bigint, 'the task events are all still there');
select cmp_ok((select count(*) from public.acknowledgments), '>', 0::bigint, 'and the acknowledgments');
-- the cascade: deleting the parent removes the history
select is((select count(*) from public.task_events where task_id = pg_temp.gid('t1')), 3::bigint, 'sanity: task one has its history (created, two escalations)');
select is(pg_temp.run($$delete from public.tasks where id = pg_temp.gid('t1')$$), 'ok', 'deleting a task (as the owner) works');
select is((select count(*) from public.task_events where task_id = pg_temp.gid('t1')), 0::bigint, 'and its task events went with it (cascade)');
select is((select count(*) from public.task_events where task_id = pg_temp.gid('t2')), 2::bigint, 'twin: another task''s history is untouched');
select is((select count(*) from public.acknowledgments where notice_id = pg_temp.id('n_ack')), 1::bigint, 'sanity: the notice has one acknowledgment');
select is(pg_temp.run($$delete from public.notices where id = pg_temp.id('n_ack')$$), 'ok', 'deleting a notice (as the owner) works');
select is((select count(*) from public.acknowledgments where notice_id = pg_temp.id('n_ack')), 0::bigint, 'and its acknowledgments went with it (cascade)');
select is(pg_temp.run($$delete from public.task_events where task_id = pg_temp.gid('t2')$$)::text ~ '^42501', true, 'twin: deleting history directly while its task exists is still refused');
select is(pg_temp.run($$delete from public.organizations where id = pg_temp.id('org_b')$$), 'ok', 'deleting an organization (as the owner) works');
select is((select count(*) from public.organizations where id = pg_temp.id('org_b')), 0::bigint, 'organization B is gone');
select is((select count(*) from public.task_events where organization_id = pg_temp.id('org_b')), 0::bigint, 'with its task events');
select is((select count(*) from public.acknowledgments where organization_id = pg_temp.id('org_b')), 0::bigint, 'and its acknowledgments');
select cmp_ok((select count(*) from public.task_events where organization_id = pg_temp.id('org_a')), '>', 0::bigint, 'twin: organization A''s history is untouched');
select has_trigger('public', 'task_events', 'task_events_append_only_truncate', 'task_events has the truncate guard');
select has_trigger('public', 'acknowledgments', 'acknowledgments_append_only_truncate', 'acknowledgments has the truncate guard');

-- ===========================================================================
-- 4. Manual retries are capped (3)
-- ===========================================================================
insert into ids select 'ev_dead', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}');
create function pg_temp.kill(p_id uuid) returns void language sql as $$ update public.outbox_events set status = 'dead', attempts = 8, processed_at = null, locked_by = null, lock_expires_at = null where id = p_id $$;
grant execute on function pg_temp.kill(uuid) to public;
select pg_temp.kill(pg_temp.gid('ev_dead'));
select is(private.outbox_max_manual_retries(), 3, 'the cap is 3 manual retries');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.run($$select public.retry_dead_outbox_event(pg_temp.gid('ev_dead'))$$), 'ok', 'manual retry 1 works');
select pg_temp.act_as('postgres');
select pg_temp.kill(pg_temp.gid('ev_dead'));
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.run($$select public.retry_dead_outbox_event(pg_temp.gid('ev_dead'))$$), 'ok', 'manual retry 2 works');
select pg_temp.act_as('postgres');
select pg_temp.kill(pg_temp.gid('ev_dead'));
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.run($$select public.retry_dead_outbox_event(pg_temp.gid('ev_dead'))$$), 'ok', 'manual retry 3 works');
select pg_temp.act_as('postgres');
select pg_temp.kill(pg_temp.gid('ev_dead'));
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.run($$select public.retry_dead_outbox_event(pg_temp.gid('ev_dead'))$$), '22023 this job has been retried too many times; ask support', 'manual retry 4 is refused (22023)');
select pg_temp.act_as('postgres');
select results_eq($$select status, manual_retries from public.outbox_events where id = pg_temp.gid('ev_dead')$$, $$values ('dead'::text, 3)$$, 'the event stays dead with 3 manual retries');
select pg_temp.act_as('u_platform');
select is(pg_temp.run($$select public.retry_dead_outbox_event(pg_temp.gid('ev_dead'))$$), '22023 this job has been retried too many times; ask support', 'a platform admin is held to the same cap');
select pg_temp.act_as('postgres');
insert into ids select 'ev_dead2', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}');
select pg_temp.kill(pg_temp.gid('ev_dead2'));
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.run($$select public.retry_dead_outbox_event(pg_temp.gid('ev_dead2'))$$), 'ok', 'twin: another dead event has its own count');
select is(pg_temp.run($$select public.retry_dead_outbox_event(pg_temp.gid('ev_dead2'))$$), '22023 only failed events can be retried', 'a pending event cannot be retried (22023)');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.run($$select public.retry_dead_outbox_event(pg_temp.gid('ev_dead'))$$), '42501 not allowed', 'staff cannot retry (the permission is checked before the cap)');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 5. A failed delivery keeps its next_attempt_at
-- ===========================================================================
insert into ids select 'ev_d', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}');
select pg_temp.act_as('service_role');
select is(public.create_notifications(pg_temp.gid('ev_d'), array[pg_temp.id('p_staff_a2'), pg_temp.id('p_locadmin_a1'), pg_temp.id('p_manager_a1')], 'task.created', 'Delivery test'), 3, 'three notifications for the delivery tests');
select pg_temp.act_as('postgres');
insert into ids select 'd_perm', d.id from public.notification_deliveries d join public.notifications n on n.id = d.notification_id where n.source_event_id = pg_temp.gid('ev_d') and n.person_id = pg_temp.id('p_staff_a2') and d.channel = 'email';
insert into ids select 'd_last', d.id from public.notification_deliveries d join public.notifications n on n.id = d.notification_id where n.source_event_id = pg_temp.gid('ev_d') and n.person_id = pg_temp.id('p_locadmin_a1') and d.channel = 'email';
insert into ids select 'd_retry', d.id from public.notification_deliveries d join public.notifications n on n.id = d.notification_id where n.source_event_id = pg_temp.gid('ev_d') and n.person_id = pg_temp.id('p_manager_a1') and d.channel = 'email';
update public.notification_deliveries set next_attempt_at = timestamptz '2026-01-02 03:04:05+00' where id in (pg_temp.gid('d_perm'), pg_temp.gid('d_last'), pg_temp.gid('d_retry'));
update public.notification_deliveries set attempts = private.delivery_max_attempts() - 1 where id = pg_temp.gid('d_last');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_notification_deliveries('fw', 500, 60) where id in (pg_temp.gid('d_perm'), pg_temp.gid('d_last'), pg_temp.gid('d_retry'))), 3::bigint, 'a worker claims the three');
select is(public.fail_notification_delivery(pg_temp.gid('d_perm'), 'fw', 'bad address', true), 'failed', 'a permanent failure ends in failed');
select is(public.fail_notification_delivery(pg_temp.gid('d_last'), 'fw', 'timeout'), 'failed', 'a failure on the last allowed attempt ends in failed');
select is(public.fail_notification_delivery(pg_temp.gid('d_retry'), 'fw', 'timeout'), 'pending', 'twin: a failure with attempts left stays pending');
select pg_temp.act_as('postgres');
select is((select next_attempt_at from public.notification_deliveries where id = pg_temp.gid('d_perm')), timestamptz '2026-01-02 03:04:05+00', 'permanently failed: next_attempt_at is untouched (no future retry time on a final row)');
select is((select next_attempt_at from public.notification_deliveries where id = pg_temp.gid('d_last')), timestamptz '2026-01-02 03:04:05+00', 'failed on the last attempt: next_attempt_at is untouched');
select cmp_ok((select next_attempt_at from public.notification_deliveries where id = pg_temp.gid('d_retry')), '>', now(), 'twin: a retry sets the back-off time in the future');
select results_eq($$select status, locked_by, last_error from public.notification_deliveries where id in (pg_temp.gid('d_perm'), pg_temp.gid('d_last')) order by id$$,
  $$select 'failed'::text, null::text, e from (select id, case when id = pg_temp.gid('d_perm') then 'bad address' else 'timeout' end as e from public.notification_deliveries where id in (pg_temp.gid('d_perm'), pg_temp.gid('d_last'))) x order by id$$, 'both are failed, unlocked, with their error text');

-- ===========================================================================
-- 6. publish_notice validates before it writes
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
insert into public.notices (id, organization_id, location_id, title, body, expires_at, urgency) values
  (pg_temp.id('v_exp'),   pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Expires soon', 'b', now() + interval '1 hour', 'normal'),
  (pg_temp.id('v_noaud'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'No audience', 'b', null, 'normal'),
  (pg_temp.id('v_ok'),    pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Fine', 'b', null, 'normal'),
  (pg_temp.id('v_crit'),  pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Critical', 'b', null, 'critical');
insert into public.notice_audiences (organization_id, notice_id, location_id)
select pg_temp.id('org_a'), pg_temp.id(k), pg_temp.id('loc_a1') from (values ('v_exp'), ('v_ok'), ('v_crit')) v (k);
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_exp'), now() + interval '2 hours')$$), '22023 the notice would expire before it is shown', 'a publish time after the expiry is refused (22023)');
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_exp'), 'infinity')$$), '22023 invalid publish time', 'an infinite publish time is refused (22023)');
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_exp'), '-infinity')$$), '22023 invalid publish time', 'and so is -infinity');
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_noaud'))$$), '22023 choose who the notice is for first', 'a notice with no audience is refused (22023)');
select pg_temp.act_as('postgres');
select results_eq($$select status, publish_at is null, published_at is null from public.notices where id = pg_temp.id('v_exp')$$, $$values ('draft'::text, true, true)$$, 'a refused publish changed nothing: still a draft with no times');
select is((select count(*) from public.outbox_events where entity_id in (pg_temp.id('v_exp'), pg_temp.id('v_noaud'))), 0::bigint, 'and no event was emitted');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_exp'), now() + interval '30 minutes')$$), 'ok', 'twin: a publish time before the expiry works');
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_exp'))$$), '22023 only a draft can be published', 'publishing it again is refused (22023)');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_ok'))$$), '42501 not allowed', 'staff cannot publish');
select is(pg_temp.run(format('select public.publish_notice(%L)', gen_random_uuid())), '42501 not allowed', 'an unknown notice: the same refusal');
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_ok'))$$), '42501 not allowed', 'an admin of another organization cannot publish it');
select pg_temp.act_as('u_manager_a1');
-- (the limits themselves are in 180)
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_ok'), 'infinity')$$), '22023 invalid publish time', 'an infinite publish time is refused for a draft that is otherwise valid');
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_ok'))$$), 'ok', 'twin: a valid publish works');
select is(pg_temp.run($$select public.publish_notice(pg_temp.id('v_crit'))$$), 'ok', 'and so does a valid critical one');
select pg_temp.act_as('postgres');

select * from finish();
rollback;
