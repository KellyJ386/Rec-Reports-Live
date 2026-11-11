-- Phase 2 review fixes (000600 R2): the three batch claimers are round-robin by organization (one busy organization cannot
-- starve another); every event-emitting write RPC has a per-person limit that answers PT429 "slow down" (and a second person is
-- unaffected, a refused call does not count, the window ends); no time or date column and no time argument accepts infinity.
-- Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(84);

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

create function pg_temp.try_msg(p_sql text) returns text language plpgsql as $$
begin
  execute p_sql;
  return 'ok';
exception when others then return sqlstate || ' ' || sqlerrm;
end $$;
grant execute on function pg_temp.try_msg(text) to public;
create temp table ids (k text primary key, v uuid);
grant all on ids to public;
create function pg_temp.gid(p_k text) returns uuid language sql stable as $$ select v from ids where k = p_k $$;
grant execute on function pg_temp.gid(text) to public;

-- ===========================================================================
-- 1. Round-robin claims
-- ===========================================================================
-- org A has 6 due events (older), org B has 2 (newer). Without fairness a batch of 4 would be all org A.
insert into public.outbox_events (id, organization_id, location_id, type, entity_table, entity_id, correlation_id, next_attempt_at)
select pg_temp.id('rr_a' || g), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), pg_temp.id('rr_a' || g), now() - interval '1 hour' + g * interval '1 second'
from generate_series(1, 6) g;
insert into public.outbox_events (id, organization_id, location_id, type, entity_table, entity_id, correlation_id, next_attempt_at)
select pg_temp.id('rr_b' || g), pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'task.created', 'tasks', gen_random_uuid(), pg_temp.id('rr_b' || g), now() - interval '10 minutes' + g * interval '1 second'
from generate_series(1, 2) g;
create temp table cl (w text, id uuid, org uuid, n int);
grant all on cl to public;
select pg_temp.act_as('service_role');
insert into cl select 'w1', e.id, e.organization_id, 0 from public.claim_outbox_events('w1', 4, 60) e;
select pg_temp.act_as('postgres');
select is((select count(*) from cl where w = 'w1' and org = pg_temp.id('org_a')), 2::bigint, 'outbox: a batch of 4 takes 2 events of org A (the busy organization)...');
select is((select count(*) from cl where w = 'w1' and org = pg_temp.id('org_b')), 2::bigint, '...and 2 of org B, although B''s events are newer');
select is((select count(*) from cl where w = 'w1' and id in (pg_temp.id('rr_a1'), pg_temp.id('rr_a2'), pg_temp.id('rr_b1'), pg_temp.id('rr_b2'))), 4::bigint, 'and they are each organization''s oldest two');
select pg_temp.act_as('service_role');
insert into cl select 'w2', e.id, e.organization_id, 0 from public.claim_outbox_events('w2', 3, 60) e;
select pg_temp.act_as('postgres');
select is((select count(*) from cl where w = 'w2' and org = pg_temp.id('org_a')), 3::bigint, 'twin: when only one organization has work left, it gets the whole batch (org A: 3)');
select is((select count(*) from cl where w = 'w2' and id in (pg_temp.id('rr_a3'), pg_temp.id('rr_a4'), pg_temp.id('rr_a5'))), 3::bigint, 'in order of age');
-- one claimer does not get a row another holds
select is((select count(*) from (select id from cl group by id having count(*) > 1) d), 0::bigint, 'no event was handed to both claimers');
-- limit 3 over three rounds: A1, B1, A2
update public.outbox_events set status = 'pending', attempts = 0, locked_by = null, locked_at = null, lock_expires_at = null where id in (select id from cl);
delete from cl;
select pg_temp.act_as('service_role');
insert into cl select 'w3', e.id, e.organization_id, 0 from public.claim_outbox_events('w3', 3, 60) e;
select pg_temp.act_as('postgres');
select is((select count(*) from cl where org = pg_temp.id('org_a')), 2::bigint, 'outbox: a batch of 3 is A, B, A (2 of A, 1 of B)');
select is((select count(*) from cl where org = pg_temp.id('org_b')), 1::bigint, 'one of B');

-- deliveries: 6 for org A (older), 2 for org B
insert into public.notifications (id, organization_id, person_id, kind, title, source_event_id)
select pg_temp.id('nf_a' || g), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'k.a' || g, 't', gen_random_uuid() from generate_series(1, 6) g;
insert into public.notifications (id, organization_id, person_id, kind, title, source_event_id)
select pg_temp.id('nf_b' || g), pg_temp.id('org_b'), pg_temp.id('p_staff_b1'), 'k.b' || g, 't', gen_random_uuid() from generate_series(1, 2) g;
insert into public.notification_deliveries (id, organization_id, notification_id, person_id, channel, status, next_attempt_at)
select pg_temp.id('dl_a' || g), pg_temp.id('org_a'), pg_temp.id('nf_a' || g), pg_temp.id('p_staff_a1'), 'email', 'pending', now() - interval '1 hour' + g * interval '1 second' from generate_series(1, 6) g;
insert into public.notification_deliveries (id, organization_id, notification_id, person_id, channel, status, next_attempt_at)
select pg_temp.id('dl_b' || g), pg_temp.id('org_b'), pg_temp.id('nf_b' || g), pg_temp.id('p_staff_b1'), 'email', 'pending', now() - interval '10 minutes' + g * interval '1 second' from generate_series(1, 2) g;
delete from cl;
select pg_temp.act_as('service_role');
insert into cl select 'd1', d.id, d.organization_id, 0 from public.claim_notification_deliveries('d1', 4, 60) d;
select pg_temp.act_as('postgres');
select is((select count(*) from cl where org = pg_temp.id('org_a')), 2::bigint, 'deliveries: a batch of 4 takes 2 of org A...');
select is((select count(*) from cl where org = pg_temp.id('org_b')), 2::bigint, '...and 2 of org B');
select is((select count(*) from cl where id in (pg_temp.id('dl_a1'), pg_temp.id('dl_a2'), pg_temp.id('dl_b1'), pg_temp.id('dl_b2'))), 4::bigint, 'each organization''s oldest two');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_notification_deliveries('d2', 100, 60) d where d.organization_id = pg_temp.id('org_a')), 4::bigint, 'twin: the rest is org A''s 4 remaining deliveries');
select pg_temp.act_as('postgres');

-- overdue sweep: 6 overdue tasks in A, 2 in B
insert into public.tasks (id, organization_id, location_id, title, due_at)
select pg_temp.id('od_a' || g), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'od a' || g, now() - interval '5 hours' + g * interval '1 minute' from generate_series(1, 6) g;
insert into public.tasks (id, organization_id, location_id, title, due_at)
select pg_temp.id('od_b' || g), pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'od b' || g, now() - interval '1 hour' + g * interval '1 minute' from generate_series(1, 2) g;
select pg_temp.act_as('service_role');
select is(public.emit_overdue_task_events(4), 4, 'overdue sweep: a limit of 4 emits 4 events');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'task.overdue' and organization_id = pg_temp.id('org_a')), 2::bigint, 'sweep: 2 for org A...');
select is((select count(*) from public.outbox_events where type = 'task.overdue' and organization_id = pg_temp.id('org_b')), 2::bigint, 'sweep: ...and 2 for org B (not 4 for the busy organization)');
select pg_temp.act_as('service_role');
select is(public.emit_overdue_task_events(100), 4, 'twin: the next sweep emits the 4 that remain (once per task per due time)');
select is(public.emit_overdue_task_events(100), 0, 'and then nothing more');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 2. Write limits
-- ===========================================================================
create function pg_temp.fill(p_bucket text, p_user text, p_n int, p_max int, p_window int) returns bigint language sql as $$
  select count(public.consume_rate_limit(p_bucket, pg_temp.id(p_user)::text, p_max, p_window)) from generate_series(1, p_n)
$$;
grant execute on function pg_temp.fill(text, text, int, int, int) to public;
create function pg_temp.hits(p_bucket text) returns int language sql as $$ select coalesce(max(hits), 0) from private.rate_limit_counters where bucket = p_bucket $$;
create function pg_temp.new_window(p_bucket text) returns void language sql as $$
  update private.rate_limit_counters set window_start = window_start - interval '1 day', window_end = now() - interval '1 second' where bucket = p_bucket
$$;
grant execute on function pg_temp.hits(text), pg_temp.new_window(text) to public;

-- the table of limits itself
select results_eq($$select action, max_hits, window_seconds from private.write_limits() order by action$$,
  $$values ('availability_edit'::text, 60, 600), ('message_send', 30, 600), ('notice_critical', 5, 86400), ('notice_publish', 20, 3600),
           ('push_save', 10, 3600), ('schedule_publish', 20, 3600), ('shift_decide', 120, 600), ('shift_edit', 300, 600),
           ('shift_exchange', 30, 600), ('staffing_config', 120, 600), ('task_comment', 60, 600), ('task_create', 60, 600),
           ('task_transition', 120, 600), ('time_off_decide', 120, 600), ('time_off_request', 20, 3600)$$,
  'the write limits are exactly: task_create 60/10 min, task_comment 60/10 min, task_transition 120/10 min, message_send 30/10 min, notice_publish 20/h, notice_critical 5/day, push_save 10/h, and the eight staffing limits (staffing_config 120/10 min, shift_edit 300/10 min, schedule_publish 20/h, shift_exchange 30/10 min, shift_decide 120/10 min, availability_edit 60/10 min, time_off_request 20/h, time_off_decide 120/10 min)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try('select private.write_limits()'), '42501', 'the limits table is not readable by users');
select is(pg_temp.try($$select private.enforce_write_limit('task_create')$$), '42501', 'nor can a user call the limiter directly');
select pg_temp.act_as('postgres');
select is(pg_temp.try_msg($$select private.enforce_write_limit('task_create')$$), 'ok', 'twin: code with no signed-in user (the worker, the owner) is not limited');
select pg_temp.act_as('service_role');
select is(pg_temp.try($$select private.enforce_write_limit('task_create')$$), '42501', 'service_role cannot call the limiter either (it is internal)');
select pg_temp.act_as('postgres');

-- ---- task_create (create_task): 60 per 10 minutes
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'limit 1')$$), 'ok', 'create_task: the first call is fine');
select pg_temp.act_as('postgres');
select is(pg_temp.fill('write.task_create', 'u_manager_a1', 59, 60, 600), 59::bigint, 'the manager makes 59 more calls to the limiter (60 in the window)');
select is(pg_temp.hits('write.task_create'), 60, 'the counter is at 60');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'limit 61')$$), 'PT429 slow down', 'create_task: the 61st call is refused with PT429 "slow down"');
select pg_temp.act_as('postgres');
select is((select count(*) from public.tasks where title = 'limit 61'), 0::bigint, 'and nothing was created');
select is(pg_temp.hits('write.task_create'), 60, 'a refused call does not count against the window');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'other person')$$), 'ok', 'twin: another person is unaffected (staff A1 can still create a task)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.add_task_comment((select id from public.tasks where title = 'limit 1'), 'a comment')$$), 'ok', 'twin: the same person can still do other things (comment: its own bucket)');
select pg_temp.act_as('postgres');
select pg_temp.new_window('write.task_create');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'after the window')$$), 'ok', 'twin: when the window has passed the same person can create again');
select pg_temp.act_as('postgres');

-- ---- task_comment: 60 per 10 minutes
select pg_temp.fill('write.task_comment', 'u_manager_a1', 59, 60, 600);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.add_task_comment((select id from public.tasks where title = 'limit 1'), 'one too many')$$), 'PT429 slow down', 'add_task_comment: refused with PT429 after 60 in the window');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.add_task_comment((select id from public.tasks where title = 'other person'), 'staff comment')$$), 'ok', 'twin: another person can still comment');
select pg_temp.act_as('postgres');
select is((select count(*) from public.task_events where body = 'one too many'), 0::bigint, 'the refused comment was not stored');

-- ---- task_transition: 120 per 10 minutes, shared by start, complete, reopen, assign, cancel
insert into public.tasks (id, organization_id, location_id, title) select pg_temp.id('tr' || g), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tr ' || g from generate_series(1, 6) g;
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.start_task(pg_temp.id('tr1'))$$), 'ok', 'start_task: fine below the limit');
select pg_temp.act_as('postgres');
select pg_temp.fill('write.task_transition', 'u_manager_a1', 119, 120, 600);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.start_task(pg_temp.id('tr2'))$$), 'PT429 slow down', 'start_task: refused at the 121st transition in the window');
select is(pg_temp.try_msg($$select public.complete_task(pg_temp.id('tr1'))$$), 'PT429 slow down', 'complete_task: the same bucket');
select is(pg_temp.try_msg($$select public.reopen_task(pg_temp.id('tr1'))$$), 'PT429 slow down', 'reopen_task: the same bucket (checked before the state)');
select is(pg_temp.try_msg($$select public.assign_task(pg_temp.id('tr3'), pg_temp.id('p_staff_a1'), null)$$), 'PT429 slow down', 'assign_task: the same bucket');
select is(pg_temp.try_msg($$select public.cancel_task(pg_temp.id('tr3'))$$), 'PT429 slow down', 'cancel_task: the same bucket');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.start_task(pg_temp.id('tr2'))$$), 'ok', 'twin: another person''s transitions are unaffected');
select pg_temp.act_as('postgres');
select is((select status from public.tasks where id = pg_temp.id('tr1')), 'in_progress', 'tr1 is still in progress: none of the refused calls changed anything');
select is((select status from public.tasks where id = pg_temp.id('tr3')), 'open', 'tr3 is still open');
select is(pg_temp.hits('write.task_transition'), 120, 'refused calls did not count');
select pg_temp.new_window('write.task_transition');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.cancel_task(pg_temp.id('tr3'))$$), 'ok', 'twin: after the window the manager can transition again');
select pg_temp.act_as('postgres');

-- ---- message_send: 30 per 10 minutes
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_staff_a1')], 'm1')$$), 'ok', 'send_message: fine below the limit');
select pg_temp.act_as('postgres');
select pg_temp.fill('write.message_send', 'u_manager_a1', 29, 30, 600);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_staff_a1')], 'm31')$$), 'PT429 slow down', 'send_message: the 31st message in the window is refused');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_manager_a1')], 'reply')$$), 'ok', 'twin: another person can still send');
select pg_temp.act_as('postgres');
select is((select count(*) from public.messages where body = 'm31'), 0::bigint, 'the refused message was not stored');
select is((select count(*) from public.outbox_events where type = 'message.sent'), 2::bigint, 'and no message.sent event was written for it (2: m1 and the reply)');

-- ---- notice_publish: 20 per hour; notice_critical: 5 per day
insert into public.notices (id, organization_id, location_id, title, body, urgency) values
  (pg_temp.id('np1'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'np1', 'x', 'normal'),
  (pg_temp.id('np2'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'np2', 'x', 'normal'),
  (pg_temp.id('np3'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'np3', 'x', 'normal'),
  (pg_temp.id('nc1'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'nc1', 'x', 'critical'),
  (pg_temp.id('nc2'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'nc2', 'x', 'critical'),
  (pg_temp.id('nc3'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'nc3', 'x', 'critical');
insert into public.notice_audiences (organization_id, notice_id, location_id)
select pg_temp.id('org_a'), id, pg_temp.id('loc_a1') from public.notices where title in ('np1', 'np2', 'np3', 'nc1', 'nc2', 'nc3');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('np1'))$$), 'ok', 'publish_notice: fine below the limit');
select pg_temp.act_as('postgres');
select pg_temp.fill('write.notice_publish', 'u_manager_a1', 19, 20, 3600);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('np2'))$$), 'PT429 slow down', 'publish_notice: the 21st publish in the hour is refused');
select pg_temp.act_as('postgres');
select is((select status from public.notices where id = pg_temp.id('np2')), 'draft', 'and the notice is still a draft (the whole call rolled back)');
select is((select count(*) from public.outbox_events where type = 'notice.published' and entity_id = pg_temp.id('np2')), 0::bigint, 'with no notice.published event');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('np3'))$$), 'ok', 'twin: another person can still publish');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('nc1'))$$), 'ok', 'publish_notice: a critical notice is fine below its limit (the daily critical count is 1)');
select pg_temp.act_as('postgres');
select pg_temp.fill('write.notice_critical', 'u_orgadmin_a', 4, 5, 86400);
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('nc2'))$$), 'PT429 slow down', 'publish_notice: the 6th critical notice in a day is refused');
select pg_temp.act_as('postgres');
select is((select status from public.notices where id = pg_temp.id('nc2')), 'draft', 'the critical notice stays a draft');
insert into public.notices (id, organization_id, location_id, title, body, urgency) values (pg_temp.id('np4'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'np4', 'x', 'normal');
insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('np4'), pg_temp.id('loc_a1'));
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('np4'))$$), 'ok', 'twin: the same person can still publish a NORMAL notice (the critical cap is on top of the hourly one)');
select pg_temp.act_as('postgres');
select pg_temp.new_window('write.notice_publish');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('np2'))$$), 'ok', 'twin: after the hour the manager can publish again');
select pg_temp.act_as('postgres');
-- a validation failure does not use up the limit (checked before counting)
insert into public.notices (id, organization_id, location_id, title, body) values (pg_temp.id('np_noaud'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'np_noaud', 'x');
select pg_temp.fill('write.notice_publish', 'u_manager_a1', 19, 20, 3600);
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('np_noaud'))$$), '22023 choose who the notice is for first', 'publish_notice: a notice with no audience gets its own error, not PT429');
select pg_temp.act_as('postgres');

-- ---- push_save: 10 per hour
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://fcm.googleapis.com/fcm/send/p1', 'BPpushpushpushpushpush1', 'pushauth1')$$), 'ok', 'save_push_subscription: fine below the limit');
select pg_temp.act_as('postgres');
select pg_temp.fill('write.push_save', 'u_staff_a1', 9, 10, 3600);
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://fcm.googleapis.com/fcm/send/p2', 'BPpushpushpushpushpush1', 'pushauth1')$$), 'PT429 slow down', 'save_push_subscription: the 11th save in the hour is refused');
select pg_temp.act_as('postgres');
select is((select count(*) from public.push_subscriptions where endpoint like '%/p2'), 0::bigint, 'and nothing was stored');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://fcm.googleapis.com/fcm/send/p3', 'BPpushpushpushpushpush1', 'pushauth1')$$), 'ok', 'twin: another person can still save a device');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 3. Infinity is refused everywhere
-- ===========================================================================
create temp table fin (n int, label text, res text);
grant all on fin to public;
insert into fin values
  (1, 'tasks.due_at +infinity',                  pg_temp.try_msg($$insert into public.tasks (organization_id, location_id, title, due_at) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'inf', 'infinity')$$)),
  (2, 'tasks.due_at -infinity',                  pg_temp.try_msg($$insert into public.tasks (organization_id, location_id, title, due_at) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'inf', '-infinity')$$)),
  (3, 'tasks.due_at on update',                  pg_temp.try_msg($$update public.tasks set due_at = 'infinity' where id = pg_temp.id('tr4')$$)),
  (4, 'notices.expires_at',                      pg_temp.try_msg($$update public.notices set expires_at = 'infinity' where id = pg_temp.id('np_noaud')$$)),
  (5, 'notices.publish_at',                      pg_temp.try_msg($$update public.notices set publish_at = '-infinity' where id = pg_temp.id('np_noaud')$$)),
  (6, 'outbox_events.next_attempt_at',           pg_temp.try_msg($$insert into public.outbox_events (organization_id, location_id, type, entity_table, entity_id, correlation_id, next_attempt_at) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), gen_random_uuid(), 'infinity')$$)),
  (7, 'notification_deliveries.next_attempt_at', pg_temp.try_msg($$update public.notification_deliveries set next_attempt_at = 'infinity' where id = pg_temp.id('dl_a1')$$)),
  (8, 'locations.archived_at',                   pg_temp.try_msg($$update public.locations set archived_at = 'infinity' where id = pg_temp.id('loc_a2')$$)),
  (9, 'people.archived_at',                      pg_temp.try_msg($$update public.people set archived_at = 'infinity' where id = pg_temp.id('p_staff_a2')$$)),
  (10, 'a finite value is fine (twin)',          pg_temp.try_msg($$update public.tasks set due_at = now() + interval '1 day' where id = pg_temp.id('tr4')$$));
select matches((select res from fin where n = f.n), '^23514 .*finite_', 'a CHECK named finite_<column> refuses ' || f.label) from fin f where f.n <= 9 order by f.n;
select is((select res from fin where n = 10), 'ok', 'twin: an ordinary time is accepted');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'inf due', null, 'infinity')$$), '22023 invalid due time', 'create_task: an infinite due time is refused (22023, not a constraint error)');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'inf due', null, '-infinity')$$), '22023 invalid due time', 'and so is -infinity');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'finite due', null, now() + interval '1 day')$$), 'ok', 'twin: a finite due time is accepted');
select pg_temp.act_as('postgres');
select is((select count(*) from public.tasks where title = 'inf due'), 0::bigint, 'nothing was created by the refused calls');
select pg_temp.new_window('write.notice_publish');
select pg_temp.act_as('u_manager_a1');
insert into ids select 'ndraft', id from public.notices where title = 'np_noaud';
select pg_temp.act_as('postgres');
insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.gid('ndraft'), pg_temp.id('loc_a1'));
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.gid('ndraft'), 'infinity')$$), '22023 invalid publish time', 'publish_notice: an infinite publish time is refused (22023)');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.gid('ndraft'), '-infinity')$$), '22023 invalid publish time', 'and so is -infinity');
select pg_temp.act_as('postgres');
select is((select status from public.notices where id = pg_temp.gid('ndraft')), 'draft', 'the notice is still a draft');
select is(pg_temp.try_msg($$select private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}', 1, null, 'infinity')$$), '22023 invalid time', 'emit_event: an infinite available_at is refused (22023)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.gid('ndraft'), now() + interval '1 hour')$$), 'ok', 'twin: a finite publish time is accepted');
select pg_temp.act_as('postgres');

select * from finish();
rollback;
