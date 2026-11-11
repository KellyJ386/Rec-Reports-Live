-- Phase 2 review fixes (000600 R3, R2d): message metadata is private. message.sent carries the message id only; message.* outbox
-- rows are invisible to every tenant (platform admins included) and cannot be retried by them; audit rows of the person-private
-- tables and of the worker ledger are hidden from every tenant and platform admin (the server key still reads them); and worker
-- bookkeeping is no longer written to the audit log. Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(91);

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
create function pg_temp.seen(p_sql text) returns bigint language plpgsql as $$
declare n bigint;
begin
  execute p_sql into n;
  return n;
exception when others then return -1;
end $$;
grant execute on function pg_temp.seen(text) to public;
create temp table ids (k text primary key, v uuid);
grant all on ids to public;
create function pg_temp.gid(p_k text) returns uuid language sql stable as $$ select v from ids where k = p_k $$;
grant execute on function pg_temp.gid(text) to public;

-- ===========================================================================
-- 1. The event type rule and the message event itself
-- ===========================================================================
select is(private.outbox_type_is_private(t.type), t.expect, 'outbox_type_is_private(' || coalesce(t.type, 'null') || ') = ' || t.expect)
from (values ('message.sent', true), ('message.read', true), ('message.anything_else', true), ('task.created', false), ('notice.published', false),
             ('messages.sent', false), ('message', true), ('messagesent', false), ('', false), (null, false)) t (type, expect);
select ok(has_function_privilege('authenticated', 'private.outbox_type_is_private(text)', 'execute') and has_function_privilege('service_role', 'private.outbox_type_is_private(text)', 'execute')
          and not has_function_privilege('anon', 'private.outbox_type_is_private(text)', 'execute'), 'outbox_type_is_private is executable by authenticated and service_role, not anon (the policies call it as the caller)');
select is(pg_temp.try_msg($$insert into public.outbox_events (organization_id, location_id, type, entity_table, entity_id, correlation_id) values (pg_temp.id('org_a'), null, 'Message.sent', 'messages', gen_random_uuid(), gen_random_uuid())$$)::text ~ '^23514', true, 'an event type must be lower case, so "Message.sent" cannot dodge the message.* rule');

select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_manager_a1')], 'MSG-PRIVATE-ONE')$$), 'ok', 'staff A1 sends a message to manager A1');
select pg_temp.act_as('postgres');
insert into ids select 'msg1', id from public.messages where body = 'MSG-PRIVATE-ONE';
select is((select count(*) from public.outbox_events where type = 'message.sent' and entity_id = pg_temp.gid('msg1')), 1::bigint, 'one message.sent event');
select is((select payload from public.outbox_events where type = 'message.sent' and entity_id = pg_temp.gid('msg1')), jsonb_build_object('message_id', pg_temp.gid('msg1')), 'its payload is exactly {"message_id": <id>}');
select is((select count(*) from public.outbox_events where type = 'message.sent' and (payload::text like '%' || pg_temp.id('p_staff_a1')::text || '%' or payload::text like '%' || pg_temp.id('p_manager_a1')::text || '%' or payload::text like '%MSG-PRIVATE%')), 0::bigint, 'neither the sender, the recipients nor the text are in it');
select is((select location_id from public.outbox_events where type = 'message.sent' and entity_id = pg_temp.gid('msg1')), null, 'and it has no location (so no location-scoped reader could match it either)');
-- a task event so there is something ordinary to see next to it
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'ordinary')$$), 'ok', 'a manager creates a task (an ordinary event)');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 2. Who can read outbox rows: everyone with audit_log view sees ordinary events and no message events
-- ===========================================================================
-- give a location manager audit_log view at the organization (an override) so there is a read-only auditor too
insert into public.user_permissions (organization_id, person_id, location_id, module_key, level) values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), null, 'audit_log', 'view');
create temp table orr (n int, who text, aal text, note text, ordinary text, msgs text);
insert into orr values
  (1, 'u_orgadmin_a',   'aal2', 'org admin A (audit_log admin)',              'positive', '0'),
  (2, 'u_platform',     'aal2', 'platform admin',                             'positive', '0'),
  (3, 'u_manager_a1',   'aal2', 'manager A1 with audit_log view at org scope','positive', '0'),
  (4, 'u_locadmin_a1',  'aal2', 'location admin A1',                          'positive', '0'),
  (5, 'u_orgadmin_a',   'aal1', 'org admin A at aal1',                        '0',        '0'),
  (6, 'u_staff_a1',     'aal2', 'staff A1 (sender of the message)',           '0',        '0'),
  (7, 'u_orgadmin_b',   'aal2', 'org admin B',                                '0',        '0'),
  (8, 'anon',           'aal2', 'anon',                                       '-1',       '-1'),
  (9, 'service_role',   'aal2', 'the server key (the worker reads every event)', 'positive', 'positive');
grant all on orr to public;
create temp table orr_got (n int, ordinary bigint, msgs bigint);
grant all on orr_got to public;
do $$
declare r record;
begin
  for r in select * from orr order by n loop
    perform pg_temp.act_as(r.who, r.aal);
    insert into orr_got values (r.n, pg_temp.seen($q$select count(*) from public.outbox_events where type = 'task.created'$q$),
                                     pg_temp.seen($q$select count(*) from public.outbox_events where type = 'message.sent'$q$));
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select case when o.ordinary = 'positive' then (g.ordinary > 0)::text else g.ordinary::text end from orr_got g where g.n = o.n),
          case when o.ordinary = 'positive' then 'true' else o.ordinary end, 'outbox, ordinary events: ' || o.note)
  from orr o order by o.n;
select is((select case when o.msgs = 'positive' then (g.msgs > 0)::text else g.msgs::text end from orr_got g where g.n = o.n),
          case when o.msgs = 'positive' then 'true' else o.msgs end, 'outbox, message events: ' || o.note)
  from orr o order by o.n;
select is((select count(*) from public.outbox_events where type = 'message.sent'), 1::bigint, 'sanity: the owner sees the message event (it exists)');

-- ===========================================================================
-- 3. A dead message event cannot be retried by a tenant; a dead ordinary one can
-- ===========================================================================
update public.outbox_events set status = 'dead', attempts = 8, last_error = 'x' where type in ('message.sent', 'task.created');
insert into ids select 'msg_ev', id from public.outbox_events where type = 'message.sent';
insert into ids select 'task_ev', id from public.outbox_events where type = 'task.created' limit 1;
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg(format('select public.retry_dead_outbox_event(%L)', pg_temp.gid('msg_ev'))), '42501 not allowed', 'retry: org admin A cannot retry a dead message event');
select is(pg_temp.try_msg(format('select public.retry_dead_outbox_event(%L)', gen_random_uuid())), '42501 not allowed', 'retry: the same answer as for an event that does not exist');
select pg_temp.act_as('u_platform');
select is(pg_temp.try_msg(format('select public.retry_dead_outbox_event(%L)', pg_temp.gid('msg_ev'))), '42501 not allowed', 'retry: a platform admin cannot retry a message event either');
select pg_temp.act_as('postgres');
select results_eq($$select status, attempts, manual_retries from public.outbox_events where id = pg_temp.gid('msg_ev')$$, $$values ('dead'::text, 8, 0)$$, 'the message event is untouched');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg(format('select public.retry_dead_outbox_event(%L)', pg_temp.gid('task_ev'))), 'ok', 'twin: the same org admin can retry a dead ordinary event');
select pg_temp.act_as('postgres');
select results_eq($$select status, manual_retries from public.outbox_events where id = pg_temp.gid('task_ev')$$, $$values ('pending'::text, 1)$$, 'and it is pending again with one manual retry counted');

-- ===========================================================================
-- 4. Audit rows of the person-private tables are hidden from every tenant and platform admin
-- ===========================================================================
select is((select array_agg(t order by t) from unnest(private.audit_hidden_tables()) t),
          array['message_recipients', 'messages', 'notification_deliveries', 'notification_preferences', 'notifications', 'outbox_event_handlers', 'push_subscriptions'],
          'the hidden audit tables are exactly: messages, message_recipients, notifications, notification_deliveries, push_subscriptions, notification_preferences, outbox_event_handlers');
select ok(has_function_privilege('authenticated', 'private.audit_hidden_tables()', 'execute') and not has_function_privilege('anon', 'private.audit_hidden_tables()', 'execute'), 'the list is callable by the policy as the caller, not by anon');
-- put a row in each hidden table (some through the real functions) and one ordinary audited change
insert into public.outbox_event_handlers (event_id, handler, organization_id) values (pg_temp.gid('task_ev'), 'tasks', pg_temp.id('org_a'));
insert into public.notifications (id, organization_id, person_id, kind, title, source_event_id) values (pg_temp.id('n1'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'k.x', 'T', pg_temp.gid('task_ev'));
insert into public.notification_deliveries (id, organization_id, notification_id, person_id, channel, status) values (pg_temp.id('dl1'), pg_temp.id('org_a'), pg_temp.id('n1'), pg_temp.id('p_staff_a1'), 'email', 'pending');
update public.notification_deliveries set status = 'sent', sent_at = now() where id = pg_temp.id('dl1');
insert into public.push_subscriptions (organization_id, person_id, endpoint, p256dh, auth_secret) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'https://fcm.googleapis.com/fcm/send/h1', 'BPhiddenhiddenhiddenhid1', 'hiddenauth1');
insert into public.notification_preferences (organization_id, person_id, channel, enabled) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'email', false);
update public.people set preferred_name = 'Visible change' where id = pg_temp.id('p_staff_a2');
select cmp_ok((select count(distinct table_name) from public.audit_log where table_name = any (private.audit_hidden_tables())), '>=', 5::bigint, 'sanity: the owner finds audit rows for the hidden tables (they are written, only hidden)');
create temp table ar (n int, who text, aal text, note text, hidden bigint, visible bigint, hidden_outbox_msg bigint);
insert into ar values
  (1, 'u_orgadmin_a',  'aal2', 'org admin A',               0, 1, 0),
  (2, 'u_platform',    'aal2', 'platform admin',            0, 1, 0),
  (3, 'u_manager_a1',  'aal2', 'manager A1 (audit view override; location-bound rows only)',   0, 0, 0),
  (4, 'u_locadmin_a1', 'aal2', 'location admin A1',         0, 0, 0),
  (5, 'u_orgadmin_b',  'aal2', 'org admin B',               0, 0, 0),
  (6, 'service_role',  'aal2', 'the server key',           -9, 1, -9);
grant all on ar to public;
create temp table ar_got (n int, hidden bigint, visible bigint, msg bigint);
grant all on ar_got to public;
-- an audited retry of the dead message event, done by the owner (so an audit row for a message.* event exists)
update public.outbox_events set manual_retries = manual_retries + 1, retried_at = now() where id = pg_temp.gid('msg_ev');
update public.outbox_events set manual_retries = manual_retries + 1, retried_at = now() where id = pg_temp.gid('task_ev');
do $$
declare r record;
begin
  for r in select * from ar order by n loop
    perform pg_temp.act_as(r.who, r.aal);
    insert into ar_got values (r.n,
      pg_temp.seen($q$select count(*) from public.audit_log where table_name = any (private.audit_hidden_tables())$q$),
      pg_temp.seen($q$select count(*) from public.audit_log where table_name = 'people' and organization_id = '$q$ || pg_temp.id('org_a') || $q$'$q$),
      pg_temp.seen($q$select count(*) from public.audit_log where table_name = 'outbox_events' and (new_row ->> 'type') = 'message.sent'$q$));
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select g.hidden from ar_got g where g.n = a.n), case when a.hidden = -9 then (select g.hidden from ar_got g where g.n = a.n) else 0::bigint end, 'audit_log, person-private tables: ' || a.note || case when a.hidden = -9 then ' (reads them: the server key sees everything)' else ' reads 0 rows' end)
  from ar a order by a.n;
select cmp_ok((select hidden from ar_got where n = 6), '>', 0::bigint, 'twin: the server key reads the hidden audit rows (so the 0 above is the policy, not an empty table)');
select is((select g.visible > 0 from ar_got g where g.n = a.n), a.visible = 1, 'audit_log, ordinary rows (a profile change): ' || a.note || case when a.visible = 1 then ' reads them' else ' reads none' end)
  from ar a order by a.n;
select is((select g.msg from ar_got g where g.n = a.n), 0::bigint, 'audit_log, the retry of a message event: ' || a.note || ' reads none')
  from ar a where a.n <= 5 order by a.n;
select cmp_ok((select msg from ar_got where n = 6), '>', 0::bigint, 'twin: the server key reads the message-event audit row (it exists)');
select pg_temp.act_as('u_orgadmin_a');
select cmp_ok((select count(*) from public.audit_log where table_name = 'outbox_events'), '>', 0::bigint, 'twin: the org admin does read audit rows of ordinary outbox events (the retry of the task event)');
select is((select count(*) from public.audit_log where table_name = 'outbox_events' and (new_row ->> 'type') = 'message.sent' or (old_row ->> 'type') = 'message.sent'), 0::bigint, 'but none of a message event, in the old or the new row');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 5. Worker bookkeeping is not audited; a person's manual retry and a delivery status change are
-- ===========================================================================
create temp table cnt as
  select (select count(*) from public.audit_log where table_name = 'outbox_events') as ob,
         (select count(*) from public.audit_log where table_name = 'outbox_event_handlers') as hd,
         (select count(*) from public.audit_log where table_name = 'notification_deliveries') as dv;
grant all on cnt to public;
-- an event: emitted (insert), claimed, failed, claimed again, completed
insert into ids select 'ev9', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}');
select is((select count(*) from public.audit_log where table_name = 'outbox_events') - (select ob from cnt), 0::bigint, 'emitting an event writes no audit row');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('wa', 50, 60) where id = pg_temp.gid('ev9')), 1::bigint, 'the worker claims it');
select is(public.fail_outbox_event(pg_temp.gid('ev9'), 'wa', 'AUD-FAIL'), 'pending', 'fails it (retry later)');
select pg_temp.act_as('postgres');
update public.outbox_events set next_attempt_at = now() where id = pg_temp.gid('ev9');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('wb', 50, 60) where id = pg_temp.gid('ev9')), 1::bigint, 'claims it again');
select is(public.record_outbox_handler(pg_temp.gid('ev9'), 'tasks'), true, 'records a handler in the ledger');
select is(public.complete_outbox_event(pg_temp.gid('ev9'), 'wb'), true, 'completes it');
select pg_temp.act_as('postgres');
select is((select count(*) from public.audit_log where table_name = 'outbox_events') - (select ob from cnt), 0::bigint, 'claim, fail, claim, complete: no outbox audit rows (worker bookkeeping)');
select is((select count(*) from public.audit_log where table_name = 'outbox_event_handlers') - (select hd from cnt), 0::bigint, 'a ledger row is not audited');
-- manual retry is audited, exactly once
update public.outbox_events set status = 'dead', attempts = 8, processed_at = null where id = pg_temp.gid('ev9');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg(format('select public.retry_dead_outbox_event(%L)', pg_temp.gid('ev9'))), 'ok', 'an org admin retries the dead event');
select pg_temp.act_as('postgres');
select is((select count(*) from public.audit_log where table_name = 'outbox_events') - (select ob from cnt), 1::bigint, 'the manual retry is audited: exactly one audit row');
select results_eq($$select action, actor_role, 'manual_retries' = any (changed_columns), 'retried_at' = any (changed_columns) from public.audit_log where table_name = 'outbox_events' and row_id = pg_temp.gid('ev9')::text$$,
  $$values ('update'::text, 'authenticated'::text, true, true)$$, 'it is an update by the person (authenticated), listing manual_retries and retried_at as changed');
-- deliveries
insert into public.notifications (id, organization_id, person_id, kind, title, source_event_id) values (pg_temp.id('n2'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'k.y', 'T', pg_temp.gid('ev9'));
insert into public.notification_deliveries (id, organization_id, notification_id, person_id, channel, status) values
  (pg_temp.id('dl2'), pg_temp.id('org_a'), pg_temp.id('n2'), pg_temp.id('p_staff_a1'), 'email', 'pending'),
  (pg_temp.id('dl3'), pg_temp.id('org_a'), pg_temp.id('n2'), pg_temp.id('p_staff_a1'), 'push', 'pending');
select is((select count(*) from public.audit_log where table_name = 'notification_deliveries') - (select dv from cnt), 0::bigint, 'creating deliveries writes no audit row');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_notification_deliveries('dw', 10, 60) where id in (pg_temp.id('dl2'), pg_temp.id('dl3'))), 2::bigint, 'the worker claims both');
select is(public.fail_notification_delivery(pg_temp.id('dl2'), 'dw', 'try later'), 'pending', 'one fails with a retry (the status stays pending)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.audit_log where table_name = 'notification_deliveries') - (select dv from cnt), 0::bigint, 'claim, lock and a retry failure (status unchanged): still no audit rows');
select pg_temp.act_as('service_role');
select is(public.complete_notification_delivery(pg_temp.id('dl3'), 'dw', 'prov'), true, 'the other completes (pending -> sent)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.audit_log where table_name = 'notification_deliveries') - (select dv from cnt), 1::bigint, 'a status change is audited: one row');
select results_eq($$select action, new_row ->> 'status', new_row ->> 'provider_message_id' from public.audit_log where table_name = 'notification_deliveries' and row_id = pg_temp.id('dl3')::text$$,
  $$values ('update'::text, 'sent'::text, '[redacted]'::text)$$, 'and its provider id is redacted');
select results_eq($$select count(*)::int from public.audit_log where table_name = 'notification_deliveries' and row_id = pg_temp.id('dl3')::text and action = 'insert'$$, $$values (0)$$, 'the delivery''s creation was never audited');
select pg_temp.act_as('service_role');
select pg_temp.act_as('postgres');
update public.notification_deliveries set next_attempt_at = now() where id = pg_temp.id('dl2');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_notification_deliveries('dw2', 10, 60) where id = pg_temp.id('dl2')), 1::bigint, 'it is claimed again once its retry time has come');
select is(public.fail_notification_delivery(pg_temp.id('dl2'), 'dw2', 'dead end', true), 'failed', 'the first one then fails for good (pending -> failed)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.audit_log where table_name = 'notification_deliveries') - (select dv from cnt), 2::bigint, 'a second status change: two audit rows in all');
-- business tables are still audited (twin)
select cmp_ok((select count(*) from public.audit_log where table_name = 'tasks'), '>', 0::bigint, 'twin: the business tables are still audited (tasks)');
select cmp_ok((select count(*) from public.audit_log where table_name = 'messages' and action = 'insert'), '>', 0::bigint, 'twin: the message insert is still audited (hidden from tenants, redacted)');

select * from finish();
rollback;
