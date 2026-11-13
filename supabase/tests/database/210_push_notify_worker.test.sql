-- Phase 2 review fixes (000600 R2, R5, R6, R10, R11, R12; 000700 M1, M2): push endpoint allowlist, 10-device cap, endpoint ownership;
-- notice fan-out only when live; create_notifications; the worker_* read functions (including worker_message_recipients_for_event);
-- release and extend of locks. Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(181);

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

-- BEGIN PHASE 2 ROWS: byte-identical in every file that uses it (020, 050).
-- Phase 2 rows: one row in each of the 15 Phase 2 tables, in both organizations, written
-- with the owner's rights because the API roles cannot write most of them (and they are what the
-- generated tests below are about). Org A: staff A1 sends a message to manager A1 and owns the
-- notification, push subscription and preference. Org B: staff B1 sends to staff B2 (a person with no
-- login), so org admin B is neither sender nor recipient.
insert into public.people (id, organization_id, first_name, last_name) values
  (pg_temp.id('p_staff_b2'), pg_temp.id('org_b'), 'Bao', 'StaffB2');
insert into public.outbox_events (id, organization_id, location_id, type, entity_table, entity_id, correlation_id, payload)
select pg_temp.id('ev_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), 'task.created', 'tasks', pg_temp.id('task_' || v.k),
       pg_temp.id('ev_' || v.k), jsonb_build_object('task_id', pg_temp.id('task_' || v.k))
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.outbox_event_handlers (event_id, handler, organization_id)
select pg_temp.id('ev_' || v.k), 'tasks', pg_temp.id(v.org) from (values ('a', 'org_a'), ('b', 'org_b')) v (k, org);
insert into public.task_templates (id, organization_id, location_id, title)
select pg_temp.id('tpl_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), 'Template ' || v.k
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.workflow_rules (id, organization_id, location_id, name, event_type, task_template_id)
select pg_temp.id('rule_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), 'Rule ' || v.k, 'booking.confirmed', pg_temp.id('tpl_' || v.k)
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.tasks (id, organization_id, location_id, title, assigned_person_id)
select pg_temp.id('task_' || v.k), pg_temp.id(v.org), pg_temp.id(v.loc), 'Task ' || v.k, pg_temp.id(v.person)
from (values ('a', 'org_a', 'loc_a1', 'p_staff_a1'), ('b', 'org_b', 'loc_b1', 'p_staff_b1')) v (k, org, loc, person);
insert into public.task_events (organization_id, location_id, task_id, kind)
select pg_temp.id(v.org), pg_temp.id(v.loc), pg_temp.id('task_' || v.k), 'created'
from (values ('a', 'org_a', 'loc_a1'), ('b', 'org_b', 'loc_b1')) v (k, org, loc);
insert into public.notices (id, organization_id, location_id, title, body)
select pg_temp.id('notice_' || v.k), pg_temp.id(v.org), null, 'Notice ' || v.k, 'Body ' || v.k
from (values ('a', 'org_a'), ('b', 'org_b')) v (k, org);
insert into public.notice_audiences (id, organization_id, notice_id)
select pg_temp.id('aud_' || v.k), pg_temp.id(v.org), pg_temp.id('notice_' || v.k) from (values ('a', 'org_a'), ('b', 'org_b')) v (k, org);
insert into public.acknowledgments (organization_id, notice_id, person_id)
select pg_temp.id(v.org), pg_temp.id('notice_' || v.k), pg_temp.id(v.person)
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, person);
insert into public.messages (id, organization_id, sender_person_id, body)
select pg_temp.id('msg_' || v.k), pg_temp.id(v.org), pg_temp.id(v.sender), 'Private body ' || v.k
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, sender);
insert into public.message_recipients (organization_id, message_id, person_id)
select pg_temp.id(v.org), pg_temp.id('msg_' || v.k), pg_temp.id(v.rcpt)
from (values ('a', 'org_a', 'p_manager_a1'), ('b', 'org_b', 'p_staff_b2')) v (k, org, rcpt);
insert into public.notifications (id, organization_id, person_id, kind, title, source_event_id)
select pg_temp.id('notif_' || v.k), pg_temp.id(v.org), pg_temp.id(v.person), 'task.created', 'Notification ' || v.k, pg_temp.id('ev_' || v.k)
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, person);
insert into public.notification_deliveries (organization_id, notification_id, person_id, channel, status, sent_at)
select pg_temp.id(v.org), pg_temp.id('notif_' || v.k), pg_temp.id(v.person), 'in_app', 'sent', now()
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, person);
insert into public.push_subscriptions (organization_id, person_id, endpoint, p256dh, auth_secret)
select pg_temp.id(v.org), pg_temp.id(v.person), 'https://fcm.googleapis.com/fcm/send/' || v.k, 'BPfixturefixturefixturefixture' || v.k, 'fixtureauth' || v.k
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, person);
insert into public.notification_preferences (organization_id, person_id, channel, enabled)
select pg_temp.id(v.org), pg_temp.id(v.person), 'email', false from (values ('org_a', 'p_staff_a1'), ('org_b', 'p_staff_b1')) v (org, person);

-- END PHASE 2 ROWS

create function pg_temp.f(p_sql text) returns text language plpgsql as $$
declare r text;
begin
  execute p_sql into r;
  return coalesce(r, 'null');
exception when others then return sqlstate || ' ' || sqlerrm;
end $$;
grant execute on function pg_temp.f(text) to public;
create temp table ids (k text primary key, v uuid);
grant all on ids to public;
create function pg_temp.gid(p_k text) returns uuid language sql stable as $$ select v from ids where k = p_k $$;
grant execute on function pg_temp.gid(text) to public;

-- ===========================================================================
-- 1. The push endpoint allowlist
-- ===========================================================================
create temp table ep (n int, url text, expect boolean, note text);
insert into ep values
  (1,  'https://fcm.googleapis.com/fcm/send/abc',                              true,  'Google FCM'),
  (2,  'https://updates.push.services.mozilla.com/wpush/v2/abc',               true,  'Mozilla autopush'),
  (3,  'https://web.push.apple.com/QWERTY',                                    true,  'Apple web push'),
  (4,  'https://api.sandbox.push.apple.com/3/device/abc',                      true,  'Apple, deeper subdomain'),
  (5,  'https://wns2-par02p.notify.windows.com/w/?token=abc',                  true,  'Windows notifications, with a query'),
  (6,  'https://FCM.GoogleAPIs.com/fcm/send/abc',                              true,  'the host is case-insensitive'),
  (7,  'https://fcm.googleapis.com:443/fcm/send/abc',                          true,  'the default port written out'),
  (8,  'http://fcm.googleapis.com/fcm/send/abc',                               false, 'plain http'),
  (9,  'https://fcm.googleapis.com.evil.test/fcm/send/abc',                    false, 'the allowed name as a prefix of another host'),
  (10, 'https://evil.test/fcm.googleapis.com/x',                               false, 'the allowed name in the path'),
  (11, 'https://user@fcm.googleapis.com/x',                                    false, 'userinfo'),
  (12, 'https://fcm.googleapis.com@evil.test/x',                               false, 'userinfo that names an allowed host'),
  (13, 'https://fcm.googleapis.com:8443/x',                                    false, 'another port'),
  (14, 'https://push.example.test/x',                                          false, 'a host that is not a push service'),
  (15, 'https://push.apple.com/x',                                             false, 'the bare apple domain (needs a subdomain)'),
  (16, 'https://notify.windows.com/x',                                         false, 'the bare windows domain'),
  (17, 'https://evilpush.apple.com/x',                                         false, 'a look-alike for push.apple.com'),
  (18, 'https://x.push.apple.com.evil.test/x',                                 false, 'apple as a prefix of another host'),
  (19, 'https://fcm.googleapis.com',                                           false, 'no path'),
  (20, 'https://fcm.googleapis.com/fcm send',                                  false, 'whitespace in the path'),
  (21, 'ftp://fcm.googleapis.com/x',                                           false, 'another scheme'),
  (22, '',                                                                     false, 'empty'),
  (23, 'https://fcm.googleapis.com/' || repeat('a', 1973),                     true,  'exactly 2000 characters'),
  (24, 'https://fcm.googleapis.com/' || repeat('a', 1974),                     false, '2001 characters'),
  (25, 'https://127.0.0.1/x',                                                  false, 'an IP address'),
  (26, 'https://localhost/x',                                                  false, 'localhost');
select is(private.push_endpoint_allowed(e.url), e.expect, 'push_endpoint_allowed: ' || e.note) from ep e order by e.n;
select is(private.push_endpoint_allowed(null), false, 'push_endpoint_allowed: null is not allowed');
select is(private.max_push_subscriptions_per_person(), 10, 'a person keeps at most 10 devices');
select is(pg_temp.f($$insert into public.push_subscriptions (organization_id, person_id, endpoint, p256dh, auth_secret) values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), 'https://push.example.test/x', 'BPmanagermanagermanager1', 'mgrauth1')$$)::text ~ '^23514', true, 'the table CHECK refuses a bad endpoint even for the owner role');
select lives_ok($$insert into public.push_subscriptions (organization_id, person_id, endpoint, p256dh, auth_secret) values (pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), 'https://fcm.googleapis.com/fcm/send/mgr-ok', 'BPmanagermanagermanager1', 'mgrauth1')$$, 'twin: and takes a good one');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.f($$select public.save_push_subscription(pg_temp.id('org_a'), 'http://fcm.googleapis.com/fcm/send/a2', 'BPstaffa2staffa2staffa2xx', 'a2authsecret')$$), '22023 this push service is not supported', 'save_push_subscription: plain http is refused (22023)');
select is(pg_temp.f($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://evil.test/x', 'BPstaffa2staffa2staffa2xx', 'a2authsecret')$$), '22023 this push service is not supported', 'another host is refused (22023)');
select is(pg_temp.f($$select public.save_push_subscription(pg_temp.id('org_a'), null, 'BPstaffa2staffa2staffa2xx', 'a2authsecret')$$), '22023 this push service is not supported', 'a null endpoint is refused (22023)');
select is(pg_temp.f($$select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_staff_a2')$$), '0', 'nothing was saved');
select is(pg_temp.f($$select (public.save_push_subscription(pg_temp.id('org_a'), 'https://fcm.googleapis.com/fcm/send/a2', 'BPstaffa2staffa2staffa2xx', 'a2authsecret', 'Phone')) is not null$$), 'true', 'twin: a good endpoint is saved');
select is(pg_temp.f($$select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_staff_a2')$$), '1', 'and shows as one row');
select pg_temp.act_as('postgres');

-- ---------------------------------------------------------------------------
-- Endpoint ownership: saving an endpoint takes it from any other person, in any organization
-- ---------------------------------------------------------------------------
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.f($$select (public.save_push_subscription(pg_temp.id('org_a'), 'https://fcm.googleapis.com/fcm/send/a2', 'BPmanagermanagermanager1', 'mgrauth1')) is not null$$), 'true', 'manager A1 saves the endpoint staff A2 saved (a shared phone): no error, no information about the other row');
select pg_temp.act_as('postgres');
select is((select array_agg(person_id) from public.push_subscriptions where endpoint = 'https://fcm.googleapis.com/fcm/send/a2'), array[pg_temp.id('p_manager_a1')], 'the endpoint now belongs to manager A1 only');
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_staff_a2')), 0::bigint, 'staff A2 lost that row');
-- another organization: B1's device is taken by staff A1 saving it (the endpoint is a device, whatever organization it was saved for)
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_staff_b1') and endpoint = 'https://fcm.googleapis.com/fcm/send/b'), 1::bigint, 'sanity: staff B1 has the fixture device "b"');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.f($$select (public.save_push_subscription(pg_temp.id('org_a'), 'https://fcm.googleapis.com/fcm/send/b', 'BPstaffa1staffa1staffa1xx', 'a1authsecret')) is not null$$), 'true', 'staff A1 saves the endpoint staff B1 has in organization B');
select pg_temp.act_as('postgres');
select is((select array_agg(person_id) from public.push_subscriptions where endpoint = 'https://fcm.googleapis.com/fcm/send/b'), array[pg_temp.id('p_staff_a1')], 'it now belongs to staff A1 only (one person per endpoint across organizations)');
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_staff_b1')), 0::bigint, 'staff B1 lost it');
-- saving your own endpoint again keeps one row, refreshes the keys and switches a disabled device back on
update public.push_subscriptions set disabled_at = now() where person_id = pg_temp.id('p_staff_a1') and endpoint = 'https://fcm.googleapis.com/fcm/send/b';
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.f($$select (public.save_push_subscription(pg_temp.id('org_a'), 'https://fcm.googleapis.com/fcm/send/b', 'BPstaffa1newkeysnewkeys1', 'a1authsecret2')) is not null$$), 'true', 'staff A1 saves the same endpoint again');
select pg_temp.act_as('postgres');
select results_eq($$select count(*)::int, bool_and(disabled_at is null), max(p256dh) from public.push_subscriptions where person_id = pg_temp.id('p_staff_a1') and endpoint = 'https://fcm.googleapis.com/fcm/send/b'$$,
  $$values (1, true, 'BPstaffa1newkeysnewkeys1'::text)$$, 'still one row, with the new keys, switched on again');

-- ---------------------------------------------------------------------------
-- The 10-device cap: saving an 11th removes the least recently saved
-- ---------------------------------------------------------------------------
delete from public.push_subscriptions where person_id = pg_temp.id('p_locadmin_a1');
insert into public.push_subscriptions (organization_id, person_id, endpoint, p256dh, auth_secret, updated_at)
select pg_temp.id('org_a'), pg_temp.id('p_locadmin_a1'), 'https://fcm.googleapis.com/fcm/send/dev' || g, 'BPdevicedevicedevice' || lpad(g::text, 4, '0'), 'devauth' || g, now() - make_interval(mins => 20 - g)
from generate_series(1, 10) g;
alter table public.push_subscriptions disable trigger user;
update public.push_subscriptions set updated_at = now() - make_interval(mins => 20 - substring(endpoint from 'dev(\d+)$')::int) where person_id = pg_temp.id('p_locadmin_a1');
alter table public.push_subscriptions enable trigger user;
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_locadmin_a1')), 10::bigint, 'sanity: locadmin A1 has 10 devices (dev1 the oldest)');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.f($$select (public.save_push_subscription(pg_temp.id('org_a'), 'https://fcm.googleapis.com/fcm/send/dev3', 'BPdevicedevicedevice0003', 'devauth3')) is not null$$), 'true', 'saving an endpoint they already have (the 3rd) at the cap works');
select pg_temp.act_as('postgres');
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_locadmin_a1')), 10::bigint, 'and removes nobody (it was an update)');
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_locadmin_a1') and endpoint = 'https://fcm.googleapis.com/fcm/send/dev1'), 1::bigint, 'the oldest is still there');
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.f($$select (public.save_push_subscription(pg_temp.id('org_a'), 'https://fcm.googleapis.com/fcm/send/dev11', 'BPdevicedevicedevice0011', 'devauth11')) is not null$$), 'true', 'saving an 11th new endpoint works');
select pg_temp.act_as('postgres');
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_locadmin_a1')), 10::bigint, 'there are still 10');
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_locadmin_a1') and endpoint = 'https://fcm.googleapis.com/fcm/send/dev1'), 0::bigint, 'the oldest (dev1) was replaced');
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_locadmin_a1') and endpoint = 'https://fcm.googleapis.com/fcm/send/dev2'), 1::bigint, 'the second oldest (dev2) is kept (only one was removed)');
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_locadmin_a1') and endpoint = 'https://fcm.googleapis.com/fcm/send/dev11'), 1::bigint, 'and the new one is there');
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_manager_a1')), 2::bigint, 'twin: another person''s devices are not touched by the cap (manager A1 still has hers)');

-- ===========================================================================
-- 2. Notice fan-out only when the notice is live
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
insert into public.notices (id, organization_id, location_id, title, body) values
  (pg_temp.id('nt_draft'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Draft', 'body'),
  (pg_temp.id('nt_sched'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Scheduled', 'body'),
  (pg_temp.id('nt_live'),  pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Live', 'body'),
  (pg_temp.id('nt_exp'),   pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Expired', 'body'),
  (pg_temp.id('nt_arch'),  pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Archived', 'body');
insert into public.notice_audiences (organization_id, notice_id, location_id)
select pg_temp.id('org_a'), pg_temp.id(k), pg_temp.id('loc_a1') from (values ('nt_draft'), ('nt_sched'), ('nt_live'), ('nt_exp'), ('nt_arch')) v (k);
select public.publish_notice(pg_temp.id('nt_sched'), now() + interval '1 hour');
select public.publish_notice(pg_temp.id('nt_live'));
select public.publish_notice(pg_temp.id('nt_exp'));
select public.publish_notice(pg_temp.id('nt_arch'));
select pg_temp.act_as('postgres');
update public.notices set publish_at = now() - interval '2 hours', published_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' where id = pg_temp.id('nt_exp');
update public.notices set status = 'archived', archived_at = now() where id = pg_temp.id('nt_arch');
select pg_temp.act_as('service_role');
select is((select count(*) from public.notice_audience_person_ids(pg_temp.id('nt_draft'))), 0::bigint, 'fan-out: a draft has no audience');
select is((select count(*) from public.notice_audience_person_ids(pg_temp.id('nt_sched'))), 0::bigint, 'fan-out: a scheduled notice (not live yet) has none');
select is((select count(*) from public.notice_audience_person_ids(pg_temp.id('nt_exp'))), 0::bigint, 'fan-out: an expired notice has none');
select is((select count(*) from public.notice_audience_person_ids(pg_temp.id('nt_arch'))), 0::bigint, 'fan-out: an archived notice has none');
select is((select count(*) from public.notice_audience_person_ids(gen_random_uuid())), 0::bigint, 'fan-out: an unknown notice has none');
select is((select count(*) from public.notice_audience_person_ids(pg_temp.id('nt_live'))), 4::bigint, 'twin: a live notice reaches its audience (org admin, A1 admin, manager A1, staff A1)');
select pg_temp.act_as('postgres');
update public.notices set expires_at = now() + interval '1 day' where id = pg_temp.id('nt_exp');
select pg_temp.act_as('service_role');
select is((select count(*) from public.notice_audience_person_ids(pg_temp.id('nt_exp'))), 4::bigint, 'twin: the same notice with its expiry in the future is live again');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.f($$select count(*) from public.notice_audience_person_ids(pg_temp.id('nt_live'))$$)::text ~ '^(42501|0)', true, 'a signed-in user gets no audience list (the function is for the server)');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 3. create_notifications
-- ===========================================================================
insert into ids select 'ev_t1', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}');
insert into ids select 'ev_t2', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{"urgency":"high"}');
select pg_temp.act_as('service_role');
select is(public.create_notifications(pg_temp.gid('ev_t1'), array[pg_temp.id('p_staff_a1'), pg_temp.id('p_staff_a2'), pg_temp.id('p_manager_a1')], 'task.created', 'New task', 'Sweep the floor', '/app/tasks/1'), 3, 'create_notifications: three active people, three notifications');
select pg_temp.act_as('postgres');
select is((select count(*) from public.notifications where source_event_id = pg_temp.gid('ev_t1')), 3::bigint, 'three notification rows');
select is((select count(*) from public.notification_deliveries d join public.notifications n on n.id = d.notification_id where n.source_event_id = pg_temp.gid('ev_t1')), 9::bigint, 'with one delivery per channel each (in app, email, push)');
select is((select count(*) from public.notifications where source_event_id = pg_temp.gid('ev_t1') and title = 'New task' and body = 'Sweep the floor' and link_path = '/app/tasks/1' and urgency = 'normal'), 3::bigint, 'each carries the title, text, link and the default urgency');
select pg_temp.act_as('service_role');
select is(public.create_notifications(pg_temp.gid('ev_t1'), array[pg_temp.id('p_staff_a1'), pg_temp.id('p_staff_a2'), pg_temp.id('p_manager_a1')], 'task.created', 'New task', 'Sweep the floor', '/app/tasks/1'), 3, 'run again: it reports the same three');
select pg_temp.act_as('postgres');
select is((select count(*) from public.notifications where source_event_id = pg_temp.gid('ev_t1')), 3::bigint, 'and nothing was added (idempotent on event, person and kind)');
select pg_temp.act_as('service_role');
select is(public.create_notifications(pg_temp.gid('ev_t1'), array[pg_temp.id('p_staff_a1'), pg_temp.id('p_staff_a1'), null, pg_temp.id('p_locadmin_a1')], 'task.created', 'New task'), 2, 'duplicates and nulls in the list count once; a new person is added (staff A1 was already there)');
select is(public.create_notifications(pg_temp.gid('ev_t1'), array[pg_temp.id('p_staff_a1')], 'task.reminder', 'Reminder'), 1, 'a different kind for the same person and event is a new notification');
select is(public.create_notifications(pg_temp.gid('ev_t2'), array[pg_temp.id('p_staff_a1')], 'task.created', 'High', null, null), 1, 'the urgency comes from the event payload when not given');
select pg_temp.act_as('postgres');
select is((select urgency from public.notifications where source_event_id = pg_temp.gid('ev_t2')), 'high', 'it is "high"');
select pg_temp.act_as('service_role');
select is(public.create_notifications(pg_temp.gid('ev_t2'), array[pg_temp.id('p_staff_a2')], 'task.created', 'Crit', null, null, 'critical'), 1, 'an explicit urgency wins');
select is(public.create_notifications(pg_temp.gid('ev_t2'), array[pg_temp.id('p_disabled_a'), pg_temp.id('p_unassigned_a'), pg_temp.id('p_staff_b1'), gen_random_uuid()], 'task.created', 'Skip'), 0, 'people with a disabled account, no assignment, in another organization or unknown get nothing (and no error)');
select is(pg_temp.f($$select public.create_notifications(gen_random_uuid(), array[pg_temp.id('p_staff_a1')], 'x.y', 'T')$$), '22023 no such event', 'an unknown event is refused (22023)');
select is(pg_temp.f($$select public.create_notifications(null, array[pg_temp.id('p_staff_a1')], 'x.y', 'T')$$)::text ~ '^22023', true, 'a null event is refused');
select is(pg_temp.f($$select public.create_notifications(pg_temp.gid('ev_t1'), null, 'x.y', 'T')$$), '22023 give 1 to 10000 people', 'a null list is refused (22023)');
select is(pg_temp.f(format('select public.create_notifications(%L, (select array_agg(gen_random_uuid()) from generate_series(1, 10001)), %L, %L)', pg_temp.gid('ev_t1'), 'x.y', 'T')), '22023 give 1 to 10000 people', '10001 people are refused (22023)');
select is(pg_temp.f(format('select public.create_notifications(%L, (select array_agg(gen_random_uuid()) from generate_series(1, 10000)), %L, %L)', pg_temp.gid('ev_t1'), 'x.y', 'T')), '0', 'twin: 10000 is accepted (none of those people exist, so none are notified)');
select is(pg_temp.f($$select public.create_notifications(pg_temp.gid('ev_t1'), '{}', 'x.y', 'T')$$), '0', 'an empty list does nothing and reports 0');
select pg_temp.act_as_service('u_manager_a1');
select is(pg_temp.f($$select public.create_notifications(pg_temp.gid('ev_t1'), array[pg_temp.id('p_staff_a1')], 'x.y', 'T')$$), '42501 not allowed', 'a service JWT carrying a user (sub) is refused (42501)');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.f($$select public.create_notifications(pg_temp.gid('ev_t1'), array[pg_temp.id('p_staff_a1')], 'x.y', 'T')$$)::text ~ '^42501', true, 'a signed-in user cannot call it');
select pg_temp.act_as('anon');
select is(pg_temp.f($$select public.create_notifications(pg_temp.gid('ev_t1'), array[pg_temp.id('p_staff_a1')], 'x.y', 'T')$$)::text ~ '^42501', true, 'anon cannot either');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 4. The worker read functions
-- ===========================================================================
-- fixtures: a task, a notice, a message and deliveries
select pg_temp.act_as('u_manager_a1');
insert into ids select 'task1', public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Worker task', 'private instructions', null, 'high', null, pg_temp.id('p_staff_a1'), null);
select pg_temp.act_as('postgres');
insert into ids select 'ev_task', id from public.outbox_events where type = 'task.created' and entity_id = pg_temp.gid('task1');
insert into ids select 'ev_notice', id from public.outbox_events where type = 'notice.published' and entity_id = pg_temp.id('nt_live');
insert into ids select 'ev_task_b', private.emit_event(pg_temp.id('org_b'), null, 'task.created', 'tasks', pg_temp.gid('task1'), '{}');
insert into ids select 'ev_notice_b', private.emit_event(pg_temp.id('org_b'), null, 'notice.published', 'notices', pg_temp.id('nt_live'), '{}');
insert into ids select 'ev_wrong_table', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'notices', pg_temp.gid('task1'), '{}');
select pg_temp.act_as('service_role');
select results_eq($$select task_id, organization_id, location_id, location_name, title, status, priority, assigned_person_id from public.worker_task_for_event(pg_temp.gid('ev_task'))$$,
  $$values (pg_temp.gid('task1'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'A1 Arena'::text, 'Worker task'::text, 'open'::text, 'high'::text, pg_temp.id('p_staff_a1'))$$, 'worker_task_for_event: the task of the event with its location name');
select is((select count(*) from public.worker_task_for_event(pg_temp.gid('ev_task_b'))), 0::bigint, 'worker_task_for_event: a forged event of another organization naming that task returns nothing');
select is((select count(*) from public.worker_task_for_event(pg_temp.gid('ev_wrong_table'))), 0::bigint, 'an event whose entity is not a task returns nothing');
select is((select count(*) from public.worker_task_for_event(gen_random_uuid())), 0::bigint, 'an unknown event returns nothing');
select is((select count(*) from public.worker_task_for_event(null)), 0::bigint, 'null returns nothing');
select ok(pg_get_function_result('public.worker_task_for_event(uuid)'::regprocedure) not like '%instructions%', 'worker_task_for_event returns no instructions');
select ok(pg_get_function_result('public.worker_notice_for_event(uuid)'::regprocedure) not like '%body%', 'worker_notice_for_event returns no body');
select results_eq($$select notice_id, organization_id, title, status, urgency, requires_acknowledgment from public.worker_notice_for_event(pg_temp.gid('ev_notice'))$$,
  $$values (pg_temp.id('nt_live'), pg_temp.id('org_a'), 'Live'::text, 'published'::text, 'normal'::text, false)$$, 'worker_notice_for_event: the notice of the event (no body)');
select is((select count(*) from public.worker_notice_for_event(pg_temp.gid('ev_notice_b'))), 0::bigint, 'worker_notice_for_event: a forged event of another organization returns nothing');
select is((select count(*) from public.worker_notice_for_event(pg_temp.gid('ev_task'))), 0::bigint, 'an event about a task returns no notice');
select is((select count(*) from public.worker_notice_for_event(gen_random_uuid())), 0::bigint, 'an unknown event returns nothing');
select pg_temp.act_as('postgres');
-- notification deliveries for worker_notification / email / push
insert into ids select 'ev_n', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}');
select pg_temp.act_as('service_role');
select is(public.create_notifications(pg_temp.gid('ev_n'), array[pg_temp.id('p_staff_a1'), pg_temp.id('p_staff_a2')], 'task.created', 'Hello', 'Body text', '/app/x'), 2, 'two notifications for the delivery tests');
select pg_temp.act_as('postgres');
insert into ids select 'dl_a1_email', d.id from public.notification_deliveries d join public.notifications n on n.id = d.notification_id where n.source_event_id = pg_temp.gid('ev_n') and n.person_id = pg_temp.id('p_staff_a1') and d.channel = 'email';
insert into ids select 'dl_a1_push', d.id from public.notification_deliveries d join public.notifications n on n.id = d.notification_id where n.source_event_id = pg_temp.gid('ev_n') and n.person_id = pg_temp.id('p_staff_a1') and d.channel = 'push';
insert into ids select 'dl_a1_app', d.id from public.notification_deliveries d join public.notifications n on n.id = d.notification_id where n.source_event_id = pg_temp.gid('ev_n') and n.person_id = pg_temp.id('p_staff_a1') and d.channel = 'in_app';
insert into ids select 'dl_a2_email', d.id from public.notification_deliveries d join public.notifications n on n.id = d.notification_id where n.source_event_id = pg_temp.gid('ev_n') and n.person_id = pg_temp.id('p_staff_a2') and d.channel = 'email';
insert into ids select 'dl_a2_push', d.id from public.notification_deliveries d join public.notifications n on n.id = d.notification_id where n.source_event_id = pg_temp.gid('ev_n') and n.person_id = pg_temp.id('p_staff_a2') and d.channel = 'push';
select pg_temp.act_as('service_role');
select results_eq($$select organization_id, person_id, channel, kind, title, body, link_path from public.worker_notification_for_delivery(pg_temp.gid('dl_a1_email'))$$,
  $$values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'email'::text, 'task.created'::text, 'Hello'::text, 'Body text'::text, '/app/x'::text)$$, 'worker_notification_for_delivery: the delivery with its notification');
select is((select count(*) from public.worker_notification_for_delivery(gen_random_uuid())), 0::bigint, 'an unknown delivery returns nothing');
select pg_temp.act_as('postgres');

-- email: only a confirmed, active, current login
select pg_temp.act_as('service_role');
select is(public.worker_email_for_delivery(pg_temp.gid('dl_a2_email')), null, 'worker_email_for_delivery: an address that was never confirmed gives null');
select pg_temp.act_as('postgres');
update auth.users set email_confirmed_at = now() where id in (pg_temp.id('u_staff_a1'), pg_temp.id('u_staff_a2'));
select pg_temp.act_as('service_role');
select is(public.worker_email_for_delivery(pg_temp.gid('dl_a2_email')), 'staff-a2@test.invalid', 'a confirmed login: the address from auth.users');
select is(public.worker_email_for_delivery(pg_temp.gid('dl_a2_push')), null, 'a push delivery has no email');
select is(public.worker_email_for_delivery(pg_temp.gid('dl_a1_app')), null, 'an in-app delivery has no email');
select is(public.worker_email_for_delivery(gen_random_uuid()), null, 'an unknown delivery has none');
select pg_temp.act_as('postgres');
update auth.users set banned_until = now() + interval '1 day' where id = pg_temp.id('u_staff_a2');
select pg_temp.act_as('service_role');
select is(public.worker_email_for_delivery(pg_temp.gid('dl_a2_email')), null, 'banned until tomorrow: null');
select pg_temp.act_as('postgres');
update auth.users set banned_until = now() - interval '1 minute' where id = pg_temp.id('u_staff_a2');
select pg_temp.act_as('service_role');
select is(public.worker_email_for_delivery(pg_temp.gid('dl_a2_email')), 'staff-a2@test.invalid', 'twin: the ban has expired: the address again');
select pg_temp.act_as('postgres');
update auth.users set banned_until = null, deleted_at = now() where id = pg_temp.id('u_staff_a2');
select pg_temp.act_as('service_role');
select is(public.worker_email_for_delivery(pg_temp.gid('dl_a2_email')), null, 'deleted: null');
select pg_temp.act_as('postgres');
update auth.users set deleted_at = null where id = pg_temp.id('u_staff_a2');
update public.accounts set disabled_at = now() where id = pg_temp.id('acct_staff_a2');
select pg_temp.act_as('service_role');
select is(public.worker_email_for_delivery(pg_temp.gid('dl_a2_email')), null, 'a disabled account: null');
select pg_temp.act_as('postgres');
update public.accounts set disabled_at = null where id = pg_temp.id('acct_staff_a2');
update public.people set archived_at = now() where id = pg_temp.id('p_staff_a2');
select pg_temp.act_as('service_role');
select is(public.worker_email_for_delivery(pg_temp.gid('dl_a2_email')), null, 'an archived person: null');
select pg_temp.act_as('postgres');
update public.people set archived_at = null where id = pg_temp.id('p_staff_a2');
update public.people set email = 'other-address@test.invalid' where id = pg_temp.id('p_staff_a2');
select pg_temp.act_as('service_role');
select is(public.worker_email_for_delivery(pg_temp.gid('dl_a2_email')), 'staff-a2@test.invalid', 'twin: all restored: the login address, never the address typed on the person (people.email)');
select pg_temp.act_as('postgres');

-- push subscriptions of a delivery
select pg_temp.act_as('service_role');
select is((select count(*) from public.worker_push_subscriptions_for_delivery(pg_temp.gid('dl_a1_push'))), 2::bigint, 'worker_push_subscriptions_for_delivery: staff A1''s two active devices');
select is((select count(*) from public.worker_push_subscriptions_for_delivery(pg_temp.gid('dl_a1_email'))), 0::bigint, 'an email delivery has no devices');
select is((select count(*) from public.worker_push_subscriptions_for_delivery(pg_temp.gid('dl_a2_push'))), 0::bigint, 'a person with no device has none');
select is((select count(*) from public.worker_push_subscriptions_for_delivery(gen_random_uuid())), 0::bigint, 'an unknown delivery has none');
select ok(pg_get_function_result('public.worker_push_subscriptions_for_delivery(uuid)'::regprocedure) not like '%user_agent%', 'worker_push_subscriptions_for_delivery returns no user agent');
select pg_temp.act_as('postgres');
update public.push_subscriptions set disabled_at = now() where person_id = pg_temp.id('p_staff_a1') and endpoint = 'https://fcm.googleapis.com/fcm/send/b';
select pg_temp.act_as('service_role');
select is((select count(*) from public.worker_push_subscriptions_for_delivery(pg_temp.gid('dl_a1_push'))), 1::bigint, 'a disabled device is not returned');
select pg_temp.act_as('postgres');

-- every worker function refuses a service JWT with a user, a user, and anon
create temp table wf (n int, call text, label text);
insert into wf values
  (1, $$select count(*) from public.worker_task_for_event(pg_temp.gid('ev_task'))$$, 'worker_task_for_event'),
  (2, $$select count(*) from public.worker_notice_for_event(pg_temp.gid('ev_notice'))$$, 'worker_notice_for_event'),
  (3, $$select count(*) from public.worker_notification_for_delivery(pg_temp.gid('dl_a1_email'))$$, 'worker_notification_for_delivery'),
  (4, $$select public.worker_email_for_delivery(pg_temp.gid('dl_a2_email'))$$, 'worker_email_for_delivery'),
  (5, $$select count(*) from public.worker_push_subscriptions_for_delivery(pg_temp.gid('dl_a1_push'))$$, 'worker_push_subscriptions_for_delivery'),
  (6, $$select count(*) from public.worker_message_recipients_for_event(pg_temp.gid('ev_task'))$$, 'worker_message_recipients_for_event');
grant all on wf to public;
create temp table wf_got (n int, svc text, usr text, anon text, jwt_sub text);
grant all on wf_got to public;
do $$
declare r record; a text; b text; c text; d text;
begin
  for r in select * from wf order by n loop
    perform pg_temp.act_as('service_role');
    a := pg_temp.f(r.call);
    perform pg_temp.act_as_service('u_manager_a1');
    d := pg_temp.f(r.call);
    perform pg_temp.act_as('u_orgadmin_a');
    b := pg_temp.f(r.call);
    perform pg_temp.act_as('anon');
    c := pg_temp.f(r.call);
    insert into wf_got values (r.n, a, b, c, d);
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select jwt_sub from wf_got g where g.n = w.n), '42501 not allowed', w.label || ': a service connection that carries a user (sub) is refused (42501)') from wf w order by w.n;
select ok(((select usr from wf_got g where g.n = w.n)) like '42501%', w.label || ': a signed-in org admin cannot call it') from wf w order by w.n;
select ok(((select anon from wf_got g where g.n = w.n)) like '42501%', w.label || ': anon cannot call it') from wf w order by w.n;
select ok(not ((select svc from wf_got g where g.n = w.n)) like '42501%', w.label || ' (twin): the server key itself can call it') from wf w order by w.n;

-- ---------------------------------------------------------------------------
-- worker_message_recipients_for_event (000700 M1)
-- ---------------------------------------------------------------------------
select pg_temp.act_as('u_orgadmin_a');
insert into ids select 'msg1', public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_staff_a1'), pg_temp.id('p_locadmin_a1'), pg_temp.id('p_manager_a1')], 'MSG-WORKER-SECRET-TEXT');
select pg_temp.act_as('postgres');
insert into ids select 'ev_msg', id from public.outbox_events where type = 'message.sent' and entity_id = pg_temp.gid('msg1');
-- extra recipients the sender cannot add through send_message: the sender itself, a disabled account, a person with no assignment
insert into public.message_recipients (organization_id, message_id, person_id) values
  (pg_temp.id('org_a'), pg_temp.gid('msg1'), pg_temp.id('p_orgadmin_a')),
  (pg_temp.id('org_a'), pg_temp.gid('msg1'), pg_temp.id('p_disabled_a')),
  (pg_temp.id('org_a'), pg_temp.gid('msg1'), pg_temp.id('p_unassigned_a')),
  (pg_temp.id('org_a'), pg_temp.gid('msg1'), pg_temp.id('p_staff_a2'));
update public.people set archived_at = now() where id = pg_temp.id('p_staff_a2');
select pg_temp.act_as('service_role');
select is((select array_agg(person_id order by person_id) from public.worker_message_recipients_for_event(pg_temp.gid('ev_msg'))),
          (select array_agg(p order by p) from unnest(array[pg_temp.id('p_staff_a1'), pg_temp.id('p_locadmin_a1'), pg_temp.id('p_manager_a1')]) p),
  'worker_message_recipients_for_event: only the active recipients (not the sender, the disabled account, the person with no assignment or the archived person)');
select results_eq($$select distinct organization_id, message_id, link_path from public.worker_message_recipients_for_event(pg_temp.gid('ev_msg'))$$,
  $$values (pg_temp.id('org_a'), pg_temp.gid('msg1'), '/app/messages/' || pg_temp.gid('msg1')::text)$$, 'every row carries the organization, the message id and a link');
select is((select array_agg(a.attname::text order by a.attnum) from pg_proc p, lateral unnest(p.proargnames, p.proargmodes) with ordinality as a (attname, mode, attnum) where p.proname = 'worker_message_recipients_for_event' and a.mode = 't'),
          array['organization_id', 'message_id', 'person_id', 'link_path'], 'it returns exactly organization_id, message_id, person_id, link_path: no body, sender or read state');
select is((select count(*) from public.worker_message_recipients_for_event(pg_temp.gid('ev_msg')) r where r::text like '%MSG-WORKER-SECRET-TEXT%'), 0::bigint, 'and the message text appears nowhere in the rows');
select pg_temp.act_as('postgres');
update public.message_recipients set read_at = now() where message_id = pg_temp.gid('msg1') and person_id = pg_temp.id('p_staff_a1');
select pg_temp.act_as('service_role');
select is((select count(*) from public.worker_message_recipients_for_event(pg_temp.gid('ev_msg'))), 3::bigint, 'twin: a recipient who has already read it is still returned (the read state is not an input)');
-- other events
select pg_temp.act_as('postgres');
insert into ids select 'ev_msg_b', private.emit_event(pg_temp.id('org_b'), null, 'message.sent', 'messages', pg_temp.gid('msg1'), jsonb_build_object('message_id', pg_temp.gid('msg1')));
insert into ids select 'ev_msg_wrongtype', private.emit_event(pg_temp.id('org_a'), null, 'message.deleted', 'messages', pg_temp.gid('msg1'), '{}');
insert into ids select 'ev_msg_wrongtable', private.emit_event(pg_temp.id('org_a'), null, 'message.sent', 'tasks', pg_temp.gid('msg1'), '{}');
select pg_temp.act_as('service_role');
select is((select count(*) from public.worker_message_recipients_for_event(pg_temp.gid('ev_msg_b'))), 0::bigint, 'a forged message.sent event of another organization returns nothing');
select is((select count(*) from public.worker_message_recipients_for_event(pg_temp.gid('ev_msg_wrongtype'))), 0::bigint, 'an event that is not message.sent returns nothing');
select is((select count(*) from public.worker_message_recipients_for_event(pg_temp.gid('ev_msg_wrongtable'))), 0::bigint, 'a message.sent event about something that is not a message returns nothing');
select is((select count(*) from public.worker_message_recipients_for_event(pg_temp.gid('ev_task'))), 0::bigint, 'a task event returns nothing');
select is((select count(*) from public.worker_message_recipients_for_event(gen_random_uuid())), 0::bigint, 'an unknown event returns nothing');
select is((select count(*) from public.worker_message_recipients_for_event(null)), 0::bigint, 'null returns nothing');
select pg_temp.act_as('postgres');
-- a recipient who loses their assignment or account is not returned
update public.accounts set disabled_at = now() where id = pg_temp.id('acct_locadmin_a1');
delete from public.role_assignments where id = pg_temp.id('ra_manager_a1');
select pg_temp.act_as('service_role');
select is((select array_agg(person_id) from public.worker_message_recipients_for_event(pg_temp.gid('ev_msg'))), array[pg_temp.id('p_staff_a1')], 'with the A1 admin''s account disabled and the manager''s assignment removed only staff A1 is left');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 5. Release and extend: holder only
-- ===========================================================================
insert into ids select 'ev_l1', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'task.created', 'tasks', gen_random_uuid(), '{}');
update public.outbox_events set status = 'done', processed_at = now() where id <> pg_temp.gid('ev_l1') and status = 'pending';
update public.outbox_events set next_attempt_at = now() where id = pg_temp.gid('ev_l1');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('holder-1', 500, 60) where id = pg_temp.gid('ev_l1')), 1::bigint, 'holder-1 claims the event');
select is(public.release_outbox_event(pg_temp.gid('ev_l1'), 'other-worker'), false, 'release: someone else cannot give it back');
select is(public.extend_outbox_lock(pg_temp.gid('ev_l1'), 'other-worker', 120), false, 'extend: someone else cannot extend it');
select is(pg_temp.f($$select public.extend_outbox_lock(pg_temp.gid('ev_l1'), 'holder-1', 4)$$), '22023 invalid lock time', 'extend: 4 seconds is refused (5 to 3600)');
select is(pg_temp.f($$select public.extend_outbox_lock(pg_temp.gid('ev_l1'), 'holder-1', 3601)$$), '22023 invalid lock time', 'extend: 3601 seconds is refused');
select is(pg_temp.f($$select public.extend_outbox_lock(pg_temp.gid('ev_l1'), 'holder-1', null)$$), '22023 invalid lock time', 'extend: null seconds is refused');
select pg_temp.act_as('postgres');
select results_eq($$select status, locked_by, attempts from public.outbox_events where id = pg_temp.gid('ev_l1')$$, $$values ('processing'::text, 'holder-1'::text, 1)$$, 'sanity: still held by holder-1, one attempt used');
select pg_temp.act_as('service_role');
select is(public.extend_outbox_lock(pg_temp.gid('ev_l1'), ' holder-1 ', 3600), true, 'extend: the holder can (the name is trimmed)');
select pg_temp.act_as('postgres');
select cmp_ok((select lock_expires_at from public.outbox_events where id = pg_temp.gid('ev_l1')), '>', now() + interval '59 minutes', 'the lock now runs for about an hour');
update public.outbox_events set lock_expires_at = now() - interval '1 second' where id = pg_temp.gid('ev_l1');
select pg_temp.act_as('service_role');
select is(public.extend_outbox_lock(pg_temp.gid('ev_l1'), 'holder-1', 60), false, 'extend: after the lock has expired even the holder cannot (another worker may hold it)');
select is(public.release_outbox_event(pg_temp.gid('ev_l1'), 'holder-1'), true, 'release: the holder can give it back (an expired lock is still theirs until reclaimed)');
select pg_temp.act_as('postgres');
select results_eq($$select status, locked_by, attempts from public.outbox_events where id = pg_temp.gid('ev_l1')$$, $$values ('pending'::text, null::text, 0)$$, 'it is pending again, unlocked, with the attempt given back');
select pg_temp.act_as('service_role');
select is(public.release_outbox_event(pg_temp.gid('ev_l1'), 'holder-1'), false, 'releasing it again does nothing (it is not held)');
select is(public.extend_outbox_lock(pg_temp.gid('ev_l1'), 'holder-1', 60), false, 'extending it does nothing either');
select is(public.release_outbox_event(gen_random_uuid(), 'holder-1'), false, 'an unknown event: false');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('holder-2', 500, 60) where id = pg_temp.gid('ev_l1')), 1::bigint, 'twin: another worker can claim it now');
select is(public.release_outbox_event(pg_temp.gid('ev_l1'), 'holder-1'), false, 'and the first holder can no longer release it');
select is(public.extend_outbox_lock(pg_temp.gid('ev_l1'), 'holder-2', 30), true, 'while the new holder can extend');
select pg_temp.act_as('u_manager_a1');
select ok(pg_temp.f($$select public.release_outbox_event(pg_temp.gid('ev_l1'), 'holder-2')$$) like '42501%', 'a signed-in user cannot release');
select ok(pg_temp.f($$select public.extend_outbox_lock(pg_temp.gid('ev_l1'), 'holder-2', 30)$$) like '42501%', 'a signed-in user cannot extend');
select pg_temp.act_as_service('u_manager_a1');
select is(pg_temp.f($$select public.release_outbox_event(pg_temp.gid('ev_l1'), 'holder-2')$$), '42501 not allowed', 'a service connection carrying a user is refused on release');
select is(pg_temp.f($$select public.extend_outbox_lock(pg_temp.gid('ev_l1'), 'holder-2', 30)$$), '42501 not allowed', 'and on extend');
select pg_temp.act_as('postgres');
-- deliveries
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_notification_deliveries('dw-1', 500, 60) where id = pg_temp.gid('dl_a2_email')), 1::bigint, 'dw-1 claims a delivery');
select is(public.release_notification_delivery(pg_temp.gid('dl_a2_email'), 'dw-other'), false, 'release_notification_delivery: someone else cannot give it back');
select pg_temp.act_as('postgres');
select results_eq($$select locked_by, attempts from public.notification_deliveries where id = pg_temp.gid('dl_a2_email')$$, $$values ('dw-1'::text, 1)$$, 'sanity: still held, one attempt used');
select pg_temp.act_as('service_role');
select is(public.release_notification_delivery(pg_temp.gid('dl_a2_email'), 'dw-1'), true, 'the holder can');
select pg_temp.act_as('postgres');
select results_eq($$select locked_by, attempts, status from public.notification_deliveries where id = pg_temp.gid('dl_a2_email')$$, $$values (null::text, 0, 'pending'::text)$$, 'it is unlocked, pending, with the attempt given back');
select pg_temp.act_as('service_role');
select is(public.release_notification_delivery(pg_temp.gid('dl_a2_email'), 'dw-1'), false, 'again: nothing to release');
select is(public.release_notification_delivery(pg_temp.gid('dl_a1_app'), 'dw-1'), false, 'a delivery that is already sent cannot be released');
select pg_temp.act_as_service('u_manager_a1');
select is(pg_temp.f($$select public.release_notification_delivery(pg_temp.gid('dl_a2_email'), 'dw-1')$$), '42501 not allowed', 'a service connection carrying a user is refused');
select pg_temp.act_as('postgres');

select * from finish();
rollback;
