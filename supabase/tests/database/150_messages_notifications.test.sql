-- Phase 2 / messages, notifications, push subscriptions, preferences. Privacy is the point: messages, recipients,
-- notifications, deliveries, push subscriptions and preferences are private to the people they belong to, and neither an
-- organization admin nor a platform admin can read them. send_message refuses uniformly (it never says which recipient),
-- create_notification is idempotent, critical overrides a muted channel, push endpoints and keys cannot be read through the
-- API roles, and the delivery worker functions enforce claim ownership. Every deny has an allowed twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(430);

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
-- rows visible to the current role in public.<table>; -1 when the role may not read it at all
create function pg_temp.seen(p_table text) returns bigint language plpgsql as $$
declare n bigint;
begin
  execute 'select count(*) from public.' || p_table into n;
  return n;
exception when others then return -1;
end $$;
grant execute on function pg_temp.seen(text) to public;

-- events (as the owner), looked up by name
create temp table evs (name text primary key, id uuid not null);
grant all on evs to public;
create function pg_temp.mkev(p_name text, p_org text default 'org_a', p_payload jsonb default '{}') returns void language plpgsql as $$
begin
  insert into evs values (p_name, private.emit_event(pg_temp.id(p_org), null, 'task.created', 'tasks', gen_random_uuid(), p_payload));
end $$;
create function pg_temp.ev(p_name text) returns uuid language sql stable as $$ select id from evs where name = p_name $$;
grant execute on function pg_temp.mkev(text, text, jsonb), pg_temp.ev(text) to public;

-- people used here: staff A1b (a second A1 staff member), who gets archived in one test
insert into auth.users (id, email) values (pg_temp.id('u_staff_a1b'), 'staff-a1b@test.invalid');
insert into public.people (id, organization_id, first_name, last_name) values (pg_temp.id('p_staff_a1b'), pg_temp.id('org_a'), 'Sid', 'StaffA1b');
insert into public.accounts (id, organization_id, person_id, user_id) values (pg_temp.id('acct_staff_a1b'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.id('u_staff_a1b'));
insert into public.role_assignments (organization_id, person_id, role_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1b'), pg_temp.sys_role('staff'), pg_temp.id('loc_a1'));

-- ===========================================================================
-- 0. Set-up of private rows: devices and preferences (as the owner), notifications through the worker function
-- ===========================================================================
insert into public.push_subscriptions (id, organization_id, person_id, endpoint, p256dh, auth_secret, user_agent) values
  (pg_temp.id('ps_s'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'),   'https://push.example.test/SECRET-ENDPOINT-S', 'BPsecretsecretsecretsecretS', 'SECRETAUTHs', 'UA-S'),
  (pg_temp.id('ps_m'), pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), 'https://push.example.test/SECRET-ENDPOINT-M', 'BPsecretsecretsecretsecretM', 'SECRETAUTHm', 'UA-M'),
  (pg_temp.id('ps_b'), pg_temp.id('org_b'), pg_temp.id('p_staff_b1'),   'https://push.example.test/SECRET-ENDPOINT-B', 'BPsecretsecretsecretsecretB', 'SECRETAUTHb', 'UA-B');
insert into public.notification_preferences (id, organization_id, person_id, channel, enabled) values
  (pg_temp.id('pref_s'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'),   'email', false),
  (pg_temp.id('pref_m'), pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), 'push',  false),
  (pg_temp.id('pref_b'), pg_temp.id('org_b'), pg_temp.id('p_staff_b1'),   'email', false);
select pg_temp.mkev('e_s');
select pg_temp.mkev('e_m');
select pg_temp.mkev('e_b', 'org_b');
select pg_temp.act_as('service_role');
select is(public.create_notification(pg_temp.ev('e_s'), pg_temp.id('p_staff_a1'),   'task.assigned', 'Title S', 'Body S', '/tasks/s') is not null, true, 'the worker creates the notification for staff A1');
select is(public.create_notification(pg_temp.ev('e_m'), pg_temp.id('p_manager_a1'), 'task.assigned', 'Title M', 'Body M', '/tasks/m') is not null, true, 'the worker creates the notification for manager A1');
select is(public.create_notification(pg_temp.ev('e_b'), pg_temp.id('p_staff_b1'),   'task.assigned', 'Title B', 'Body B', '/tasks/b') is not null, true, 'the worker creates the notification for staff B1 (org B)');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_manager_a1')], 'LIT-MSG-1 private words')$$), 'ok', 'staff A1 sends a message to manager A1');
select pg_temp.act_as('postgres');
insert into public.messages (id, organization_id, sender_person_id, body) values (pg_temp.id('m_b'), pg_temp.id('org_b'), pg_temp.id('p_staff_b1'), 'LIT-MSG-B private words');
insert into public.message_recipients (organization_id, message_id, person_id) values (pg_temp.id('org_b'), pg_temp.id('m_b'), pg_temp.id('p_orgadmin_b'));

-- ===========================================================================
-- 1. Privacy: who can read what. Own rows only. No admin, org admin, platform admin or aal1 shortcut.
-- ===========================================================================
create temp table readers (n int, who text, aal text, note text, notifs bigint, delivs bigint, pushes bigint, prefs bigint, msgs bigint, rcpts bigint);
insert into readers values
  (1,  'u_staff_a1',     'aal2', 'staff A1 (the sender, and owner of a notification, device and preference)', 1, 3, 1, 1, 1, 1),
  (2,  'u_manager_a1',   'aal2', 'manager A1 (the recipient, and owner of their own rows)',                    1, 3, 1, 1, 1, 1),
  (3,  'u_staff_a2',     'aal2', 'staff A2 (nothing is theirs)',                                               0, 0, 0, 0, 0, 0),
  (4,  'u_locadmin_a1',  'aal2', 'location admin A1',                                                          0, 0, 0, 0, 0, 0),
  (5,  'u_orgadmin_a',   'aal2', 'org admin A',                                                                0, 0, 0, 0, 0, 0),
  (6,  'u_orgadmin_a',   'aal1', 'org admin A at aal1',                                                        0, 0, 0, 0, 0, 0),
  (7,  'u_platform',     'aal2', 'platform admin',                                                             0, 0, 0, 0, 0, 0),
  (8,  'u_platform',     'aal1', 'platform admin at aal1',                                                     0, 0, 0, 0, 0, 0),
  (9,  'u_orgadmin_b',   'aal2', 'org admin B (recipient of the org B message only)',                          0, 0, 0, 0, 1, 1),
  (10, 'u_staff_b1',     'aal2', 'staff B1 (owner of the org B rows, sender of the org B message)',            1, 3, 1, 1, 1, 1),
  (11, 'u_noaccount',    'aal2', 'a user with no account',                                                     0, 0, 0, 0, 0, 0),
  (12, 'u_disabled_a',   'aal2', 'a disabled account',                                                         0, 0, 0, 0, 0, 0),
  (13, 'anon',           'aal2', 'anon (no table privilege)',                                                 -1,-1,-1,-1,-1,-1),
  (14, 'service_role',   'aal2', 'the worker key (reads everything it sends)',                                 3, 9, 3, 3, 2, 2);
grant all on readers to public;
create temp table readers_got (n int, notifs bigint, delivs bigint, pushes bigint, prefs bigint, msgs bigint, rcpts bigint);
grant all on readers_got to public;
do $$
declare r record;
begin
  for r in select * from readers order by n loop
    perform pg_temp.act_as(r.who, r.aal);
    insert into readers_got values (r.n, pg_temp.seen('notifications'), pg_temp.seen('notification_deliveries'), pg_temp.seen('push_subscriptions'),
      pg_temp.seen('notification_preferences'), pg_temp.seen('messages'), pg_temp.seen('message_recipients'));
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select g.notifs from readers_got g where g.n = r.n), r.notifs, 'notifications, ' || r.note) from readers r order by r.n;
select is((select g.delivs from readers_got g where g.n = r.n), r.delivs, 'notification_deliveries, ' || r.note) from readers r order by r.n;
select is((select g.pushes from readers_got g where g.n = r.n), r.pushes, 'push_subscriptions, ' || r.note) from readers r order by r.n;
select is((select g.prefs from readers_got g where g.n = r.n), r.prefs, 'notification_preferences, ' || r.note) from readers r order by r.n;
select is((select g.msgs from readers_got g where g.n = r.n), r.msgs, 'messages, ' || r.note) from readers r order by r.n;
select is((select g.rcpts from readers_got g where g.n = r.n), r.rcpts, 'message_recipients, ' || r.note) from readers r order by r.n;
-- the same, stated plainly for the people the brief names
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.messages) + (select count(*) from public.message_recipients) + (select count(*) from public.notifications)
          + (select count(*) from public.notification_deliveries) + (select count(*) from public.notification_preferences), 0::bigint, 'an org admin reads 0 rows of messages, message_recipients, notifications, deliveries and preferences of their own organization');
select is(pg_temp.val('(select count(*) from public.push_subscriptions)'), '0', 'and 0 push subscriptions');
select pg_temp.act_as('u_platform');
select is((select count(*) from public.messages) + (select count(*) from public.message_recipients) + (select count(*) from public.notifications)
          + (select count(*) from public.notification_deliveries) + (select count(*) from public.notification_preferences) + (select count(*) from public.push_subscriptions), 0::bigint, 'a platform admin (aal2) reads 0 rows of all six private tables, in any organization');
select pg_temp.act_as('postgres');
select is((select count(*) from public.messages), 2::bigint, 'twin: the owner sees both messages');
select is((select count(*) from public.notifications), 3::bigint, 'twin: and the three notifications');

-- column privileges: delivery detail and push secrets are not readable through any API role
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try('select endpoint from public.push_subscriptions'), '42501', 'push endpoint cannot be selected, even by the person who owns the device');
select is(pg_temp.try('select p256dh from public.push_subscriptions'), '42501', 'p256dh cannot be selected');
select is(pg_temp.try('select auth_secret from public.push_subscriptions'), '42501', 'auth_secret cannot be selected');
select is(pg_temp.try('select * from public.push_subscriptions'), '42501', 'select * on push_subscriptions fails (it would include the secrets)');
select is(pg_temp.try('select id, user_agent, last_used_at, disabled_at from public.push_subscriptions'), 'ok', 'twin: the harmless columns can be selected');
select is((select count(*) from public.push_subscriptions where user_agent = 'UA-S'), 1::bigint, 'twin: and the person sees their own device');
select is(pg_temp.try('select provider_message_id from public.notification_deliveries'), '42501', 'delivery provider_message_id cannot be selected');
select is(pg_temp.try('select last_error from public.notification_deliveries'), '42501', 'delivery last_error cannot be selected');
select is(pg_temp.try('select attempts from public.notification_deliveries'), '42501', 'delivery attempts cannot be selected');
select is(pg_temp.try('select locked_by from public.notification_deliveries'), '42501', 'delivery locked_by cannot be selected');
select is(pg_temp.try('select * from public.notification_deliveries'), '42501', 'select * on deliveries fails');
select is(pg_temp.try('select id, channel, status, sent_at from public.notification_deliveries'), 'ok', 'twin: channel and status can be selected');
select pg_temp.act_as('postgres');
select ok(not has_any_column_privilege('anon', 'public.push_subscriptions', 'select') and not has_any_column_privilege('anon', 'public.notification_deliveries', 'select')
          and not has_any_column_privilege('anon', 'public.notifications', 'select') and not has_any_column_privilege('anon', 'public.notification_preferences', 'select')
          and not has_any_column_privilege('anon', 'public.messages', 'select') and not has_any_column_privilege('anon', 'public.message_recipients', 'select'), 'anon holds no privilege on any of the six private tables');
select ok(not has_column_privilege('authenticated', 'public.push_subscriptions', c, 'select'), 'authenticated cannot select push_subscriptions.' || c)
  from unnest(array['endpoint', 'p256dh', 'auth_secret']) c;
select ok(has_column_privilege('service_role', 'public.push_subscriptions', c, 'select'), 'twin: the worker can read push_subscriptions.' || c)
  from unnest(array['endpoint', 'p256dh', 'auth_secret']) c;
select ok(not has_column_privilege('authenticated', 'public.notification_deliveries', c, 'select'), 'authenticated cannot select notification_deliveries.' || c)
  from unnest(array['provider_message_id', 'last_error', 'attempts', 'locked_by', 'locked_at', 'lock_expires_at', 'next_attempt_at']) c;
select ok(has_column_privilege('service_role', 'public.notification_deliveries', c, 'select'), 'twin: the worker can read notification_deliveries.' || c)
  from unnest(array['provider_message_id', 'last_error', 'attempts', 'locked_by']) c;

-- ===========================================================================
-- 2. Nobody writes these tables directly (only the functions do), apart from a person's own preferences and devices
-- ===========================================================================
create temp table wr (who text, op text, res text);
grant all on wr to public;
do $$
declare w text;
begin
  foreach w in array array['u_staff_a1', 'u_manager_a1', 'u_locadmin_a1', 'u_orgadmin_a', 'u_platform', 'u_orgadmin_b', 'anon', 'service_role'] loop
    perform pg_temp.act_as(w);
    insert into wr values
      (w, 'insert message', pg_temp.try($q$insert into public.messages (organization_id, sender_person_id, body) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'forged')$q$)),
      (w, 'update message', pg_temp.try($q$update public.messages set body = 'edited'$q$)),
      (w, 'delete message', pg_temp.try($q$delete from public.messages$q$)),
      (w, 'insert recipient', pg_temp.try($q$insert into public.message_recipients (organization_id, message_id, person_id) values (pg_temp.id('org_a'), (select id from public.messages limit 1), pg_temp.id('p_staff_a2'))$q$)),
      (w, 'update recipient', pg_temp.try($q$update public.message_recipients set read_at = now()$q$)),
      (w, 'delete recipient', pg_temp.try($q$delete from public.message_recipients$q$)),
      (w, 'insert notification', pg_temp.try($q$insert into public.notifications (organization_id, person_id, kind, title, source_event_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'task.assigned', 'forged', gen_random_uuid())$q$)),
      (w, 'update notification', pg_temp.try($q$update public.notifications set read_at = now()$q$)),
      (w, 'delete notification', pg_temp.try($q$delete from public.notifications$q$)),
      (w, 'update delivery', pg_temp.try($q$update public.notification_deliveries set status = 'sent'$q$)),
      (w, 'delete delivery', pg_temp.try($q$delete from public.notification_deliveries$q$)),
      (w, 'insert push', pg_temp.try($q$insert into public.push_subscriptions (organization_id, person_id, endpoint, p256dh, auth_secret) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'https://push.example.test/forged', 'BPforgedforgedforgedforged', 'forgedauth1')$q$)),
      (w, 'update push', pg_temp.try($q$update public.push_subscriptions set endpoint = 'https://push.example.test/hijack'$q$));
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select string_agg(distinct res, ',') from wr where who = w.who), '42501', w.who || ': 14 direct writes on messages, recipients, notifications, deliveries and push subscriptions are all refused')
  from (values ('u_staff_a1'), ('u_manager_a1'), ('u_locadmin_a1'), ('u_orgadmin_a'), ('u_platform'), ('u_orgadmin_b'), ('anon'), ('service_role')) w (who);
select is((select count(*) from public.messages), 2::bigint, 'no message was added, changed or removed by those attempts');
select is((select count(*) from public.notifications where read_at is not null), 0::bigint, 'and no notification was changed');
select is((select count(*) from public.notification_deliveries where status = 'sent'), 3::bigint, 'and no delivery was changed (only the 3 in_app rows are sent)');
select pg_temp.act_as('service_role');
select is(pg_temp.try($$delete from public.push_subscriptions$$), '42501', 'the worker cannot delete push subscriptions either (it disables them through a function)');
select is(pg_temp.try($$delete from public.notification_preferences$$), '42501', 'nor delete preferences');
select is(pg_temp.try($$insert into public.notification_preferences (organization_id, person_id, channel, enabled) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'push', false)$$), '42501', 'nor write preferences');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 3. send_message
-- ===========================================================================
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_staff_a1')], 'reply')$$), 'ok', 'twin: manager A1 can message a person they can see (staff A1)');
select pg_temp.act_as('postgres');
select results_eq($$select count(*), min(e.organization_id::text), min(e.entity_table) from public.outbox_events e where e.type = 'message.sent'$$, $$select 2::bigint, pg_temp.id('org_a')::text, 'messages'::text$$, 'each sent message wrote exactly one message.sent event (2 so far)');
select is((select count(*) from public.outbox_events e where e.type = 'message.sent' and (e.payload ? 'body' or e.payload::text like '%private words%' or e.payload::text like '%reply%')), 0::bigint, 'and the event carries ids only, never the text');
select is((select array(select jsonb_object_keys(payload) order by 1) from public.outbox_events where type = 'message.sent' limit 1), array['message_id', 'recipient_person_ids', 'sender_person_id'], 'the event payload keys are message_id, recipient_person_ids, sender_person_id');
select results_eq($$select sender_person_id, body from public.messages where body like 'LIT-MSG-1%'$$, $$select pg_temp.id('p_staff_a1'), 'LIT-MSG-1 private words'$$, 'the message is stored with the caller as sender (not chosen by the caller)');
select is((select count(*) from public.message_recipients r join public.messages m on m.id = r.message_id where m.body like 'LIT-MSG-1%' and r.person_id = pg_temp.id('p_manager_a1') and r.read_at is null), 1::bigint, 'with one unread recipient row');

create temp table sm (n int, who text, recipients text, body text, expect text, label text);
grant all on sm to public;
insert into sm values
  (1,  'u_staff_a1',   'p_staff_a1',                  'x',  '42501 you cannot message one or more of these people', 'yourself'),
  (2,  'u_staff_a1',   'p_manager_a1,p_staff_a1',     'x',  '42501 you cannot message one or more of these people', 'yourself among valid recipients'),
  (3,  'u_staff_a1',   'p_staff_a2',                  'x',  '42501 you cannot message one or more of these people', 'someone you cannot see (another location)'),
  (4,  'u_staff_a1',   'p_staff_b1',                  'x',  '42501 you cannot message one or more of these people', 'a person of another organization'),
  (5,  'u_staff_a1',   'RANDOM',                      'x',  '42501 you cannot message one or more of these people', 'a person that does not exist'),
  (6,  'u_staff_a1',   'p_manager_a1,p_staff_a2',     'x',  '42501 you cannot message one or more of these people', 'one valid and one unseeable recipient (the whole message is refused)'),
  (7,  'u_staff_a1',   'p_manager_a1,RANDOM',         'x',  '42501 you cannot message one or more of these people', 'one valid and one nonexistent recipient'),
  (8,  'u_staff_a2',   'p_manager_a1',                'x',  '42501 you cannot message one or more of these people', 'staff A2 to manager A1 (not visible to each other)'),
  (9,  'u_staff_a1',   'NONE',                        'x',  '22023 choose 1 to 50 people', 'no recipients (empty array)'),
  (10, 'u_staff_a1',   'NULLS',                       'x',  '22023 choose 1 to 50 people', 'only null recipients'),
  (11, 'u_staff_a1',   'MANY51',                      'x',  '22023 choose 1 to 50 people', '51 recipients'),
  (12, 'u_staff_a1',   'MANY50',                      'x',  '42501 you cannot message one or more of these people', '50 recipients (the limit is passed; none can be seen)'),
  (13, 'u_staff_a1',   'p_manager_a1',                NULL, '22023 a message needs 1 to 4000 characters', 'a null body'),
  (14, 'u_staff_a1',   'p_manager_a1',                '',   '22023 a message needs 1 to 4000 characters', 'an empty body'),
  (15, 'u_staff_a1',   'p_manager_a1',                '   ','22023 a message needs 1 to 4000 characters', 'a blank body'),
  (16, 'u_staff_a1',   'p_manager_a1',                'LONG4001', '22023 a message needs 1 to 4000 characters', 'a 4001 character body'),
  (17, 'u_staff_a1',   'p_manager_a1',                'LONG4000', 'ok', 'twin: a 4000 character body'),
  (18, 'u_staff_a1',   'p_manager_a1,p_manager_a1',   'dup', 'ok', 'twin: the same recipient twice (counted once)'),
  (19, 'u_staff_a1',   'p_manager_a1,NULLS',          'with a null', 'ok', 'twin: a null among valid recipients (ignored)'),
  (20, 'u_noaccount',  'p_manager_a1',                'x',  '42501 not allowed', 'a user with no account'),
  (21, 'u_disabled_a', 'p_manager_a1',                'x',  '42501 not allowed', 'a disabled account'),
  (22, 'u_staff_b1',   'p_manager_a1',                'x',  '42501 not allowed', 'a user of another organization sending in org A'),
  (23, 'u_platform',   'p_manager_a1',                'x',  '42501 not allowed', 'a platform admin (not a member of the organization)');
create temp table sm_res (n int, res text);
grant all on sm_res to public;
create temp table sm_before as select (select count(*) from public.messages) as msgs, (select count(*) from public.message_recipients) as rcpts;
grant all on sm_before to public;
do $$
declare r record; v_ids text; v_body text;
begin
  for r in select * from sm order by n loop
    v_ids := case
      when r.recipients = 'NONE' then 'array[]::uuid[]'
      when r.recipients = 'NULLS' then 'array[null, null]::uuid[]'
      when r.recipients = 'MANY51' then '(select array_agg(gen_random_uuid()) from generate_series(1, 51))'
      when r.recipients = 'MANY50' then '(select array_agg(gen_random_uuid()) from generate_series(1, 50))'
      else 'array[' || (select string_agg(case when x = 'RANDOM' then 'gen_random_uuid()' when x = 'NULLS' then 'null::uuid' else 'pg_temp.id(' || quote_literal(x) || ')' end, ',') from unnest(string_to_array(r.recipients, ',')) x) || ']::uuid[]' end;
    v_body := case when r.body = 'LONG4001' then quote_literal(repeat('b', 4001)) when r.body = 'LONG4000' then quote_literal(repeat('b', 4000)) when r.body is null then 'null' else quote_literal(r.body) end;
    perform pg_temp.act_as(r.who);
    insert into sm_res values (r.n, pg_temp.try_msg('select public.send_message(pg_temp.id(''org_a''), ' || v_ids || ', ' || v_body || ')'));
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select res from sm_res s where s.n = t.n), t.expect, 'send_message: ' || t.label) from sm t order by t.n;
select is((select count(distinct res) from sm_res where n in (1, 2, 3, 4, 5, 6, 7, 8, 12)), 1::bigint, 'the nine refusals about recipients are word-for-word identical (it never says which recipient)');
select is((select count(*) from public.messages) - (select msgs from sm_before), 3::bigint, 'only the three allowed twins created a message');
select is((select count(*) from public.message_recipients) - (select rcpts from sm_before), 3::bigint, 'with one recipient row each (the duplicated and the null recipient counted once)');
select pg_temp.act_as('anon');
select is(pg_temp.try($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_manager_a1')], 'x')$$), '42501', 'send_message: anon cannot call it');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_manager_a1')], 'x')$$), '42501 not signed in', 'send_message: the server key with no user is refused');
select pg_temp.act_as('postgres');
-- archived recipient: the same message is accepted until the person is archived
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_staff_a1b')], 'hello Sid')$$), 'ok', 'twin: org admin A messages staff A1b');
select pg_temp.act_as('postgres');
update public.people set archived_at = now() where id = pg_temp.id('p_staff_a1b');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_staff_a1b')], 'hello Sid again')$$), '42501 you cannot message one or more of these people', 'an archived person cannot be messaged (same refusal)');
select pg_temp.act_as('postgres');
update public.people set archived_at = null where id = pg_temp.id('p_staff_a1b');
-- a message to a person you can see is allowed even for an org admin, and the org admin still cannot read the others' messages
select pg_temp.act_as('u_orgadmin_a');
select is((select count(*) from public.messages where body like 'LIT-MSG-1%'), 0::bigint, 'org admin A still cannot read the message from staff A1 to manager A1');
select is((select count(*) from public.messages where body = 'hello Sid'), 1::bigint, 'twin: but reads the one they sent');
select pg_temp.act_as('u_staff_a1b');
select is((select count(*) from public.messages where body = 'hello Sid'), 1::bigint, 'twin: and the recipient reads it');
select is((select count(*) from public.message_recipients), 1::bigint, 'the recipient sees only their own recipient row');
select pg_temp.act_as('u_manager_a1');
select is((select count(*) from public.messages where body like 'LIT-MSG-1%'), 1::bigint, 'twin: manager A1 reads the message addressed to them');
select is((select count(*) from public.messages where body = 'hello Sid'), 0::bigint, 'but not the message to someone else');
select pg_temp.act_as('postgres');

-- mark_message_read
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.mark_message_read((select id from public.messages where body like 'LIT-MSG-1%'))$$), 'ok', 'mark_message_read: the recipient marks it read');
select pg_temp.act_as('postgres');
select is((select read_at = now() from public.message_recipients r join public.messages m on m.id = r.message_id where m.body like 'LIT-MSG-1%' and r.person_id = pg_temp.id('p_manager_a1')), true, 'it sets read_at');
update public.message_recipients set read_at = now() - interval '1 hour' where person_id = pg_temp.id('p_manager_a1');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.mark_message_read((select id from public.messages where body like 'LIT-MSG-1%'))$$), 'ok', 'a second call is fine');
select pg_temp.act_as('postgres');
select is((select read_at = now() - interval '1 hour' from public.message_recipients where person_id = pg_temp.id('p_manager_a1') and message_id = (select id from public.messages where body like 'LIT-MSG-1%')), true, 'and keeps the first read time');
create temp table mr (n int, who text, res text);
grant all on mr to public;
do $$
declare w text; i int := 0;
begin
  foreach w in array array['u_staff_a1', 'u_staff_a2', 'u_orgadmin_a', 'u_locadmin_a1', 'u_platform', 'u_staff_b1', 'u_noaccount', 'u_disabled_a'] loop
    i := i + 1;
    perform pg_temp.act_as(w);
    insert into mr values (i, w, pg_temp.try_msg($q$select public.mark_message_read((select id from public.messages where body like 'LIT-MSG-1%'))$q$));
  end loop;
  perform pg_temp.act_as('postgres');
end $$;
select is((select res from mr where n = t.n), '42501 not allowed', 'mark_message_read refused (uniform): ' || t.who) from (select n, who from mr) t order by t.n;
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg('select public.mark_message_read(gen_random_uuid())'), '42501 not allowed', 'mark_message_read: a message that does not exist gives the same answer');
select is(pg_temp.try_msg('select public.mark_message_read(null)'), '42501 not allowed', 'and so does null');
select pg_temp.act_as('anon');
select is(pg_temp.try('select public.mark_message_read(gen_random_uuid())'), '42501', 'mark_message_read: anon cannot call it');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg('select public.mark_message_read(gen_random_uuid())'), '42501 not signed in', 'mark_message_read: the server key with no user is refused');
select pg_temp.act_as('postgres');
select is((select count(*) from public.message_recipients where read_at is not null and person_id <> pg_temp.id('p_manager_a1')), 0::bigint, 'only the real recipient''s rows were marked read (nobody else''s)');
select is((select count(*) from public.message_recipients r join public.messages m on m.id = r.message_id where m.body like 'LIT-MSG-1%' and r.person_id = pg_temp.id('p_manager_a1') and r.read_at is not null), 1::bigint, 'twin: and the real recipient''s row is marked read');

-- ===========================================================================
-- 4. create_notification (the worker): idempotent, who is a member, urgency, muted channels and devices
-- ===========================================================================
-- Devices and preferences: staff A1 = email muted + active device; manager A1 = push muted + active device (set up above);
-- staff A2 = nothing; location admin A1 = only a disabled device.
insert into public.push_subscriptions (id, organization_id, person_id, endpoint, p256dh, auth_secret, disabled_at)
values (pg_temp.id('ps_la'), pg_temp.id('org_a'), pg_temp.id('p_locadmin_a1'), 'https://push.example.test/dead', 'BPdeaddeaddeaddeaddead1', 'deadauth1', now());
select pg_temp.mkev('c1', 'org_a', '{"urgency":"high"}');
select pg_temp.mkev('c2', 'org_a', '{"urgency":"bogus"}');
select pg_temp.mkev('c3');
select pg_temp.mkev('c4', 'org_a', '{"urgency":"critical"}');
select pg_temp.mkev('cb', 'org_b');
create temp table nb as select (select count(*) from public.notifications) as n, (select count(*) from public.notification_deliveries) as d;
grant all on nb to public;
create temp table nid (k text primary key, id uuid);
grant all on nid to public;
select pg_temp.act_as('service_role');
insert into nid values ('c1_s', public.create_notification(pg_temp.ev('c1'), pg_temp.id('p_staff_a1'), 'task.assigned', '  Title ONE  ', ' body one ', '/tasks/1', null));
select pg_temp.act_as('postgres');
select results_eq($$select title, body, link_path, urgency, source_table, (source_event_id = pg_temp.ev('c1')), organization_id from public.notifications where id = (select id from nid where k = 'c1_s')$$,
  $$select 'Title ONE'::text, 'body one'::text, '/tasks/1'::text, 'high'::text, 'tasks'::text, true, pg_temp.id('org_a')$$, 'create_notification trims the text, takes the urgency from the event payload and the source from the event');
select is((select count(*) from public.notification_deliveries where notification_id = (select id from nid where k = 'c1_s')), 3::bigint, 'it creates the three delivery rows');
select results_eq($$select channel, status, last_error from public.notification_deliveries where notification_id = (select id from nid where k = 'c1_s') order by channel$$,
  $$values ('email'::text, 'skipped'::text, 'turned off by the person'::text), ('in_app', 'sent', null), ('push', 'pending', null)$$, 'in_app sent; email skipped because staff A1 turned it off; push pending (active device)');
select is((select sent_at = now() from public.notification_deliveries where notification_id = (select id from nid where k = 'c1_s') and channel = 'in_app'), true, 'in_app has its sent time');
select pg_temp.act_as('service_role');
-- idempotent: same (event, person, kind) again, with different text
insert into nid values ('c1_s_again', public.create_notification(pg_temp.ev('c1'), pg_temp.id('p_staff_a1'), 'task.assigned', 'A different title', 'different', '/tasks/other', 'critical'));
insert into nid values ('c1_s_3', public.create_notification(pg_temp.ev('c1'), pg_temp.id('p_staff_a1'), 'task.assigned', 'Title ONE', null, null, null));
select pg_temp.act_as('postgres');
select is((select id from nid where k = 'c1_s_again'), (select id from nid where k = 'c1_s'), 'idempotent: the same event, person and kind returns the same notification id');
select is((select id from nid where k = 'c1_s_3'), (select id from nid where k = 'c1_s'), 'and again');
select is((select count(*) from public.notifications where source_event_id = pg_temp.ev('c1')), 1::bigint, 'still exactly one notification for that event');
select is((select count(*) from public.notification_deliveries where notification_id = (select id from nid where k = 'c1_s')), 3::bigint, 'and still three deliveries');
select results_eq($$select title, urgency, link_path from public.notifications where id = (select id from nid where k = 'c1_s')$$, $$select 'Title ONE'::text, 'high'::text, '/tasks/1'::text$$, 'the first call''s content is kept (a retry changes nothing)');
select is(pg_temp.try($$insert into public.notifications (organization_id, person_id, kind, title, source_event_id) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'task.assigned', 'dup', pg_temp.ev('c1'))$$), '23505', 'the database itself refuses a second row for (event, person, kind) (unique)');
select is(pg_temp.try($$insert into public.notification_deliveries (organization_id, notification_id, person_id, channel) values (pg_temp.id('org_a'), (select id from nid where k = 'c1_s'), pg_temp.id('p_staff_a1'), 'email')$$), '23505', 'and a second delivery for (notification, channel) (unique)');
-- different kind / person / event are separate notifications
select pg_temp.act_as('service_role');
insert into nid values ('c1_k2', public.create_notification(pg_temp.ev('c1'), pg_temp.id('p_staff_a1'), 'task.overdue', 'Other kind'));
insert into nid values ('c1_a2', public.create_notification(pg_temp.ev('c1'), pg_temp.id('p_staff_a2'), 'task.assigned', 'For A2'));
insert into nid values ('c3_s',  public.create_notification(pg_temp.ev('c3'), pg_temp.id('p_staff_a1'), 'task.assigned', 'Event 3'));
insert into nid values ('c2_s',  public.create_notification(pg_temp.ev('c2'), pg_temp.id('p_staff_a1'), 'task.assigned', 'Event 2 bogus urgency'));
insert into nid values ('c4_s',  public.create_notification(pg_temp.ev('c4'), pg_temp.id('p_staff_a1'), 'task.assigned', 'Event 4 critical'));
insert into nid values ('c4_m',  public.create_notification(pg_temp.ev('c4'), pg_temp.id('p_manager_a1'), 'task.assigned', 'Critical for manager'));
insert into nid values ('c1_m',  public.create_notification(pg_temp.ev('c1'), pg_temp.id('p_manager_a1'), 'task.assigned', 'High for manager'));
insert into nid values ('c1_la', public.create_notification(pg_temp.ev('c1'), pg_temp.id('p_locadmin_a1'), 'task.assigned', 'For loc admin'));
insert into nid values ('c3_pn', public.create_notification(pg_temp.ev('c3'), pg_temp.id('p_staff_a1'), 'task.assigned', 'Normal override', null, null, 'normal'));
select pg_temp.act_as('postgres');
select is((select count(distinct id) from nid where k in ('c1_s', 'c1_k2', 'c1_a2', 'c3_s', 'c2_s', 'c4_s')), 6::bigint, 'a different kind, person or event each gives a separate notification');
select is((select urgency from public.notifications where id = (select id from nid where k = 'c2_s')), 'normal', 'an unknown urgency in the event payload falls back to normal');
select is((select urgency from public.notifications where id = (select id from nid where k = 'c4_s')), 'critical', 'urgency critical in the payload is used');
select is((select urgency from public.notifications where id = (select id from nid where k = 'c3_s')), 'normal', 'no urgency anywhere means normal');
select results_eq($$select channel, status from public.notification_deliveries where notification_id = (select id from nid where k = 'c4_s') order by channel$$,
  $$values ('email'::text, 'pending'::text), ('in_app', 'sent'), ('push', 'pending')$$, 'critical overrides the muted email channel (staff A1 muted email, it is pending anyway)');
select results_eq($$select channel, status from public.notification_deliveries where notification_id = (select id from nid where k = 'c3_s') order by channel$$,
  $$values ('email'::text, 'skipped'::text), ('in_app', 'sent'), ('push', 'pending')$$, 'twin: the same person with a normal notification keeps email skipped');
select results_eq($$select channel, status from public.notification_deliveries where notification_id = (select id from nid where k = 'c3_pn') order by channel$$,
  $$values ('email'::text, 'skipped'::text), ('in_app', 'sent'), ('push', 'pending')$$, 'an explicit normal urgency is not critical, so the mute applies');
select results_eq($$select channel, status, last_error from public.notification_deliveries where notification_id = (select id from nid where k = 'c1_m') order by channel$$,
  $$values ('email'::text, 'pending'::text, null), ('in_app', 'sent', null), ('push', 'skipped', 'turned off by the person')$$, 'a muted push channel (with an active device) is skipped for a high notification');
select results_eq($$select channel, status from public.notification_deliveries where notification_id = (select id from nid where k = 'c4_m') order by channel$$,
  $$values ('email'::text, 'pending'::text), ('in_app', 'sent'), ('push', 'pending')$$, 'critical overrides the muted push channel too');
select results_eq($$select channel, status, last_error from public.notification_deliveries where notification_id = (select id from nid where k = 'c1_a2') order by channel$$,
  $$values ('email'::text, 'pending'::text, null), ('in_app', 'sent', null), ('push', 'skipped', 'no push device')$$, 'a person with no device: push is skipped with the reason, email is pending');
select results_eq($$select channel, status, last_error from public.notification_deliveries where notification_id = (select id from nid where k = 'c1_la') order by channel$$,
  $$values ('email'::text, 'pending'::text, null), ('in_app', 'sent', null), ('push', 'skipped', 'no push device')$$, 'a disabled device does not count as a device');
-- critical does not invent a device
select pg_temp.mkev('c5', 'org_a', '{"urgency":"critical"}');
select pg_temp.act_as('service_role');
insert into nid values ('c5_a2', public.create_notification(pg_temp.ev('c5'), pg_temp.id('p_staff_a2'), 'task.assigned', 'Critical, no device'));
select pg_temp.act_as('postgres');
select is((select status from public.notification_deliveries where notification_id = (select id from nid where k = 'c5_a2') and channel = 'push'), 'skipped', 'critical does not create a device: push is still skipped when there is none');
-- not an active member: nothing created (null)
select pg_temp.act_as('service_role');
create temp table nm (n int, who text, res text);
grant all on nm to public;
insert into nm values
  (1, 'p_disabled_a',    coalesce(public.create_notification(pg_temp.ev('c3'), pg_temp.id('p_disabled_a'),    'task.assigned', 'x')::text, 'null')),
  (2, 'p_unassigned_a',  coalesce(public.create_notification(pg_temp.ev('c3'), pg_temp.id('p_unassigned_a'),  'task.assigned', 'x')::text, 'null')),
  (3, 'p_staff_b1',      coalesce(public.create_notification(pg_temp.ev('c3'), pg_temp.id('p_staff_b1'),      'task.assigned', 'x')::text, 'null')),
  (4, 'random',          coalesce(public.create_notification(pg_temp.ev('c3'), gen_random_uuid(),             'task.assigned', 'x')::text, 'null')),
  (5, 'null person',     coalesce(public.create_notification(pg_temp.ev('c3'), null,                          'task.assigned', 'x')::text, 'null')),
  (6, 'org A person on an org B event', coalesce(public.create_notification(pg_temp.ev('cb'), pg_temp.id('p_staff_a1'), 'task.assigned', 'x')::text, 'null'));
select pg_temp.act_as('postgres');
select is((select res from nm where n = t.n), 'null', 'create_notification returns null and creates nothing for: ' || t.who) from (select n, who from nm) t order by t.n;
select is((select count(*) from public.notifications where title = 'x'), 0::bigint, 'none of those left a notification behind');
update public.people set archived_at = now() where id = pg_temp.id('p_staff_a1b');
select pg_temp.act_as('service_role');
select is(public.create_notification(pg_temp.ev('c3'), pg_temp.id('p_staff_a1b'), 'task.assigned', 'x') is null, true, 'an archived person gets nothing');
select pg_temp.act_as('postgres');
update public.people set archived_at = null where id = pg_temp.id('p_staff_a1b');
select pg_temp.act_as('service_role');
select is(public.create_notification(pg_temp.ev('c3'), pg_temp.id('p_staff_a1b'), 'task.assigned', 'Welcome back') is not null, true, 'twin: the same person, active again, gets one');
select pg_temp.act_as('postgres');
-- invalid input is refused and leaves nothing
create temp table nb2 as select (select count(*) from public.notifications) as n, (select count(*) from public.notification_deliveries) as d;
grant all on nb2 to public;
select pg_temp.mkev('c6');
select pg_temp.act_as('service_role');
create temp table ni (n int, label text, res text, expect text);
grant all on ni to public;
insert into ni values
  (1, 'an unknown event',            pg_temp.try_msg($$select public.create_notification(gen_random_uuid(), pg_temp.id('p_staff_a1'), 'task.assigned', 'x')$$), '22023 no such event'),
  (2, 'a null event',                pg_temp.try_msg($$select public.create_notification(null, pg_temp.id('p_staff_a1'), 'task.assigned', 'x')$$), '22023 no such event'),
  (3, 'a bad kind',                  pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'Bad Kind', 'x')$$), '23514'),
  (4, 'a null kind',                 pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), null, 'x')$$), '23502'),
  (5, 'a blank title',               pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.assigned', '   ')$$), '23514'),
  (6, 'a null title',                pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.assigned', null)$$), '23502'),
  (7, 'a 201 character title',       pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.assigned', repeat('t', 201))$$), '23514'),
  (8, 'a 501 character body',        pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.assigned', 'x', repeat('b', 501))$$), '23514'),
  (9, 'a link to another site',      pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.assigned', 'x', null, 'https://evil.example/x')$$), '23514'),
  (10, 'a protocol-relative link',   pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.assigned', 'x', null, '//evil.example/x')$$), '23514'),
  (11, 'a link with a script',       pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.assigned', 'x', null, '/x"><script>')$$), '23514'),
  (12, 'an unknown urgency argument', pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.assigned', 'x', null, null, 'catastrophic')$$), '23514');
select pg_temp.act_as('postgres');
select is((select left(res, length(expect)) from ni where n = t.n), t.expect, 'create_notification refuses ' || t.label) from (select n, label, expect from ni) t order by t.n;
select is((select count(*) from public.notifications where source_event_id = pg_temp.ev('c6')), 0::bigint, 'none of the refused calls left a notification (all or nothing)');
select is((select count(*) from public.notification_deliveries d join public.notifications n on n.id = d.notification_id where n.source_event_id = pg_temp.ev('c6')), 0::bigint, 'or a delivery');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.assigned', 'ok title', '   ', '/ok/path?x=1&y=2')$$), 'ok', 'twin: a valid call (blank body, a safe link) succeeds');
select pg_temp.act_as('postgres');
select is((select body from public.notifications where source_event_id = pg_temp.ev('c6')), null, 'a blank body is stored as null');
-- who may call it
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.other', 'x')$$), '42501', 'create_notification: authenticated users cannot call it');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.other', 'x')$$), '42501', 'nor an org admin');
select pg_temp.act_as('anon');
select is(pg_temp.try($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.other', 'x')$$), '42501', 'nor anon');
select pg_temp.act_as_service('u_orgadmin_a');
select is(pg_temp.try_msg($$select public.create_notification(pg_temp.ev('c6'), pg_temp.id('p_staff_a1'), 'task.other', 'x')$$), '42501 not allowed', 'nor the server key carrying a user''s JWT');
select pg_temp.act_as('postgres');
select is((select count(*) from public.notifications where source_event_id = pg_temp.ev('c6') and kind = 'task.other'), 0::bigint, 'and nothing was created by those refusals');

-- ===========================================================================
-- 5. notice_audience_person_ids (fan-out)
-- ===========================================================================
insert into public.notices (id, organization_id, location_id, title, body, status, publish_at, published_at)
values (pg_temp.id('fan_n'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Fan out', 'x', 'draft', null, null);
insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('fan_n'), pg_temp.id('loc_a1'));
update public.notices set status = 'published', publish_at = now(), published_at = now() where id = pg_temp.id('fan_n');
select pg_temp.act_as('service_role');
select is((select array_agg(p) from public.notice_audience_person_ids(pg_temp.id('fan_n')) p),
  (select array_agg(x order by x) from (values (pg_temp.id('p_staff_a1')), (pg_temp.id('p_staff_a1b')), (pg_temp.id('p_manager_a1')), (pg_temp.id('p_locadmin_a1')), (pg_temp.id('p_orgadmin_a'))) v (x)),
  'fan-out: the audience is the active members of A1 (and org-scope admins), not A2, not disabled, not other organizations');
select is((select count(*) from public.notice_audience_person_ids(gen_random_uuid())), 0::bigint, 'fan-out: an unknown notice has nobody');
select pg_temp.act_as_service('u_staff_a1');
select is((select count(*) from public.notice_audience_person_ids(pg_temp.id('fan_n'))), 0::bigint, 'fan-out: the same call with a user JWT returns nobody');
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try($$select * from public.notice_audience_person_ids(pg_temp.id('fan_n'))$$), '42501', 'fan-out: authenticated cannot call it');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 6. Push subscriptions: save, refresh, delete, own only
-- ===========================================================================
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/a2-phone', 'BPa2phonea2phonea2phone1', 'a2authsecret', 'Phone UA')$$), 'ok', 'save_push_subscription: staff A2 registers a device');
select pg_temp.act_as('postgres');
select results_eq($$select person_id, organization_id, user_agent, disabled_at is null from public.push_subscriptions where endpoint = 'https://push.example.test/a2-phone'$$,
  $$select pg_temp.id('p_staff_a2'), pg_temp.id('org_a'), 'Phone UA'::text, true$$, 'the device belongs to the caller''s own person');
create temp table ps_first as select id from public.push_subscriptions where endpoint = 'https://push.example.test/a2-phone';
grant all on ps_first to public;
update public.push_subscriptions set disabled_at = now() where endpoint = 'https://push.example.test/a2-phone';
select pg_temp.act_as('u_staff_a2');
select is(public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/a2-phone', 'BPnewkeynewkeynewkey123', 'newauthsecret', 'New UA'), (select id from ps_first), 'saving the same endpoint again returns the same id (upsert)');
select pg_temp.act_as('postgres');
select results_eq($$select p256dh, auth_secret, user_agent, disabled_at is null from public.push_subscriptions where endpoint = 'https://push.example.test/a2-phone'$$,
  $$select 'BPnewkeynewkeynewkey123'::text, 'newauthsecret'::text, 'New UA'::text, true$$, 'the keys are refreshed and a disabled device is re-enabled');
select is((select count(*) from public.push_subscriptions where person_id = pg_temp.id('p_staff_a2')), 1::bigint, 'still one device');
create temp table pv (n int, label text, res text, expect text);
grant all on pv to public;
select pg_temp.act_as('u_staff_a2');
insert into pv values
  (1, 'an http (not https) endpoint',  pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'http://push.example.test/x', 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '23514'),
  (2, 'an endpoint with a space',      pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/a b', 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '23514'),
  (3, 'a 2001 character endpoint',     pg_temp.try_msg(format($f$select public.save_push_subscription(pg_temp.id('org_a'), %L, 'BPa2phonea2phonea2phone1', 'a2authsecret')$f$, 'https://x.example/' || repeat('a', 1983))), '23514'),
  (4, 'a null endpoint',               pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), null, 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '23502'),
  (5, 'a short p256dh key',            pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/y', 'short', 'a2authsecret')$$), '23514'),
  (6, 'a p256dh key with a bad character', pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/y', 'BPa2phone a2phonea2phone1', 'a2authsecret')$$), '23514'),
  (7, 'a short auth secret',           pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/y', 'BPa2phonea2phonea2phone1', 'short')$$), '23514'),
  (8, 'a null auth secret',            pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/y', 'BPa2phonea2phonea2phone1', null)$$), '23502'),
  (9, 'a different organization',      pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_b'), 'https://push.example.test/y', 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '42501 not allowed'),
  (10, 'an unknown organization',      pg_temp.try_msg($$select public.save_push_subscription(gen_random_uuid(), 'https://push.example.test/y', 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '42501 not allowed'),
  (11, 'a null organization',          pg_temp.try_msg($$select public.save_push_subscription(null, 'https://push.example.test/y', 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '42501 not allowed');
select pg_temp.act_as('postgres');
select is((select left(res, length(expect)) from pv where n = t.n), t.expect, 'save_push_subscription refuses ' || t.label) from (select n, label, expect from pv) t order by t.n;
select is((select count(*) from public.push_subscriptions where endpoint like 'https://push.example.test/y%'), 0::bigint, 'none of those left a device behind');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/y', 'BPa2phonea2phonea2phone1', 'a2authsecret', repeat('u', 500))$$), 'ok', 'twin: a valid device (an over-long user agent is cut to 300 characters)');
select pg_temp.act_as('postgres');
select is((select char_length(user_agent) from public.push_subscriptions where endpoint = 'https://push.example.test/y'), 300, 'the user agent was cut to 300');
select pg_temp.act_as('u_noaccount');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/n', 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '42501 not allowed', 'a user with no account cannot save a device');
select pg_temp.act_as('u_disabled_a');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/n', 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '42501 not allowed', 'nor a disabled account');
select pg_temp.act_as('u_platform');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/n', 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '42501 not allowed', 'nor a platform admin (no person in the organization)');
select pg_temp.act_as('anon');
select is(pg_temp.try($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/n', 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '42501', 'nor anon');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/n', 'BPa2phonea2phonea2phone1', 'a2authsecret')$$), '42501 not signed in', 'nor the server key with no user');
select pg_temp.act_as('postgres');
-- the same endpoint under another person is a separate device (unique per person and endpoint)
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/a2-phone', 'BPmanagermanagermanager1', 'mgrauthsecret')$$), 'ok', 'the same endpoint saved by manager A1 is their own device');
select pg_temp.act_as('postgres');
select results_eq($$select person_id from public.push_subscriptions where endpoint = 'https://push.example.test/a2-phone' order by person_id$$,
  $$select p from (values (pg_temp.id('p_staff_a2')), (pg_temp.id('p_manager_a1'))) v (p) order by p$$, 'two rows, one per person: manager A1 did not take over staff A2''s device');
-- delete
select pg_temp.act_as('u_staff_a1');
select is(public.delete_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/a2-phone'), false, 'delete_push_subscription: staff A1 cannot delete a device with that endpoint (they have none: false)');
select is(public.delete_push_subscription(pg_temp.id('org_b'), 'https://push.example.test/SECRET-ENDPOINT-S'), false, 'and not with the wrong organization');
select is(pg_temp.affected($$delete from public.push_subscriptions where person_id <> pg_temp.id('p_staff_a1')$$), 0::bigint, 'a direct delete reaches only their own rows (0 of other people''s)');
select pg_temp.act_as('u_orgadmin_a');
select is(public.delete_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/SECRET-ENDPOINT-S'), false, 'an org admin cannot delete staff A1''s device');
select is(pg_temp.affected($$delete from public.push_subscriptions$$), 0::bigint, 'nor by a direct delete');
select pg_temp.act_as('u_platform');
select is(public.delete_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/SECRET-ENDPOINT-S'), false, 'nor a platform admin');
select pg_temp.act_as('postgres');
select is((select count(*) from public.push_subscriptions where id = pg_temp.id('ps_s')), 1::bigint, 'staff A1''s device is still there');
select pg_temp.act_as('u_staff_a1');
select is(public.delete_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/SECRET-ENDPOINT-S'), true, 'twin: staff A1 deletes their own device by endpoint');
select is(public.delete_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/SECRET-ENDPOINT-S'), false, 'a second delete finds nothing');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.affected($$delete from public.push_subscriptions where id = pg_temp.id('ps_m')$$), 1::bigint, 'twin: a direct delete of their own device works');
select pg_temp.act_as('anon');
select is(pg_temp.try($$select public.delete_push_subscription(pg_temp.id('org_a'), 'https://x.example/')$$), '42501', 'delete_push_subscription: anon cannot call it');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select public.delete_push_subscription(pg_temp.id('org_a'), 'https://x.example/')$$), '42501 not signed in', 'the server key with no user is refused');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 7. Notification preferences: own rows only
-- ===========================================================================
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.try($$insert into public.notification_preferences (id, organization_id, person_id, channel, enabled) values (pg_temp.id('pref_a2'), pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'push', false)$$), 'ok', 'staff A2 turns push off for themselves');
select is(pg_temp.try($$insert into public.notification_preferences (organization_id, person_id, channel) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'push')$$), '23505', 'a second row for the same channel is refused (unique)');
select is(pg_temp.try($$insert into public.notification_preferences (organization_id, person_id, channel) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'in_app')$$), '23514', 'in_app cannot be turned off (no such preference)');
select is(pg_temp.try($$insert into public.notification_preferences (organization_id, person_id, channel) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'sms')$$), '23514', 'an unknown channel is refused');
select is(pg_temp.try($$insert into public.notification_preferences (organization_id, person_id, channel, enabled) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'push', false)$$), '42501', 'a preference for someone else is refused');
select is(pg_temp.try($$insert into public.notification_preferences (organization_id, person_id, channel, enabled) values (pg_temp.id('org_b'), pg_temp.id('p_staff_a2'), 'email', false)$$), '23503', 'a preference with another organization''s id is refused (composite key)');
select is(pg_temp.try($$insert into public.notification_preferences (organization_id, person_id, channel, enabled) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'email', null)$$), '23502', 'a null enabled is refused');
select is(pg_temp.affected($$update public.notification_preferences set enabled = true where id = pg_temp.id('pref_a2')$$), 1::bigint, 'twin: they can turn it back on');
select is(pg_temp.try($$update public.notification_preferences set channel = 'email' where id = pg_temp.id('pref_a2')$$), '42501', 'the channel cannot be changed (no column grant)');
select is(pg_temp.try($$update public.notification_preferences set person_id = pg_temp.id('p_staff_a1') where id = pg_temp.id('pref_a2')$$), '42501', 'the person cannot be changed');
select is(pg_temp.try($$update public.notification_preferences set organization_id = pg_temp.id('org_b') where id = pg_temp.id('pref_a2')$$), '42501', 'the organization cannot be changed');
select is(pg_temp.try($$update public.notification_preferences set enabled = null where id = pg_temp.id('pref_a2')$$), '23502', 'enabled cannot be set to null');
select is(pg_temp.affected($$update public.notification_preferences set enabled = true where id = pg_temp.id('pref_s')$$), 0::bigint, 'staff A1''s preference cannot be updated by staff A2 (0 rows)');
select is(pg_temp.affected($$delete from public.notification_preferences where id = pg_temp.id('pref_s')$$), 0::bigint, 'nor deleted');
select is((select count(*) from public.notification_preferences), 1::bigint, 'staff A2 reads only their own preference');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($$insert into public.notification_preferences (organization_id, person_id, channel, enabled) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'email', false)$$), '42501', 'an org admin cannot write a preference for someone else');
select is(pg_temp.affected($$update public.notification_preferences set enabled = false$$), 0::bigint, 'nor update any');
select is(pg_temp.affected($$delete from public.notification_preferences$$), 0::bigint, 'nor delete any');
select pg_temp.act_as('u_platform');
select is(pg_temp.try($$insert into public.notification_preferences (organization_id, person_id, channel, enabled) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'email', false)$$), '42501', 'a platform admin cannot either');
select is(pg_temp.affected($$delete from public.notification_preferences$$), 0::bigint, 'nor delete any');
select pg_temp.act_as('anon');
select is(pg_temp.try($$insert into public.notification_preferences (organization_id, person_id, channel) values (pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'email')$$), '42501', 'anon cannot write preferences');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.affected($$delete from public.notification_preferences where id = pg_temp.id('pref_a2')$$), 1::bigint, 'twin: staff A2 deletes their own preference');
select pg_temp.act_as('postgres');
select is((select count(*) from public.notification_preferences), 3::bigint, 'the three preferences of other people are all still there');

-- ===========================================================================
-- 8. Reading notifications: own only
-- ===========================================================================
select pg_temp.act_as('u_staff_a1');
select is((select count(*) from public.notifications where person_id <> pg_temp.id('p_staff_a1')), 0::bigint, 'staff A1 reads only their own notifications');
select is((select count(*) from public.notifications) >= 5, true, 'twin: and has several');
create temp table mine as select id from public.notifications order by id;
grant all on mine to public;
select pg_temp.act_as('postgres');
create temp table mgr_n as select id from public.notifications where person_id = pg_temp.id('p_manager_a1');
grant all on mgr_n to public;
create temp table s_unread as select count(*) as n from public.notifications where person_id = pg_temp.id('p_staff_a1') and read_at is null;
grant all on s_unread to public;
select pg_temp.act_as('u_staff_a1');
select is(public.mark_notifications_read(array[(select id from mine limit 1), (select id from mgr_n limit 1), gen_random_uuid()]), 1, 'mark_notifications_read: counts only my own unread notification (someone else''s and a random id are ignored)');
select is(public.mark_notifications_read(array[(select id from mine limit 1)]), 0, 'a second call changes nothing (0)');
select is(public.mark_notifications_read(null), 0, 'null changes nothing');
select is(public.mark_notifications_read('{}'), 0, 'an empty list changes nothing');
select is(pg_temp.try_msg('select public.mark_notifications_read((select array_agg(gen_random_uuid()) from generate_series(1, 501)))'), '22023 too many at once', 'more than 500 ids is refused');
select is(pg_temp.try_msg('select public.mark_notifications_read((select array_agg(gen_random_uuid()) from generate_series(1, 500)))'), 'ok', 'twin: 500 ids is fine');
select pg_temp.act_as('postgres');
select is((select count(*) from public.notifications where read_at is not null and person_id <> pg_temp.id('p_staff_a1')), 0::bigint, 'nobody else''s notification was marked read');
select pg_temp.act_as('u_orgadmin_a');
select is(public.mark_notifications_read((select array_agg(id) from mgr_n)), 0, 'an org admin cannot mark the manager''s notifications read (0)');
select is(public.mark_all_notifications_read(pg_temp.id('org_a')), 0, 'mark_all_notifications_read by an org admin changes nobody else''s (0)');
select pg_temp.act_as('u_staff_a1');
select is(public.mark_all_notifications_read(pg_temp.id('org_b')), 0, 'mark_all for another organization changes nothing (0)');
select is(public.mark_all_notifications_read(pg_temp.id('org_a')), ((select n from s_unread) - 1)::int, 'twin: mark_all for my organization marks my remaining unread ones');
select is(public.mark_all_notifications_read(pg_temp.id('org_a')), 0, 'and then nothing more');
select pg_temp.act_as('postgres');
select is((select count(*) from public.notifications where person_id = pg_temp.id('p_manager_a1') and read_at is not null), 0::bigint, 'the manager''s notifications are still unread');
select is((select count(*) from public.notifications where person_id = pg_temp.id('p_staff_b1') and read_at is not null), 0::bigint, 'and org B''s');
select pg_temp.act_as('anon');
select is(pg_temp.try('select public.mark_all_notifications_read(gen_random_uuid())'), '42501', 'mark_all: anon cannot call it');
select is(pg_temp.try('select public.mark_notifications_read(null)'), '42501', 'mark_notifications_read: anon cannot call it');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg('select public.mark_all_notifications_read(gen_random_uuid())'), '42501 not signed in', 'mark_all: the server key with no user is refused');
select is(pg_temp.try_msg('select public.mark_notifications_read(null)'), '42501 not signed in', 'mark_notifications_read: the server key with no user is refused');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 9. The delivery worker: claim, complete, fail, skip, lock expiry, disable device
-- ===========================================================================
-- staff A2 gets a device so that email and push are both pending; six notifications (l1..l6)
insert into public.push_subscriptions (id, organization_id, person_id, endpoint, p256dh, auth_secret) values (pg_temp.id('ps_l'), pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'https://push.example.test/lifecycle', 'BPlifecyclelifecycle123', 'lifecycleauth');
update public.push_subscriptions set disabled_at = null where person_id = pg_temp.id('p_staff_a2');
-- (the earlier a2-phone and y devices are on staff A2 too; remove them so the lifecycle starts clean of other pending work)
update public.notification_deliveries set status = 'skipped', last_error = 'cleanup' where status = 'pending';
select pg_temp.mkev('l1'); select pg_temp.mkev('l2'); select pg_temp.mkev('l3'); select pg_temp.mkev('l4'); select pg_temp.mkev('l5'); select pg_temp.mkev('l6');
select pg_temp.act_as('service_role');
select is((select count(*) from (select public.create_notification(pg_temp.ev('l' || i), pg_temp.id('p_staff_a2'), 'task.assigned', 'Lifecycle ' || i) from generate_series(1, 6) i) q), 6::bigint, 'six notifications created for the lifecycle (staff A2)');
select pg_temp.act_as('postgres');
create temp table dl (name text primary key, id uuid);
grant all on dl to public;
insert into dl select 'l' || i || '_' || d.channel, d.id
from generate_series(1, 6) i
join public.notifications n on n.source_event_id = pg_temp.ev('l' || i)
join public.notification_deliveries d on d.notification_id = n.id;
select is((select count(*) from dl), 18::bigint, '18 delivery rows (in_app, email, push for each)');
select is((select count(*) from public.notification_deliveries d join dl on dl.id = d.id where d.status = 'pending'), 12::bigint, '12 of them pending (email and push), the six in_app rows already sent');
-- l5's in_app made pending (the worker must still never claim in_app), l6 made not due yet
update public.notification_deliveries set status = 'pending', sent_at = null where id = (select id from dl where name = 'l5_in_app');
update public.notification_deliveries set next_attempt_at = now() + interval '1 hour' where id in (select id from dl where name in ('l6_email', 'l6_push'));

-- validation (each refused with its own message) and who may call
select pg_temp.act_as('service_role');
create temp table cv (n int, label text, res text, expect text);
grant all on cv to public;
insert into cv values
  (1, 'a null worker',           pg_temp.try_msg($$select * from public.claim_notification_deliveries(null, 10, 60)$$), '22023 invalid worker'),
  (2, 'a blank worker',          pg_temp.try_msg($$select * from public.claim_notification_deliveries('   ', 10, 60)$$), '22023 invalid worker'),
  (3, 'a 101 character worker',  pg_temp.try_msg(format($f$select * from public.claim_notification_deliveries(%L, 10, 60)$f$, repeat('w', 101))), '22023 invalid worker'),
  (4, 'a zero limit',            pg_temp.try_msg($$select * from public.claim_notification_deliveries('w', 0, 60)$$), '22023 invalid limit'),
  (5, 'a limit over 500',        pg_temp.try_msg($$select * from public.claim_notification_deliveries('w', 501, 60)$$), '22023 invalid limit'),
  (6, 'a null limit',            pg_temp.try_msg($$select * from public.claim_notification_deliveries('w', null, 60)$$), '22023 invalid limit'),
  (7, 'a lock under 5 seconds',  pg_temp.try_msg($$select * from public.claim_notification_deliveries('w', 10, 4)$$), '22023 invalid lock time'),
  (8, 'a lock over an hour',     pg_temp.try_msg($$select * from public.claim_notification_deliveries('w', 10, 3601)$$), '22023 invalid lock time'),
  (9, 'a null lock time',        pg_temp.try_msg($$select * from public.claim_notification_deliveries('w', 10, null)$$), '22023 invalid lock time'),
  (10, 'the in_app channel',     pg_temp.try_msg($$select * from public.claim_notification_deliveries('w', 10, 60, 'in_app')$$), '22023 invalid channel'),
  (11, 'an unknown channel',     pg_temp.try_msg($$select * from public.claim_notification_deliveries('w', 10, 60, 'sms')$$), '22023 invalid channel');
select pg_temp.act_as('postgres');
select is((select res from cv where n = t.n), t.expect, 'claim_notification_deliveries refuses ' || t.label) from (select n, label, expect from cv) t order by t.n;
select is((select count(*) from public.notification_deliveries where attempts > 0), 0::bigint, 'none of the refused claims counted an attempt');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.try($$select * from public.claim_notification_deliveries('w', 10, 60)$$), '42501', 'claim: authenticated cannot call it');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($$select * from public.claim_notification_deliveries('w', 10, 60)$$), '42501', 'claim: nor an org admin');
select pg_temp.act_as('anon');
select is(pg_temp.try($$select * from public.claim_notification_deliveries('w', 10, 60)$$), '42501', 'claim: nor anon');
select pg_temp.act_as_service('u_staff_a2');
select is(pg_temp.try_msg($$select * from public.claim_notification_deliveries('w', 10, 60)$$), '42501 not allowed', 'claim: nor the server key carrying a user''s JWT');
select pg_temp.act_as('postgres');
select is((select count(*) from public.notification_deliveries where attempts > 0), 0::bigint, 'still no attempt counted');

-- claiming
create temp table claimed (w text, id uuid, channel text, attempts int);
grant all on claimed to public;
select pg_temp.act_as('service_role');
insert into claimed select 'w1', d.id, d.channel, d.attempts from public.claim_notification_deliveries('w1', 3, 60, 'email') d;
select is((select count(*) from claimed where w = 'w1'), 3::bigint, 'claim with a limit of 3 and the email channel returns 3 rows');
select is((select count(*) from claimed where w = 'w1' and channel = 'email' and attempts = 1), 3::bigint, 'all email, each claim counted as attempt 1');
insert into claimed select 'w2', d.id, d.channel, d.attempts from public.claim_notification_deliveries('w2', 100, 60) d;
select pg_temp.act_as('postgres');
select is((select count(*) from claimed where w = 'w2'), 7::bigint, 'a second worker claims the rest that is due: 2 email and 5 push (not the 3 already locked, not l6 which is not due, not in_app)');
select is((select count(*) from claimed where w = 'w2' and id in (select id from claimed where w = 'w1')), 0::bigint, 'the two workers never hold the same delivery');
select is((select count(*) from claimed where channel = 'in_app'), 0::bigint, 'the worker was never handed an in_app delivery (even a pending one)');
select is((select attempts from public.notification_deliveries where id = (select id from dl where name = 'l5_in_app')), 0, 'and it was not touched');
select is((select count(*) from claimed where id in (select id from dl where name in ('l6_email', 'l6_push'))), 0::bigint, 'a delivery that is not due yet was not claimed');
select results_eq($$select locked_by, (lock_expires_at = now() + interval '60 seconds') from public.notification_deliveries where id = (select id from claimed where w = 'w1' limit 1)$$, $$select 'w1'::text, true$$, 'a claimed delivery records the worker and a lock of the requested length');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_notification_deliveries('w3', 100, 60)), 0::bigint, 'a third worker finds nothing to claim (all locked or not due)');
select pg_temp.act_as('postgres');

-- complete: only the worker that holds the claim
create temp table pick as select (array_agg(id order by id))[1] as c1, (array_agg(id order by id))[2] as c2, (array_agg(id order by id))[3] as c3 from claimed where w = 'w1';
create temp table pick2 as select (array_agg(id order by id))[1] as s1, (array_agg(id order by id))[2] as s2, (array_agg(id order by id))[3] as s3, (array_agg(id order by id))[4] as s4 from claimed where w = 'w2';
grant all on pick, pick2 to public;
select pg_temp.act_as('service_role');
select is(public.complete_notification_delivery((select c1 from pick), 'w2', 'prov-1'), false, 'complete: the wrong worker cannot complete it');
select is(public.complete_notification_delivery((select c1 from pick), null, 'prov-1'), false, 'complete: a null worker cannot');
select is(public.complete_notification_delivery((select c1 from pick), '', 'prov-1'), false, 'complete: an empty worker cannot');
select is(public.complete_notification_delivery(gen_random_uuid(), 'w1', 'prov-1'), false, 'complete: an unknown delivery is false');
select is(public.complete_notification_delivery(null, 'w1', 'prov-1'), false, 'complete: a null id is false');
select pg_temp.act_as('postgres');
select is((select status from public.notification_deliveries where id = (select c1 from pick)), 'pending', 'it is still pending after those refusals');
select pg_temp.act_as('service_role');
select is(public.complete_notification_delivery((select c1 from pick), 'w1', 'prov-1'), true, 'twin: the worker that holds the claim completes it');
select is(public.complete_notification_delivery((select c1 from pick), 'w1', 'prov-1'), false, 'completing twice is false (not pending any more)');
select pg_temp.act_as('postgres');
select results_eq($$select status, sent_at = now(), provider_message_id, locked_by, lock_expires_at from public.notification_deliveries where id = (select c1 from pick)$$, $$select 'sent'::text, true, 'prov-1'::text, null::text, null::timestamptz$$, 'sent: sent_at set, provider id kept, lock cleared');
select pg_temp.act_as('service_role');
select is(public.complete_notification_delivery((select s1 from pick2), ' w2 ', repeat('p', 300)), true, 'complete: the worker name is trimmed when matched, and an over-long provider id is cut');
select pg_temp.act_as('postgres');
select is((select char_length(provider_message_id) from public.notification_deliveries where id = (select s1 from pick2)), 200, 'the provider id was cut to 200');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.try($$select public.complete_notification_delivery(gen_random_uuid(), 'w1')$$), '42501', 'complete: authenticated cannot call it');
select pg_temp.act_as('anon');
select is(pg_temp.try($$select public.complete_notification_delivery(gen_random_uuid(), 'w1')$$), '42501', 'complete: nor anon');
select pg_temp.act_as_service('u_staff_a2');
select is(pg_temp.try_msg($$select public.complete_notification_delivery(gen_random_uuid(), 'w1')$$), '42501 not allowed', 'complete: nor the server key carrying a user JWT');
select pg_temp.act_as('postgres');

-- fail: retry with backoff, permanent, only the holder
select pg_temp.act_as('service_role');
select is(public.fail_notification_delivery((select c2 from pick), 'w2', 'boom'), null, 'fail: the wrong worker gets null and changes nothing');
select is(public.fail_notification_delivery((select c2 from pick), null, 'boom'), null, 'fail: a null worker gets null');
select is(public.fail_notification_delivery(gen_random_uuid(), 'w1', 'boom'), null, 'fail: an unknown delivery gets null');
select pg_temp.act_as('postgres');
select results_eq($$select status, attempts, locked_by from public.notification_deliveries where id = (select c2 from pick)$$, $$select 'pending'::text, 1, 'w1'::text$$, 'still locked by w1 after those refusals');
select pg_temp.act_as('service_role');
select is(public.fail_notification_delivery((select c2 from pick), 'w1', 'boom'), 'pending', 'twin: the holder fails it; with attempts left it goes back to pending');
select pg_temp.act_as('postgres');
select results_eq($$select status, last_error, (next_attempt_at = now() + interval '1 minute'), locked_by, lock_expires_at from public.notification_deliveries where id = (select c2 from pick)$$, $$select 'pending'::text, 'boom'::text, true, null::text, null::timestamptz$$, 'retry: error kept, next try in 1 minute (backoff for attempt 1), lock cleared');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_notification_deliveries('w1', 100, 60) d where d.id = (select c2 from pick)), 0::bigint, 'it is not claimable before the backoff passes');
select is(public.fail_notification_delivery((select c2 from pick), 'w1', 'again'), null, 'and failing it without holding a claim gets null');
select pg_temp.act_as('postgres');
update public.notification_deliveries set next_attempt_at = now() - interval '1 second' where id = (select c2 from pick);
select pg_temp.act_as('service_role');
insert into claimed select 'w1b', d.id, d.channel, d.attempts from public.claim_notification_deliveries('w1', 100, 60) d where d.id = (select c2 from pick);
select pg_temp.act_as('postgres');
select is((select attempts from public.notification_deliveries where id = (select c2 from pick)), 2, 'once due again it is claimed again: attempt 2');
select pg_temp.act_as('service_role');
select is(public.fail_notification_delivery((select c2 from pick), 'w1', 'permanent problem', true), 'failed', 'a permanent failure goes straight to failed');
select is(public.fail_notification_delivery((select c2 from pick), 'w1', 'again'), null, 'and a failed delivery cannot be failed again (null)');
select is(public.complete_notification_delivery((select c2 from pick), 'w1'), false, 'nor completed');
select pg_temp.act_as('postgres');
select results_eq($$select status, last_error, locked_by from public.notification_deliveries where id = (select c2 from pick)$$, $$select 'failed'::text, 'permanent problem'::text, null::text$$, 'failed with the reason, lock cleared');
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select public.fail_notification_delivery(gen_random_uuid(), 'w1', null)$$), 'ok', 'a null error text is accepted');
select pg_temp.act_as('postgres');
-- a blank error becomes "unknown error", a long one is cut
select pg_temp.act_as('service_role');
select is(public.fail_notification_delivery((select s2 from pick2), 'w2', '   '), 'pending', 'fail with a blank error text');
select pg_temp.act_as('postgres');
select is((select last_error from public.notification_deliveries where id = (select s2 from pick2)), 'unknown error', 'a blank error is stored as "unknown error"');
select pg_temp.act_as('service_role');
select is(public.fail_notification_delivery((select s3 from pick2), 'w2', repeat('e', 2500)), 'pending', 'fail with a 2500 character error');
select pg_temp.act_as('postgres');
select is((select char_length(last_error) from public.notification_deliveries where id = (select s3 from pick2)), 2000, 'it is cut to 2000');
-- skip
select pg_temp.act_as('service_role');
select is(public.skip_notification_delivery((select c3 from pick), 'w2', 'no address'), false, 'skip: the wrong worker cannot skip it');
select is(public.skip_notification_delivery((select c3 from pick), null, 'no address'), false, 'skip: a null worker cannot');
select is(public.skip_notification_delivery((select c3 from pick), 'w1', 'no address'), true, 'twin: the holder skips it');
select is(public.skip_notification_delivery((select c3 from pick), 'w1', 'no address'), false, 'skipping twice is false (final)');
select pg_temp.act_as('postgres');
select results_eq($$select status, last_error, locked_by from public.notification_deliveries where id = (select c3 from pick)$$, $$select 'skipped'::text, 'no address'::text, null::text$$, 'skipped with the reason, lock cleared');
select pg_temp.act_as('service_role');
select is(public.skip_notification_delivery((select s4 from pick2), 'w2', null), true, 'a null skip reason becomes "skipped"');
select pg_temp.act_as('postgres');
select is((select last_error from public.notification_deliveries where id = (select s4 from pick2)), 'skipped', 'stored as "skipped"');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.try($$select public.fail_notification_delivery(gen_random_uuid(), 'w1', 'x')$$), '42501', 'fail: authenticated cannot call it');
select is(pg_temp.try($$select public.skip_notification_delivery(gen_random_uuid(), 'w1', 'x')$$), '42501', 'skip: authenticated cannot call it');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($$select public.fail_notification_delivery(gen_random_uuid(), 'w1', 'x')$$), '42501', 'fail: nor an org admin');
select pg_temp.act_as('anon');
select is(pg_temp.try($$select public.skip_notification_delivery(gen_random_uuid(), 'w1', 'x')$$), '42501', 'skip: nor anon');
select pg_temp.act_as_service('u_staff_a2');
select is(pg_temp.try_msg($$select public.fail_notification_delivery(gen_random_uuid(), 'w1', 'x')$$), '42501 not allowed', 'fail: nor the server key carrying a user JWT');
select is(pg_temp.try_msg($$select public.skip_notification_delivery(gen_random_uuid(), 'w1', 'x')$$), '42501 not allowed', 'skip: nor the server key carrying a user JWT');
select pg_temp.act_as('postgres');

-- attempts run out: after the last attempt a failure is final; an expired lock on the last attempt fails the delivery
-- (take three of w2's still-locked rows)
create temp table pick3 as select (array_agg(id order by id))[1] as m, (array_agg(id order by id))[2] as n, (array_agg(id order by id))[3] as q
from (select id from claimed where w = 'w2' and id not in (select s1 from pick2 union select s2 from pick2 union select s3 from pick2 union select s4 from pick2) order by id limit 3) z;
grant all on pick3 to public;
select is((select count(*) from pick3 where m is not null and n is not null and q is not null), 1::bigint, 'three more claimed rows are available for the attempt-limit tests');
-- m: 4 attempts used, held by w2: a failure still retries; the 5th claim then fails for good
update public.notification_deliveries set attempts = 4 where id = (select m from pick3);
select pg_temp.act_as('service_role');
select is(public.fail_notification_delivery((select m from pick3), 'w2', 'try 4'), 'pending', 'attempt 4 of 5 failing goes back to pending');
select pg_temp.act_as('postgres');
update public.notification_deliveries set next_attempt_at = now() - interval '1 second' where id = (select m from pick3);
select pg_temp.act_as('service_role');
insert into claimed select 'w2c', d.id, d.channel, d.attempts from public.claim_notification_deliveries('w2', 100, 60) d where d.id = (select m from pick3);
select pg_temp.act_as('postgres');
select is((select attempts from public.notification_deliveries where id = (select m from pick3)), 5, 'the next claim is attempt 5');
select pg_temp.act_as('service_role');
select is(public.fail_notification_delivery((select m from pick3), 'w2', 'try 5'), 'failed', 'a failure on the last attempt (5) is final');
select pg_temp.act_as('postgres');
-- n: lock expired on the last attempt: the next claim call fails it instead of claiming it
update public.notification_deliveries set attempts = 5, lock_expires_at = now() - interval '1 second' where id = (select n from pick3);
-- q: lock expired with attempts left: the next claim re-claims it for the new worker
update public.notification_deliveries set attempts = 2, lock_expires_at = now() - interval '1 second' where id = (select q from pick3);
select pg_temp.act_as('service_role');
insert into claimed select 'w3', d.id, d.channel, d.attempts from public.claim_notification_deliveries('w3', 100, 60) d;
select pg_temp.act_as('postgres');
select results_eq($$select status, locked_by, (last_error like '%lock expired on the last attempt%') from public.notification_deliveries where id = (select n from pick3)$$, $$select 'failed'::text, null::text, true$$, 'an expired lock on the last attempt makes the delivery failed (never claimed again)');
select is((select count(*) from claimed where w = 'w3' and id = (select n from pick3)), 0::bigint, 'and it was not handed out');
select results_eq($$select status, locked_by, attempts from public.notification_deliveries where id = (select q from pick3)$$, $$select 'pending'::text, 'w3'::text, 3$$, 'an expired lock with attempts left is re-claimed by the new worker (attempt 3)');
select is((select count(*) from claimed where w = 'w3'), 1::bigint, 'and only that one was handed to w3 (the live locks of other rows were left alone)');
-- the old holder can no longer complete a delivery whose lock was taken over
select pg_temp.act_as('service_role');
select is(public.complete_notification_delivery((select q from pick3), 'w2', 'late'), false, 'the previous holder cannot complete a delivery that was re-claimed by another worker');
select is(public.complete_notification_delivery((select q from pick3), 'w3', 'done'), true, 'twin: the new holder can');
select pg_temp.act_as('postgres');
-- the one with a live lock and pending state is untouched by someone else
select is((select count(*) from public.notification_deliveries d join dl on dl.id = d.id where d.status = 'pending' and d.locked_by = 'w2' and d.lock_expires_at > now()), 0::bigint, 'every w2 claim was accounted for (completed, failed, skipped or re-claimed)');
-- ordering: oldest next_attempt_at first, and the limit
update public.notification_deliveries set status = 'pending', attempts = 0, locked_by = null, lock_expires_at = null, locked_at = null, sent_at = null, next_attempt_at = now() - interval '3 hours'
  where id = (select id from dl where name = 'l1_email');
update public.notification_deliveries set status = 'pending', attempts = 0, locked_by = null, lock_expires_at = null, locked_at = null, sent_at = null, next_attempt_at = now() - interval '2 hours'
  where id = (select id from dl where name = 'l2_email');
update public.notification_deliveries set status = 'pending', attempts = 0, locked_by = null, lock_expires_at = null, locked_at = null, sent_at = null, next_attempt_at = now() - interval '1 hour'
  where id = (select id from dl where name = 'l3_email');
select pg_temp.act_as('service_role');
create temp table ord (id uuid, ord int);
grant all on ord to public;
insert into ord select d.id, row_number() over () from public.claim_notification_deliveries('w4', 2, 60, 'email') d;
select pg_temp.act_as('postgres');
select is((select count(*) from ord), 2::bigint, 'claim honours the limit (2)');
select is((select count(*) from ord where id in ((select id from dl where name = 'l1_email'), (select id from dl where name = 'l2_email'))), 2::bigint, 'and takes the oldest due ones first');
-- disable_push_subscription
select pg_temp.act_as('service_role');
select is(public.disable_push_subscription(pg_temp.id('ps_l')), true, 'disable_push_subscription: the worker disables a gone endpoint');
select is(public.disable_push_subscription(pg_temp.id('ps_l')), false, 'a second call is false');
select is(public.disable_push_subscription(gen_random_uuid()), false, 'an unknown id is false');
select pg_temp.act_as('postgres');
select is((select disabled_at is not null from public.push_subscriptions where id = pg_temp.id('ps_l')), true, 'the device is marked disabled');
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.try($$select public.disable_push_subscription(gen_random_uuid())$$), '42501', 'disable_push_subscription: authenticated cannot call it');
select pg_temp.act_as('anon');
select is(pg_temp.try($$select public.disable_push_subscription(gen_random_uuid())$$), '42501', 'nor anon');
select pg_temp.act_as_service('u_staff_a2');
select is(pg_temp.try_msg($$select public.disable_push_subscription(pg_temp.id('ps_la'))$$), '42501 not allowed', 'nor the server key carrying a user JWT');
select pg_temp.act_as('postgres');
select is((select disabled_at is null from public.push_subscriptions where id = pg_temp.id('ps_b')), true, 'and nothing else was disabled');

select pg_temp.act_as('postgres');
select * from finish();
rollback;
