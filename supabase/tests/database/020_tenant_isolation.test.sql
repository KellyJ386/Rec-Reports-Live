-- Tenant isolation, generated per tenant table (every public table with
-- organization_id, plus organizations): a user of org A reads nothing of org B and
-- cannot insert, update or delete its rows, and org B's admin likewise against A.
-- The tables come from the catalog, so a table added later is covered automatically
-- (and fails the non-vacuity check until the fixture gives it rows in both orgs).
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(46 + 30 * (select count(*)::int from pg_class c
  where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') and (c.relname = 'organizations'
    or exists (select 1 from pg_attribute a where a.attrelid = c.oid and a.attname = 'organization_id' and not a.attisdropped)))
  + (select count(*)::int from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p')));

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
-- Tables that are private by design: only the person they belong to (sender/recipient/owner) reads them.
-- No role of the organization (not even an organization admin) and no platform admin can.
create temp view private_tt as
  select t.relname from (values ('messages'), ('message_recipients'), ('notifications'), ('notification_deliveries'),
                                ('push_subscriptions'), ('notification_preferences')) t (relname);
grant select on private_tt to public;

-- Tenant tables, readable by every role through a temp view.
create temp view tt as
  select c.relname from pg_class c
  where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p')
    and (c.relname = 'organizations'
         or exists (select 1 from pg_attribute a where a.attrelid = c.oid and a.attname = 'organization_id' and not a.attisdropped));
grant select on tt to public;

-- BEGIN GENERIC HELPERS: byte-identical in every file that uses them (020, 090).
-- where-clause selecting one organization's rows (organizations has no organization_id: its id is the org)
create function pg_temp.orgf(p_table text, p_org uuid) returns text language sql immutable as $$
  select (case when p_table = 'organizations' then 'id' else 'organization_id' end) || ' = ' || quote_literal(p_org)
$$;
-- one row of an organization, as json, read with the owner's rights (so a user can try to copy another org's row)
create function pg_temp.clone_of(p_table text, p_org uuid) returns jsonb language plpgsql security definer set search_path = '' as $$
declare r jsonb;
begin
  execute format('select to_jsonb(x) from public.%I x where %s limit 1', p_table, pg_temp.orgf(p_table, p_org)) into r;
  return r;
end $$;
-- Try to insert a copy (fresh id) of an organization's row; 'ok' or the SQLSTATE. RLS/grants decide before unique checks.
create function pg_temp.try_insert(p_table text, p_org uuid) returns text language plpgsql as $$
declare j jsonb := pg_temp.clone_of(p_table, p_org); cols text;
begin
  if (j ->> 'id') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
    j := jsonb_set(j, '{id}', to_jsonb(gen_random_uuid()));
  end if;
  -- all columns except generated-always identity ones (audit_log.id), which would fail before any privilege check
  select string_agg(quote_ident(a.attname), ', ' order by a.attnum) into cols from pg_attribute a
  where a.attrelid = ('public.' || quote_ident(p_table))::regclass and a.attnum > 0 and not a.attisdropped and a.attidentity <> 'a';
  execute format('insert into public.%I (%s) select %s from jsonb_populate_record(null::public.%I, $1)', p_table, cols, cols, p_table) using j;
  return 'ok';
exception when others then return sqlstate;
end $$;
-- Update the first column the current role may update to itself, on one organization's rows. Rows changed, or -1 (no privilege).
create function pg_temp.upd(p_table text, p_org uuid) returns bigint language plpgsql as $$
declare c text; n bigint;
begin
  select a.attname into c from pg_attribute a
  where a.attrelid = ('public.' || quote_ident(p_table))::regclass and a.attnum > 0 and not a.attisdropped
    and has_column_privilege(current_user, a.attrelid, a.attnum, 'update')
  order by a.attnum limit 1;
  if c is null then return -1; end if;
  execute format('update public.%I set %I = %I where %s', p_table, c, c, pg_temp.orgf(p_table, p_org));
  get diagnostics n = row_count;
  return n;
exception when insufficient_privilege then return -1;
end $$;
create function pg_temp.table_hash(p_table text) returns text language plpgsql as $f$
declare h text;
begin
  execute format('select md5(coalesce(string_agg(to_jsonb(x)::text, '','' order by to_jsonb(x)::text), '''')) from public.%I x', p_table) into h;
  return h;
end $f$;
-- try_msg: 'ok', or 'SQLSTATE message' (to prove two refusals are word for word the same).
create function pg_temp.try_msg(p_sql text) returns text language plpgsql as $$
begin
  execute p_sql;
  return 'ok';
exception when others then return sqlstate || ' ' || sqlerrm;
end $$;
grant execute on function pg_temp.orgf(text, uuid), pg_temp.clone_of(text, uuid), pg_temp.try_insert(text, uuid),
  pg_temp.upd(text, uuid), pg_temp.table_hash(text), pg_temp.try_msg(text) to public;
-- END GENERIC HELPERS
-- Snapshot of every table, to prove denied writes changed nothing.
create temp table snap as
  select c.relname, pg_temp.table_hash(c.relname) as h from pg_class c
  where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p');

-- Non-vacuity: both organizations have rows in every tenant table, so a deny test cannot pass on an empty table.
select cmp_ok(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), '>', 0::bigint, 'fixture: org A has rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b'))), '>', 0::bigint, 'fixture: org B has rows in ' || t.relname) from pg_temp.tt t order by t.relname;

-- org admin A against org B
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b'))), 0::bigint, 'org admin A reads no org B rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select is(pg_temp.try_insert(t.relname, pg_temp.id('org_b')), '42501', 'org admin A cannot insert an org B row into ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.upd(t.relname, pg_temp.id('org_b')), '<=', 0::bigint, 'org admin A updates no org B rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.affected(format('delete from public.%I where %s', t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b')))), '<=', 0::bigint,
  'org admin A deletes no org B rows from ' || t.relname) from pg_temp.tt t order by t.relname;

-- location admin A1 against org B
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b'))), 0::bigint, 'location admin A1 reads no org B rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select is(pg_temp.try_insert(t.relname, pg_temp.id('org_b')), '42501', 'location admin A1 cannot insert an org B row into ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.upd(t.relname, pg_temp.id('org_b')), '<=', 0::bigint, 'location admin A1 updates no org B rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.affected(format('delete from public.%I where %s', t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b')))), '<=', 0::bigint,
  'location admin A1 deletes no org B rows from ' || t.relname) from pg_temp.tt t order by t.relname;

-- manager A1 against org B
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b'))), 0::bigint, 'manager A1 reads no org B rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select is(pg_temp.try_insert(t.relname, pg_temp.id('org_b')), '42501', 'manager A1 cannot insert an org B row into ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.upd(t.relname, pg_temp.id('org_b')), '<=', 0::bigint, 'manager A1 updates no org B rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.affected(format('delete from public.%I where %s', t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b')))), '<=', 0::bigint,
  'manager A1 deletes no org B rows from ' || t.relname) from pg_temp.tt t order by t.relname;

-- staff A1 against org B
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b'))), 0::bigint, 'staff A1 reads no org B rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select is(pg_temp.try_insert(t.relname, pg_temp.id('org_b')), '42501', 'staff A1 cannot insert an org B row into ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.upd(t.relname, pg_temp.id('org_b')), '<=', 0::bigint, 'staff A1 updates no org B rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.affected(format('delete from public.%I where %s', t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b')))), '<=', 0::bigint,
  'staff A1 deletes no org B rows from ' || t.relname) from pg_temp.tt t order by t.relname;

-- staff A2 against org B
select pg_temp.act_as('u_staff_a2');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b'))), 0::bigint, 'staff A2 reads no org B rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select is(pg_temp.try_insert(t.relname, pg_temp.id('org_b')), '42501', 'staff A2 cannot insert an org B row into ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.upd(t.relname, pg_temp.id('org_b')), '<=', 0::bigint, 'staff A2 updates no org B rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.affected(format('delete from public.%I where %s', t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b')))), '<=', 0::bigint,
  'staff A2 deletes no org B rows from ' || t.relname) from pg_temp.tt t order by t.relname;

-- org admin B against org A
select pg_temp.act_as('u_orgadmin_b');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), 0::bigint, 'org admin B reads no org A rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select is(pg_temp.try_insert(t.relname, pg_temp.id('org_a')), '42501', 'org admin B cannot insert an org A row into ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.upd(t.relname, pg_temp.id('org_a')), '<=', 0::bigint, 'org admin B updates no org A rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.affected(format('delete from public.%I where %s', t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a')))), '<=', 0::bigint,
  'org admin B deletes no org A rows from ' || t.relname) from pg_temp.tt t order by t.relname;

-- Nothing changed anywhere while those writes were attempted.
select pg_temp.act_as('postgres');
select is(pg_temp.table_hash(c.relname), (select h from pg_temp.snap s where s.relname = c.relname), c.relname || ' is unchanged after every denied write')
from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') order by c.relname;

-- Positive paths: each org admin reads and updates their own organization, so the
-- deny tests above cannot be passing because the fixture or the actors are broken.

select pg_temp.act_as('u_orgadmin_a');
select cmp_ok(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), '>', 0::bigint, 'org admin A reads org A rows in ' || t.relname) from pg_temp.tt t where t.relname not in (select relname from pg_temp.private_tt) order by t.relname;
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), 0::bigint, 'org admin A reads no org A rows in ' || t.relname || ' (private by design)') from pg_temp.private_tt t order by t.relname;
select cmp_ok(pg_temp.upd(t, pg_temp.id('org_a')), '>', 0::bigint, 'org admin A can update org A rows in ' || t) from (values ('organizations'),('organization_settings'),('locations'),('space_kinds'),('spaces'),('space_hours'),('space_closures'),('roles'),('role_default_permissions'),('people'),('accounts'),('user_permissions'),('job_titles'),('task_templates'),('workflow_rules'),('notices')) v (t) order by t;

select pg_temp.act_as('u_orgadmin_b');
select cmp_ok(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b'))), '>', 0::bigint, 'org admin B reads org B rows in ' || t.relname) from pg_temp.tt t where t.relname not in (select relname from pg_temp.private_tt) order by t.relname;
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b'))), 0::bigint, 'org admin B reads no org B rows in ' || t.relname || ' (private by design)') from pg_temp.private_tt t order by t.relname;
select cmp_ok(pg_temp.upd(t, pg_temp.id('org_b')), '>', 0::bigint, 'org admin B can update org B rows in ' || t) from (values ('organizations'),('organization_settings'),('locations'),('space_kinds'),('spaces'),('space_hours'),('space_closures'),('roles'),('role_default_permissions'),('people'),('accounts'),('user_permissions'),('job_titles'),('task_templates'),('workflow_rules'),('notices')) v (t) order by t;

select pg_temp.act_as('u_platform');
select cmp_ok(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), '>', 0::bigint, 'platform admin reads org A rows in ' || t.relname) from pg_temp.tt t where t.relname not in (select relname from pg_temp.private_tt) order by t.relname;
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), 0::bigint, 'platform admin reads no org A rows in ' || t.relname || ' (private by design)') from pg_temp.private_tt t order by t.relname;
select cmp_ok(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b'))), '>', 0::bigint, 'platform admin reads org B rows in ' || t.relname) from pg_temp.tt t where t.relname not in (select relname from pg_temp.private_tt) order by t.relname;
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_b'))), 0::bigint, 'platform admin reads no org B rows in ' || t.relname || ' (private by design)') from pg_temp.private_tt t order by t.relname;

-- Private by design, with allowed twins: the people the rows belong to read them; admins do not.
select pg_temp.act_as('u_locadmin_a1');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), 0::bigint, 'location admin A1 reads no org A rows in ' || t.relname || ' (private by design)') from pg_temp.private_tt t order by t.relname;
select pg_temp.act_as('u_staff_a1');
select cmp_ok(pg_temp.cnt(t, 'true'), '=', 1::bigint, 'staff A1 reads their own row in ' || t) from (values ('messages'),('message_recipients'),('notifications'),('notification_deliveries'),('push_subscriptions'),('notification_preferences')) v (t) order by t;
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.cnt('messages'), 1::bigint, 'manager A1 reads the message they received');
select is(pg_temp.cnt('message_recipients'), 1::bigint, 'manager A1 reads their own recipient row');

select pg_temp.act_as('postgres');
select * from finish();
rollback;
