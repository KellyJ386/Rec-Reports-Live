-- Phase 2 / auth hardening: the admin tier (platform admin, and any assignment whose effective rank is >= 80)
-- counts only when the session JWT says "aal":"aal2". At aal1 (or with no aal claim) those grants behave as if
-- they did not exist: an org admin, a location admin and a platform admin can do nothing admin-tier on any
-- table or function, while managers, staff and custom roles are unaffected. Each denial has an aal2 twin.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(128 + 18 * (select count(*)::int from pg_class c
  where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p') and (c.relname = 'organizations'
    or exists (select 1 from pg_attribute a where a.attrelid = c.oid and a.attname = 'organization_id' and not a.attisdropped))));

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
select pg_temp.id(v.org), pg_temp.id(v.person), 'https://push.example.test/' || v.k, 'BPfixturefixturefixturefixture' || v.k, 'fixtureauth' || v.k
from (values ('a', 'org_a', 'p_staff_a1'), ('b', 'org_b', 'p_staff_b1')) v (k, org, person);
insert into public.notification_preferences (organization_id, person_id, channel, enabled)
select pg_temp.id(v.org), pg_temp.id(v.person), 'email', false from (values ('org_a', 'p_staff_a1'), ('org_b', 'p_staff_b1')) v (org, person);

-- END PHASE 2 ROWS

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

create temp view tt as
  select c.relname from pg_class c
  where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p')
    and (c.relname = 'organizations'
         or exists (select 1 from pg_attribute a where a.attrelid = c.oid and a.attname = 'organization_id' and not a.attisdropped));
grant select on tt to public;

-- A JWT with arbitrary extra claims (to try forged or odd aal values).
create function pg_temp.act_as_claims(p_who text, p_claims jsonb) returns void language plpgsql as $$
begin
  perform set_config('role', 'none', true);
  perform set_config('request.jwt.claims',
    (jsonb_build_object('sub', pg_temp.id(p_who), 'role', 'authenticated') || p_claims)::text, true);
  perform set_config('role', 'authenticated', true);
end $$;
-- val: the result of a scalar expression as text ('null' for NULL), or 'ERR <sqlstate>'.
create function pg_temp.val(p_expr text) returns text language plpgsql as $$
declare v text;
begin
  execute 'select (' || p_expr || ')::text' into v;
  return coalesce(v, 'null');
exception when others then return 'ERR ' || sqlstate;
end $$;
grant execute on function pg_temp.act_as_claims(text, jsonb), pg_temp.val(text) to public;

-- Extra people for this file (owner writes): a mixed user (admin at A1, staff at A2), and rows owned by the org admin.
insert into auth.users (id, email) values (pg_temp.id('u_mixed'), 'mixed@test.invalid');
insert into public.people (id, organization_id, first_name, last_name) values (pg_temp.id('p_mixed'), pg_temp.id('org_a'), 'Max', 'Mixed');
insert into public.accounts (id, organization_id, person_id, user_id) values (pg_temp.id('acct_mixed'), pg_temp.id('org_a'), pg_temp.id('p_mixed'), pg_temp.id('u_mixed'));
insert into public.role_assignments (id, organization_id, person_id, role_id, location_id) values
  (pg_temp.id('ra_mixed_admin'), pg_temp.id('org_a'), pg_temp.id('p_mixed'), pg_temp.sys_role('admin'), pg_temp.id('loc_a1')),
  (pg_temp.id('ra_mixed_staff'), pg_temp.id('org_a'), pg_temp.id('p_mixed'), pg_temp.sys_role('staff'), pg_temp.id('loc_a2'));
-- things that belong to the org admin personally (a message to them, two notifications, a push subscription) and a dead event
insert into public.messages (id, organization_id, sender_person_id, body) values (pg_temp.id('msg_to_oa'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'for the org admin');
insert into public.message_recipients (organization_id, message_id, person_id) values (pg_temp.id('org_a'), pg_temp.id('msg_to_oa'), pg_temp.id('p_orgadmin_a'));
insert into public.notifications (id, organization_id, person_id, kind, title, source_event_id) values
  (pg_temp.id('notif_oa1'), pg_temp.id('org_a'), pg_temp.id('p_orgadmin_a'), 'task.created', 'N1', pg_temp.id('ev_a')),
  (pg_temp.id('notif_oa2'), pg_temp.id('org_a'), pg_temp.id('p_orgadmin_a'), 'task.assigned', 'N2', pg_temp.id('ev_a'));
insert into public.push_subscriptions (organization_id, person_id, endpoint, p256dh, auth_secret)
values (pg_temp.id('org_a'), pg_temp.id('p_orgadmin_a'), 'https://push.example.test/oa', 'BPorgadminorgadminorgadmin', 'orgadminauth');
update public.outbox_events set status = 'dead', attempts = 8 where id = pg_temp.id('ev_a');

-- ===========================================================================
-- 1. session_needs_mfa(): true only for someone holding admin-tier access that is suppressed right now
-- ===========================================================================
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'session_needs_mfa: org admin A at aal1 -> true')
  from (select pg_temp.act_as('u_orgadmin_a', 'aal1')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'session_needs_mfa: org admin A with no aal claim -> true')
  from (select pg_temp.act_as('u_orgadmin_a', 'none')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: org admin A at aal2 -> false')
  from (select pg_temp.act_as('u_orgadmin_a', 'aal2')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'session_needs_mfa: location admin A1 at aal1 -> true')
  from (select pg_temp.act_as('u_locadmin_a1', 'aal1')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: location admin A1 at aal2 -> false')
  from (select pg_temp.act_as('u_locadmin_a1', 'aal2')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'session_needs_mfa: org admin B at aal1 -> true')
  from (select pg_temp.act_as('u_orgadmin_b', 'aal1')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'session_needs_mfa: platform admin at aal1 -> true')
  from (select pg_temp.act_as('u_platform', 'aal1')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'session_needs_mfa: platform admin with no aal claim -> true')
  from (select pg_temp.act_as('u_platform', 'none')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: platform admin at aal2 -> false')
  from (select pg_temp.act_as('u_platform', 'aal2')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: manager A1 at aal1 -> false (not admin tier)')
  from (select pg_temp.act_as('u_manager_a1', 'aal1')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: staff A1 at aal1 -> false')
  from (select pg_temp.act_as('u_staff_a1', 'aal1')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: staff A2 with no aal claim -> false')
  from (select pg_temp.act_as('u_staff_a2', 'none')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: a signed-in user with no account -> false')
  from (select pg_temp.act_as('u_noaccount', 'aal1')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: a disabled admin-less account -> false')
  from (select pg_temp.act_as('u_disabled_a', 'aal1')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'session_needs_mfa: admin at one location and staff at another, at aal1 -> true')
  from (select pg_temp.act_as('u_mixed', 'aal1')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: the same mixed user at aal2 -> false')
  from (select pg_temp.act_as('u_mixed', 'aal2')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: service_role with no user -> false')
  from (select pg_temp.act_as('service_role')) s;
select is(pg_temp.try('select public.session_needs_mfa()'), '42501', 'session_needs_mfa: anon cannot call it')
  from (select pg_temp.act_as('anon')) s;
-- a disabled or archived grant does not make "needs mfa" true: disable the org admin's account, then ask.
select pg_temp.act_as('postgres');
update public.accounts set disabled_at = now() where id = pg_temp.id('acct_orgadmin_b');
select is(pg_temp.val('public.session_needs_mfa()'), 'false', 'session_needs_mfa: an org admin whose account is disabled -> false')
  from (select pg_temp.act_as('u_orgadmin_b', 'aal1')) s;
select pg_temp.act_as('postgres');
update public.accounts set disabled_at = null where id = pg_temp.id('acct_orgadmin_b');

-- ===========================================================================
-- 2. An aal claim that is not exactly "aal2" does not count
-- ===========================================================================
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'org admin: aal claim "AAL2" (wrong case) does not count')
  from (select pg_temp.act_as_claims('u_orgadmin_a', '{"aal":"AAL2"}')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'org admin: aal claim "aal3" does not count')
  from (select pg_temp.act_as_claims('u_orgadmin_a', '{"aal":"aal3"}')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'org admin: aal claim "" does not count')
  from (select pg_temp.act_as_claims('u_orgadmin_a', '{"aal":""}')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'org admin: aal claim null does not count')
  from (select pg_temp.act_as_claims('u_orgadmin_a', '{"aal":null}')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'org admin: aal claim as a number does not count')
  from (select pg_temp.act_as_claims('u_orgadmin_a', '{"aal":2}')) s;
select is(pg_temp.val('public.session_needs_mfa()'), 'true', 'org admin: "aal2" planted in user_metadata (which a user can edit) does not count')
  from (select pg_temp.act_as_claims('u_orgadmin_a', '{"user_metadata":{"aal":"aal2"},"app_metadata":{"aal":"aal2"}}')) s;
select is(pg_temp.val('public.is_platform_admin()'), 'false', 'platform admin: aal "aal1" is not a platform admin')
  from (select pg_temp.act_as_claims('u_platform', '{"aal":"aal1"}')) s;
select is(pg_temp.val('public.is_platform_admin()'), 'true', 'platform admin: aal "aal2" with other claims present is a platform admin')
  from (select pg_temp.act_as_claims('u_platform', '{"aal":"aal2","amr":[{"method":"totp","timestamp":1}]}')) s;

-- ===========================================================================
-- 3. At aal1 an org admin, a location admin and a platform admin do nothing admin-tier on ANY table
--    (generated from the catalog), with the aal2 twin proving the actors and rows are real.
-- ===========================================================================
select pg_temp.act_as('postgres');
-- Non-vacuity: org A has rows in every tenant table.
select cmp_ok(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), '>', 0::bigint, 'fixture: org A has rows in ' || t.relname) from pg_temp.tt t order by t.relname;

-- Org admin A at aal1: nothing readable, nothing writable.
select pg_temp.act_as('u_orgadmin_a', 'aal1');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), 0::bigint, 'org admin A at aal1 reads no org A rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select is(pg_temp.try_insert(t.relname, pg_temp.id('org_a')), '42501', 'org admin A at aal1 cannot insert into ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.upd(t.relname, pg_temp.id('org_a')), '<=', 0::bigint, 'org admin A at aal1 updates nothing in ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.affected(format('delete from public.%I where %s', t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a')))), '<=', 0::bigint,
  'org admin A at aal1 deletes nothing from ' || t.relname) from pg_temp.tt t order by t.relname;

-- Location admin A1 at aal1.
select pg_temp.act_as('u_locadmin_a1', 'aal1');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), 0::bigint, 'location admin A1 at aal1 reads no org A rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select is(pg_temp.try_insert(t.relname, pg_temp.id('org_a')), '42501', 'location admin A1 at aal1 cannot insert into ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.upd(t.relname, pg_temp.id('org_a')), '<=', 0::bigint, 'location admin A1 at aal1 updates nothing in ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.affected(format('delete from public.%I where %s', t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a')))), '<=', 0::bigint,
  'location admin A1 at aal1 deletes nothing from ' || t.relname) from pg_temp.tt t order by t.relname;

-- Platform admin at aal1.
select pg_temp.act_as('u_platform', 'aal1');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), 0::bigint, 'platform admin at aal1 reads no org A rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select is(pg_temp.try_insert(t.relname, pg_temp.id('org_a')), '42501', 'platform admin at aal1 cannot insert into ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.upd(t.relname, pg_temp.id('org_a')), '<=', 0::bigint, 'platform admin at aal1 updates nothing in ' || t.relname) from pg_temp.tt t order by t.relname;
select cmp_ok(pg_temp.affected(format('delete from public.%I where %s', t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a')))), '<=', 0::bigint,
  'platform admin at aal1 deletes nothing from ' || t.relname) from pg_temp.tt t order by t.relname;

-- No aal claim at all behaves the same (reads and inserts).
select pg_temp.act_as('u_orgadmin_a', 'none');
select is(pg_temp.cnt(t.relname, pg_temp.orgf(t.relname, pg_temp.id('org_a'))), 0::bigint, 'org admin A with no aal claim reads no org A rows in ' || t.relname) from pg_temp.tt t order by t.relname;
select is(pg_temp.try_insert(t.relname, pg_temp.id('org_a')), '42501', 'org admin A with no aal claim cannot insert into ' || t.relname) from pg_temp.tt t order by t.relname;

-- Managers and staff are unaffected: the same rows at aal1 as at aal2.
create temp table cnts (actor text, aal text, relname text, n bigint);
grant all on cnts to public;
select pg_temp.act_as('u_manager_a1', 'aal2');
insert into cnts select 'u_manager_a1', 'aal2', t.relname, pg_temp.cnt(t.relname) from pg_temp.tt t;
select pg_temp.act_as('u_manager_a1', 'aal1');
insert into cnts select 'u_manager_a1', 'aal1', t.relname, pg_temp.cnt(t.relname) from pg_temp.tt t;
select pg_temp.act_as('u_staff_a1', 'aal2');
insert into cnts select 'u_staff_a1', 'aal2', t.relname, pg_temp.cnt(t.relname) from pg_temp.tt t;
select pg_temp.act_as('u_staff_a1', 'none');
insert into cnts select 'u_staff_a1', 'aal1', t.relname, pg_temp.cnt(t.relname) from pg_temp.tt t;
select pg_temp.act_as('u_mixed', 'aal1');
insert into cnts select 'u_mixed', 'aal1', t.relname, pg_temp.cnt(t.relname) from pg_temp.tt t;
select pg_temp.act_as('u_staff_a2', 'aal2');
insert into cnts select 'u_staff_a2', 'aal2', t.relname, pg_temp.cnt(t.relname) from pg_temp.tt t;
select pg_temp.act_as('postgres');
select is((select n from cnts where actor = 'u_mixed' and aal = 'aal1' and relname = t.relname),
          (select n from cnts where actor = 'u_staff_a2' and aal = 'aal2' and relname = t.relname),
          'the admin-at-A1 / staff-at-A2 user at aal1 sees exactly as many rows of ' || t.relname || ' as a plain staff A2 user') from pg_temp.tt t order by t.relname;
select is((select n from cnts where actor = 'u_manager_a1' and aal = 'aal1' and relname = t.relname),
          (select n from cnts where actor = 'u_manager_a1' and aal = 'aal2' and relname = t.relname),
          'manager A1 sees the same rows of ' || t.relname || ' at aal1 and aal2') from pg_temp.tt t order by t.relname;
select is((select n from cnts where actor = 'u_staff_a1' and aal = 'aal1' and relname = t.relname),
          (select n from cnts where actor = 'u_staff_a1' and aal = 'aal2' and relname = t.relname),
          'staff A1 sees the same rows of ' || t.relname || ' with no aal claim as at aal2') from pg_temp.tt t order by t.relname;
select cmp_ok((select sum(n) from cnts where actor = 'u_manager_a1' and aal = 'aal1'), '>', 20::numeric, 'manager A1 at aal1 really reads rows (the comparison above is not 0 = 0)');

-- ===========================================================================
-- 4. A user who is admin at one location and staff at another keeps exactly the staff access at aal1
-- ===========================================================================
select pg_temp.act_as('u_mixed', 'aal1');
select is((select array_agg(l order by l) from public.auth_location_ids() l), array[pg_temp.id('loc_a2')], 'mixed user at aal1: locations are only A2 (the staff location)');
select pg_temp.act_as('u_mixed', 'aal2');
select is((select array_agg(l order by l) from public.auth_location_ids() l), (select array_agg(x order by x) from unnest(array[pg_temp.id('loc_a1'), pg_temp.id('loc_a2')]) x), 'mixed user at aal2: locations are A1 and A2');
select pg_temp.act_as('u_mixed', 'aal1');
select is((select string_agg(m.key || '=' || public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), m.key), ',' order by m.key) from public.modules m),
  (select string_agg(m.key || '=' || public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), m.key), ',' order by m.key)
     from (select pg_temp.act_as('u_staff_a2', 'aal1')) s, public.modules m),
  'mixed user at aal1: permission at A2 on every module is exactly what staff A2 has')
  where (select pg_temp.act_as('u_mixed', 'aal1')) is not null;
select pg_temp.act_as('u_mixed', 'aal1');
select isnt((select string_agg(public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), m.key)::text, ',') from public.modules m),
            null, 'mixed user at aal1: A2 permissions are readable (not null)');
select is((select string_agg(distinct public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), m.key)::text, ',') from public.modules m), 'none',
  'mixed user at aal1: no permission at all at A1 (their admin role there is suppressed)');
select is(public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'admin'), false, 'mixed user at aal1: not admin at A1');
select is(public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'staff'), true, 'mixed user at aal1: still staff at A2');
select is(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks', 'view'), false, 'mixed user at aal1: no tasks access at A1');
select is(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'tasks', 'edit'), true, 'mixed user at aal1: tasks edit at A2 (staff default)');
select is(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'tasks', 'admin'), false, 'mixed user at aal1: no tasks admin at A2');
select cmp_ok(pg_temp.cnt('spaces', format('location_id = %L', pg_temp.id('loc_a2'))), '>', 0::bigint, 'mixed user at aal1: sees the spaces at A2');
select is(pg_temp.val($$public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Mixed at A1')$$), 'ERR 42501', 'mixed user at aal1: cannot create a task at A1');
select matches(pg_temp.val($$public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'Mixed at A2')$$), '^[0-9a-f-]{36}$', 'mixed user at aal1: can create a task at A2 (staff)');
select is(pg_temp.val($$public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'Mixed for other', null, null, 'normal', null, pg_temp.id('p_staff_a2'))$$), 'ERR 42501',
  'mixed user at aal1: cannot assign a task to someone else at A2 (staff cannot)');
select pg_temp.act_as('u_mixed', 'aal2');
select is(public.has_role(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'admin'), true, 'twin, mixed user at aal2: admin at A1');
select is(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks', 'admin'), true, 'twin, mixed user at aal2: tasks admin at A1');
select is(public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'tasks', 'admin'), false, 'twin, mixed user at aal2: the admin role at A1 does not reach A2');
select matches(pg_temp.val($$public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Mixed at A1 aal2')$$), '^[0-9a-f-]{36}$', 'twin, mixed user at aal2: can create a task at A1');
select cmp_ok(pg_temp.cnt('spaces', format('location_id = %L', pg_temp.id('loc_a1'))), '>', 0::bigint, 'twin, mixed user at aal2: sees the spaces at A1');
select is(pg_temp.cnt('people', format('organization_id = %L', pg_temp.id('org_a'))), (select count(*) from public.people where organization_id = pg_temp.id('org_a')) , 'twin sanity: people count readable at aal2');

-- ===========================================================================
-- 5. Every authenticated-callable function, as an org admin: refused or empty at aal1, works at aal2.
-- ===========================================================================
select pg_temp.act_as('postgres');
create temp table cases (n int primary key, fn text, expr text, e1 text, e2 text);
grant all on cases to public;
insert into cases values
  (1,  'session_needs_mfa',            $$public.session_needs_mfa()$$, '^true$', '^false$'),
  (2,  'is_platform_admin',            $$public.is_platform_admin()$$, '^false$', '^false$'),
  (3,  'auth_org_ids',                 $$(select count(*) from public.auth_org_ids())$$, '^0$', '^1$'),
  (4,  'auth_location_ids',            $$(select count(*) from public.auth_location_ids())$$, '^0$', '^2$'),
  (5,  'current_person_id',            $$public.current_person_id(pg_temp.id('org_a')) = pg_temp.id('p_orgadmin_a')$$, '^true$', '^true$'),
  (6,  'has_role',                     $$public.has_role(pg_temp.id('org_a'), null, 'admin')$$, '^false$', '^true$'),
  (7,  'actor_rank',                   $$public.actor_rank(pg_temp.id('org_a'), null)$$, '^0$', '^90$'),
  (8,  'effective_permission',         $$public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks')$$, '^none$', '^admin$'),
  (9,  'has_permission',               $$public.has_permission(pg_temp.id('org_a'), null, 'tasks', 'admin')$$, '^false$', '^true$'),
  (10, 'person_effective_permission',  $$public.person_effective_permission(pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), pg_temp.id('loc_a1'), 'tasks')$$, '^ERR 42501$', '^edit$'),
  (11, 'can_manage_person_account',    $$public.can_manage_person_account(pg_temp.id('org_a'), pg_temp.id('p_unassigned_a'))$$, '^false$', '^true$'),
  (12, 'create_person_with_assignment',$$public.create_person_with_assignment(pg_temp.id('org_a'), 'Nia', 'New', pg_temp.sys_role('staff'), pg_temp.id('loc_a1'))$$, '^ERR 42501$', '^[0-9a-f-]{36}$'),
  (13, 'update_own_profile',           $$public.update_own_profile(pg_temp.id('org_a'), 'Ollie', null)$$, '^ERR 42501$', '^[0-9a-f-]{36}$'),
  (14, 'replace_role_assignment',      $$public.replace_role_assignment(pg_temp.id('ra_staff_a1'), pg_temp.sys_role('manager'), pg_temp.id('loc_a1'))$$, '^ERR 42501$', '^[0-9a-f-]{36}$'),
  (15, 'retry_dead_outbox_event',      $$public.retry_dead_outbox_event(pg_temp.id('ev_a'))$$, '^ERR 42501$', '^$'),
  (16, 'create_task',                  $$public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Admin task')$$, '^ERR 42501$', '^[0-9a-f-]{36}$'),
  (17, 'start_task',                   $$public.start_task(pg_temp.id('task_a'))$$, '^ERR 42501$', '^$'),
  (18, 'add_task_comment',             $$public.add_task_comment(pg_temp.id('task_a'), 'a comment')$$, '^ERR 42501$', '^[0-9a-f-]{36}$'),
  (19, 'complete_task',                $$public.complete_task(pg_temp.id('task_a'))$$, '^ERR 42501$', '^$'),
  (20, 'reopen_task',                  $$public.reopen_task(pg_temp.id('task_a'))$$, '^ERR 42501$', '^$'),
  (21, 'assign_task',                  $$public.assign_task(pg_temp.id('task_a'), pg_temp.id('p_manager_a1'), null)$$, '^ERR 42501$', '^$'),
  (22, 'cancel_task',                  $$public.cancel_task(pg_temp.id('task_a'))$$, '^ERR 42501$', '^$'),
  (23, 'publish_notice',               $$public.publish_notice(pg_temp.id('notice_a'))$$, '^ERR 42501$', '^$'),
  (24, 'acknowledge_notice',           $$public.acknowledge_notice(pg_temp.id('notice_a'))$$, '^ERR 42501$', '^20'),
  (25, 'archive_notice',               $$public.archive_notice(pg_temp.id('notice_a'))$$, '^ERR 42501$', '^$'),
  (26, 'send_message',                 $$public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_manager_a1')], 'hello')$$, '^ERR 42501$', '^[0-9a-f-]{36}$'),
  (27, 'mark_message_read',            $$public.mark_message_read(pg_temp.id('msg_to_oa'))$$, '^ERR 42501$', '^$'),
  (28, 'mark_notifications_read',      $$public.mark_notifications_read(array[pg_temp.id('notif_oa1')])$$, '^0$', '^1$'),
  (29, 'mark_all_notifications_read',  $$public.mark_all_notifications_read(pg_temp.id('org_a'))$$, '^0$', '^1$'),
  (30, 'save_push_subscription',       $$public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/oa2', 'BPorgadminorgadminorgadmin2', 'orgadminauth2')$$, '^ERR 42501$', '^[0-9a-f-]{36}$'),
  (31, 'delete_push_subscription',     $$public.delete_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/oa')$$, '^false$', '^true$');

-- Every function a signed-in user can call through /rpc is in the table above (a new one must be added on purpose).
select is((select coalesce(string_agg(p.proname, ', ' order by p.proname), '') from pg_proc p
           where p.pronamespace = 'public'::regnamespace and p.prosecdef and has_function_privilege('authenticated', p.oid, 'execute')
             and p.proname not in (select fn from cases)),
  '', 'every authenticated-callable function is covered by the aal1/aal2 matrix');
select is((select coalesce(string_agg(c.fn, ', '), '') from cases c
           where not exists (select 1 from pg_proc p where p.pronamespace = 'public'::regnamespace and p.proname = c.fn
                             and has_function_privilege('authenticated', p.oid, 'execute'))),
  '', 'the aal1/aal2 matrix has no stale entries');

select pg_temp.act_as('u_orgadmin_a', 'aal1');
select matches(pg_temp.val(c.expr), c.e1, 'org admin A at aal1: ' || c.fn || ' -> ' || c.e1)
  from (select * from cases order by n offset 0) c;
select pg_temp.act_as('postgres');
-- No call at aal1 changed anything (the same notification is still unread, the task untouched).
select is((select count(*) from public.notifications where id in (pg_temp.id('notif_oa1'), pg_temp.id('notif_oa2')) and read_at is null), 2::bigint, 'the aal1 attempts marked nothing read');
select is((select status from public.tasks where id = pg_temp.id('task_a')), 'open', 'the aal1 attempts left the task open');
select is((select status from public.notices where id = pg_temp.id('notice_a')), 'draft', 'the aal1 attempts left the notice a draft');
select is((select status from public.outbox_events where id = pg_temp.id('ev_a')), 'dead', 'the aal1 attempts left the dead event dead');
select is((select count(*) from public.people where organization_id = pg_temp.id('org_a') and first_name = 'Nia'), 0::bigint, 'the aal1 attempts created no person');

select pg_temp.act_as('u_orgadmin_a', 'aal2');
select matches(pg_temp.val(c.expr), c.e2, 'twin, org admin A at aal2: ' || c.fn || ' -> ' || c.e2)
  from (select * from cases order by n offset 0) c;

-- Platform admin: same story for the platform shortcut.
select pg_temp.act_as('u_platform', 'aal1');
select is(pg_temp.val('public.is_platform_admin()'), 'false', 'platform admin at aal1: is_platform_admin() is false');
select is(pg_temp.val($$public.has_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks', 'view')$$), 'false', 'platform admin at aal1: no permission anywhere');
select is(pg_temp.val($$public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks')$$), 'none', 'platform admin at aal1: effective permission is none');
select is(pg_temp.val($$public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Platform task')$$), 'ERR 42501', 'platform admin at aal1: cannot create a task');
select is(pg_temp.val($$public.retry_dead_outbox_event(pg_temp.id('ev_a'))$$), 'ERR 42501', 'platform admin at aal1: cannot retry a dead event');
select is(pg_temp.val($$public.publish_notice(pg_temp.id('notice_a'))$$), 'ERR 42501', 'platform admin at aal1: cannot publish a notice');
select pg_temp.act_as('u_platform', 'aal2');
select is(pg_temp.val('public.is_platform_admin()'), 'true', 'twin, platform admin at aal2: is_platform_admin() is true');
select is(pg_temp.val($$public.effective_permission(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'tasks')$$), 'admin', 'twin, platform admin at aal2: effective permission is admin');
select matches(pg_temp.val($$public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Platform task')$$), '^[0-9a-f-]{36}$', 'twin, platform admin at aal2: can create a task');

-- The same org admin at aal1 cannot reach what only the admin tier can see, at aal2 can: audit log and people.
select pg_temp.act_as('u_orgadmin_a', 'aal1');
select is(pg_temp.cnt('audit_log'), 0::bigint, 'org admin A at aal1 reads no audit log rows');
select pg_temp.act_as('u_orgadmin_a', 'aal2');
select cmp_ok(pg_temp.cnt('audit_log'), '>', 0::bigint, 'twin: org admin A at aal2 reads audit log rows');

select pg_temp.act_as('postgres');
select * from finish();
rollback;
