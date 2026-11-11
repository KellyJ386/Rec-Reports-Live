-- Phase 2 / audit redaction: the audit log must never become a way to read messages, notice and task text, notification
-- content, push endpoints and keys, or delivery and event errors. Each literal below is written through the real paths
-- (as a user, as the worker, as the owner), updated and deleted, and must then appear nowhere in audit_log. Title columns
-- are NOT redacted by design (tasks, task templates and notices show them in the log); a twin proves the detector works.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(80);

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
-- How many audit rows (any column, any side of the change) contain this literal?
create function pg_temp.leaks(p_literal text) returns bigint language sql stable as $$
  select count(*) from public.audit_log a
  where a.old_row::text like '%' || p_literal || '%' or a.new_row::text like '%' || p_literal || '%'
     or a.row_id like '%' || p_literal || '%' or array_to_string(a.changed_columns, ',') like '%' || p_literal || '%'
$$;
grant execute on function pg_temp.leaks(text) to public;
create temp table evs (name text primary key, id uuid not null);
grant all on evs to public;

-- ===========================================================================
-- 1. Catalog: the redaction list of every Phase 2 audit trigger, and every text column accounted for
-- ===========================================================================
create temp table redact_expect (tbl text, col text);
insert into redact_expect values
  ('outbox_events', 'last_error'),
  ('task_templates', 'instructions'), ('tasks', 'instructions'), ('task_events', 'body'),
  ('notices', 'body'), ('messages', 'body'),
  ('notifications', 'title'), ('notifications', 'body'), ('notifications', 'link_path'),
  ('notification_deliveries', 'last_error'), ('notification_deliveries', 'provider_message_id'),
  ('push_subscriptions', 'endpoint'), ('push_subscriptions', 'p256dh'), ('push_subscriptions', 'auth_secret'), ('push_subscriptions', 'user_agent');
-- columns of the audited Phase 2 tables that hold short structural text and may appear in the log, each with its reason
create temp table text_ok (tbl text, col text, why text);
insert into text_ok values
  ('notices', 'title', 'a headline, visible in the log by design (the body is redacted)'),
  ('notices', 'status', 'enum'), ('notices', 'urgency', 'enum'),
  ('tasks', 'title', 'a headline, visible in the log by design (the instructions are redacted)'),
  ('tasks', 'status', 'enum'), ('tasks', 'priority', 'enum'),
  ('task_templates', 'title', 'a headline, visible in the log by design'), ('task_templates', 'assign_to', 'enum'), ('task_templates', 'default_priority', 'enum'),
  ('task_events', 'kind', 'enum'), ('task_events', 'from_status', 'enum'), ('task_events', 'to_status', 'enum'),
  ('workflow_rules', 'name', 'a configuration label'), ('workflow_rules', 'event_type', 'an event type'), ('workflow_rules', 'condition', 'rule configuration (field/op/value), not user content'),
  ('outbox_events', 'type', 'an event type'), ('outbox_events', 'entity_table', 'a table name'), ('outbox_events', 'status', 'enum'),
  ('outbox_events', 'locked_by', 'a worker name'), ('outbox_events', 'payload', 'a flat object of ids and flags (enforced by validate_event_payload and its CHECK)'),
  ('outbox_event_handlers', 'handler', 'a handler name'),
  ('notifications', 'kind', 'an event kind'), ('notifications', 'source_table', 'a table name'), ('notifications', 'urgency', 'enum'),
  ('notification_deliveries', 'channel', 'enum'), ('notification_deliveries', 'status', 'enum'), ('notification_deliveries', 'locked_by', 'a worker name'),
  ('notification_preferences', 'channel', 'enum');
create temp table p2_tables as
  select t as tbl from unnest(array['outbox_events', 'outbox_event_handlers', 'task_templates', 'workflow_rules', 'tasks', 'task_events', 'notices', 'notice_audiences', 'acknowledgments',
    'messages', 'message_recipients', 'notifications', 'notification_deliveries', 'push_subscriptions', 'notification_preferences']) t;
select is((select count(*) from p2_tables p join pg_trigger g on g.tgrelid = ('public.' || p.tbl)::regclass and g.tgname = 'zz_audit' and not g.tgisinternal), 15::bigint, 'all 15 Phase 2 tables have the audit trigger');
select is((select count(*) from p2_tables p join pg_trigger g on g.tgrelid = ('public.' || p.tbl)::regclass and g.tgname = 'zz_audit_no_truncate' and not g.tgisinternal), 15::bigint, 'and the no-truncate trigger');
-- the arguments of each audit trigger after the primary key column are the redacted columns
create temp table redacted_now as
  select p.tbl, r.col
  from p2_tables p
  join pg_trigger g on g.tgrelid = ('public.' || p.tbl)::regclass and g.tgname = 'zz_audit' and not g.tgisinternal
  cross join lateral (
    select unnest(string_to_array(encode(g.tgargs, 'escape'), E'\\000')) as col, generate_series(1, 20) as i) r
  where r.col <> '' and r.i > 1;
select is((select count(*) from (select tbl, col from redact_expect except select tbl, col from redacted_now) x), 0::bigint, 'every column that must be redacted is in its table''s audit trigger arguments');
select is((select count(*) from (select tbl, col from redacted_now except select tbl, col from redact_expect) x), 0::bigint, 'and no other column is redacted (the list matches this file exactly: update both together)');
select is((select count(*) from redact_expect r where not exists (select 1 from information_schema.columns c where c.table_schema = 'public' and c.table_name = r.tbl and c.column_name = r.col)), 0::bigint, 'every redacted column exists (no typo in the audit configuration)');
-- every text/jsonb column of those tables is either redacted or accounted for above (a new free-text column fails here)
select is((select string_agg(c.table_name || '.' || c.column_name, ', ' order by c.table_name, c.column_name)
           from information_schema.columns c join p2_tables p on p.tbl = c.table_name
           where c.table_schema = 'public' and c.data_type in ('text', 'jsonb', 'character varying', 'ARRAY')
             and not exists (select 1 from redact_expect r where r.tbl = c.table_name and r.col = c.column_name)
             and not exists (select 1 from text_ok o where o.tbl = c.table_name and o.col = c.column_name)), null,
  'every text column of the Phase 2 tables is redacted or explicitly allowed to be logged (a new free-text column must be classified)');
select is((select count(*) from text_ok o where not exists (select 1 from information_schema.columns c where c.table_schema = 'public' and c.table_name = o.tbl and c.column_name = o.col)), 0::bigint, 'no stale entry in the allowed-to-log list');

-- ===========================================================================
-- 2. Write literals through every path, then look for them in the log
-- ===========================================================================
-- people and devices
insert into public.job_titles (id, organization_id, name) values (pg_temp.id('jt_x'), pg_temp.id('org_a'), 'Zamboni driver') on conflict do nothing;
-- notices (as an org admin, the RLS path): body at insert, then edited, then deleted; one published notice with its text
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try_msg($$insert into public.notices (id, organization_id, location_id, title, body) values (pg_temp.id('n1'), pg_temp.id('org_a'), null, 'AUD-VISIBLE-NOTICE-TITLE', 'AUD-NOTICE-BODY-ONE')$$), 'ok', 'insert a notice with a literal body');
select is(pg_temp.try_msg($$update public.notices set body = 'AUD-NOTICE-BODY-TWO' where id = pg_temp.id('n1')$$), 'ok', 'edit the body');
select is(pg_temp.try_msg($$insert into public.notices (id, organization_id, location_id, title, body) values (pg_temp.id('n2'), pg_temp.id('org_a'), null, 'second', 'AUD-NOTICE-BODY-THREE')$$), 'ok', 'a second notice');
select is(pg_temp.try_msg($$delete from public.notices where id = pg_temp.id('n2')$$), 'ok', 'delete it (the old row goes to the log)');
select is(pg_temp.try_msg($$insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('n1'), null)$$), 'ok', 'audience for the first notice');
select is(pg_temp.try_msg($$select public.publish_notice(pg_temp.id('n1'))$$), 'ok', 'publish it (the status change is logged)');
-- messages (through send_message), and a deleted one (owner)
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.send_message(pg_temp.id('org_a'), array[pg_temp.id('p_manager_a1')], 'AUD-MSG-BODY-RPC')$$), 'ok', 'send a message with a literal body');
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.mark_message_read((select id from public.messages limit 1))$$), 'ok', 'the recipient marks it read (a recipient update is logged)');
select pg_temp.act_as('postgres');
insert into public.messages (id, organization_id, sender_person_id, body) values (pg_temp.id('m_own'), pg_temp.id('org_a'), pg_temp.id('p_staff_a1'), 'AUD-MSG-BODY-OWNER');
delete from public.messages where id = pg_temp.id('m_own');
-- tasks: instructions at insert, a comment, a completion note, a template
select pg_temp.act_as('u_manager_a1');
select is(pg_temp.try_msg($$select public.create_task(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'AUD-VISIBLE-TASK-TITLE', 'AUD-TASK-INSTRUCTIONS', null, 'normal', null, pg_temp.id('p_manager_a1'))$$), 'ok', 'create a task with literal instructions');
select is(pg_temp.try_msg($$select public.add_task_comment((select id from public.tasks where title = 'AUD-VISIBLE-TASK-TITLE'), 'AUD-COMMENT-BODY')$$), 'ok', 'add a comment with a literal body');
select is(pg_temp.try_msg($$select public.complete_task((select id from public.tasks where title = 'AUD-VISIBLE-TASK-TITLE'), 'AUD-COMPLETION-NOTE')$$), 'ok', 'complete it with a literal note');
select is(pg_temp.try_msg($$insert into public.task_templates (id, organization_id, location_id, title, instructions) values (pg_temp.id('tpl1'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'AUD-VISIBLE-TEMPLATE-TITLE', 'AUD-TEMPLATE-INSTRUCTIONS-ONE')$$), 'ok', 'a template with literal instructions');
select is(pg_temp.try_msg($$update public.task_templates set instructions = 'AUD-TEMPLATE-INSTRUCTIONS-TWO' where id = pg_temp.id('tpl1')$$), 'ok', 'edit them');
select pg_temp.act_as('postgres');
select is((select count(*) from public.task_events where body like 'AUD-%'), 2::bigint, 'sanity: the comment and the completion note are stored in task_events (so the redaction is what hides them)');
-- worker: events, notifications, deliveries
select pg_temp.act_as('postgres');
insert into evs values ('e1', private.emit_event(pg_temp.id('org_a'), null, 'task.created', 'tasks', gen_random_uuid(), '{}'));
insert into public.push_subscriptions (id, organization_id, person_id, endpoint, p256dh, auth_secret) values
  (pg_temp.id('ps0'), pg_temp.id('org_a'), pg_temp.id('p_staff_a2'), 'https://push.example.test/AUDSENTINELENDPOINT0', 'AUDSENTINELP256DHKEY0000', 'AUDSENTINELAUTH0');
select pg_temp.act_as('service_role');
select is(public.create_notification((select id from evs where name = 'e1'), pg_temp.id('p_staff_a2'), 'task.assigned', 'AUD-NOTIF-TITLE', 'AUD-NOTIF-BODY', '/aud-notif-link-path') is not null, true, 'the worker creates a notification with a literal title, body and link');
select pg_temp.act_as('postgres');
select pg_temp.act_as('service_role');
create temp table cl as select d.id, d.channel from public.claim_notification_deliveries('wa', 10, 60) d;
grant all on cl to public;
select is(public.fail_notification_delivery((select id from cl where channel = 'email'), 'wa', 'AUD-DELIVERY-ERROR smtp said no'), 'pending', 'a delivery fails with a literal error');
select is(public.complete_notification_delivery((select id from cl where channel = 'push'), 'wa', 'AUD-PROVIDER-ID-123'), true, 'a delivery completes with a literal provider id');
select pg_temp.act_as('postgres');
-- push subscription through the API: endpoint, keys, user agent; then refreshed (update) and deleted
select pg_temp.act_as('u_staff_a1');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/AUDSENTINELENDPOINT1', 'AUDSENTINELP256DHKEY0001', 'AUDSENTINELAUTH1', 'AUDSENTINELUA1')$$), 'ok', 'save a device with literal endpoint, keys and user agent');
select is(pg_temp.try_msg($$select public.save_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/AUDSENTINELENDPOINT1', 'AUDSENTINELP256DHKEY0002', 'AUDSENTINELAUTH2', 'AUDSENTINELUA2')$$), 'ok', 'refresh it with new keys (an update)');
select is(public.delete_push_subscription(pg_temp.id('org_a'), 'https://push.example.test/AUDSENTINELENDPOINT1'), true, 'delete it (the old row goes to the log)');
select pg_temp.act_as('postgres');
-- the outbox: a failure with a literal error
select pg_temp.act_as('service_role');
create temp table oc as select e.id from public.claim_outbox_events('wo', 1, 60) e;
grant all on oc to public;
select is((select count(*) from oc), 1::bigint, 'the worker claims an event');
select is(pg_temp.try_msg($$select public.fail_outbox_event((select id from oc), 'wo', 'AUD-OUTBOX-ERROR stack trace with private words')$$), 'ok', 'and fails it with a literal error');
select pg_temp.act_as('postgres');

-- ===========================================================================
-- 3. The log has the rows, with the literals gone
-- ===========================================================================
select ok((select count(*) from public.audit_log where table_name = t and action = 'insert') > 0, 'the log recorded inserts on ' || t)
  from unnest(array['notices', 'notice_audiences', 'messages', 'message_recipients', 'tasks', 'task_events', 'task_templates', 'notifications', 'notification_deliveries', 'push_subscriptions', 'outbox_events']) t;
select is((select count(*) from public.audit_log where table_name = 'notices' and action = 'update' and 'body' = any (changed_columns)), 1::bigint, 'a notice body edit is logged as a change to "body" (the column name is visible, the value is not)');
select is((select count(*) from public.audit_log where table_name = 'notices' and action = 'delete'), 1::bigint, 'and the deleted notice''s old row is logged');
select is((select count(*) from public.audit_log where table_name = 'messages' and action = 'delete'), 1::bigint, 'and the deleted message''s old row');
select is((select count(*) from public.audit_log where table_name = 'push_subscriptions' and action = 'update' and 'p256dh' = any (changed_columns)), 1::bigint, 'a push key refresh is logged as a change to p256dh (no values)');
select is((select count(*) from public.audit_log where table_name = 'push_subscriptions' and action = 'delete'), 1::bigint, 'and the deleted push subscription''s old row');
select is((select new_row ->> 'body' from public.audit_log where table_name = 'messages' and action = 'insert' limit 1), '[redacted]', 'a logged message body reads "[redacted]"');
select is((select new_row ->> 'endpoint' from public.audit_log where table_name = 'push_subscriptions' and action = 'insert' limit 1), '[redacted]', 'a logged push endpoint reads "[redacted]"');
select is(pg_temp.leaks(l), 0::bigint, 'the literal "' || l || '" appears nowhere in audit_log')
  from unnest(array[
    'AUD-NOTICE-BODY-ONE', 'AUD-NOTICE-BODY-TWO', 'AUD-NOTICE-BODY-THREE',
    'AUD-MSG-BODY-RPC', 'AUD-MSG-BODY-OWNER',
    'AUD-TASK-INSTRUCTIONS', 'AUD-COMMENT-BODY', 'AUD-COMPLETION-NOTE',
    'AUD-TEMPLATE-INSTRUCTIONS-ONE', 'AUD-TEMPLATE-INSTRUCTIONS-TWO',
    'AUD-NOTIF-TITLE', 'AUD-NOTIF-BODY', 'aud-notif-link-path',
    'AUD-DELIVERY-ERROR', 'AUD-PROVIDER-ID-123',
    'AUDSENTINELENDPOINT0', 'AUDSENTINELENDPOINT1', 'AUDSENTINELP256DHKEY0000', 'AUDSENTINELP256DHKEY0001', 'AUDSENTINELP256DHKEY0002',
    'AUDSENTINELAUTH0', 'AUDSENTINELAUTH1', 'AUDSENTINELAUTH2', 'AUDSENTINELUA1', 'AUDSENTINELUA2',
    'AUD-OUTBOX-ERROR', 'private words']) l;
-- the detector works: headlines are logged on purpose
select ok(pg_temp.leaks('AUD-VISIBLE-NOTICE-TITLE') > 0, 'twin: the notice title IS in the log (not redacted by design), so the check above would have found a leak');
select ok(pg_temp.leaks('AUD-VISIBLE-TASK-TITLE') > 0, 'twin: so is the task title');
select ok(pg_temp.leaks('AUD-VISIBLE-TEMPLATE-TITLE') > 0, 'twin: and the template title');
-- the outbox error really was stored (so it was the redaction that hid it)
select is((select count(*) from public.outbox_events where last_error like 'AUD-OUTBOX-ERROR%'), 1::bigint, 'sanity: the outbox error is stored on the event itself');
select is((select count(*) from public.notification_deliveries where last_error like 'AUD-DELIVERY-ERROR%'), 1::bigint, 'sanity: the delivery error is stored on the delivery');
select is((select count(*) from public.push_subscriptions where endpoint like '%AUDSENTINELENDPOINT0'), 1::bigint, 'sanity: the owner-inserted device is stored with its endpoint');

select * from finish();
rollback;
