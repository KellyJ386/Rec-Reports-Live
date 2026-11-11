-- ===========================================================================
-- THE PHASE 2 GATE (docs/ROADMAP.md): one event creates exactly one task per matching rule and exactly one
-- notification per recipient, even when the event is retried, replayed, or the worker crashes half way.
--
-- The worker is simulated in SQL as service_role, through the real service functions only:
--   claim_outbox_events -> outbox_handlers_done -> match_workflow_rules + create_task_from_event (handler "tasks")
--   -> task_recipient_person_ids / notice_audience_person_ids + create_notification (handler "notify")
--   -> record_outbox_handler -> complete_outbox_event
-- Scenarios: crash between handlers (ledger holds one entry), lock expiry and reclaim, finish, then replay the whole
-- event again (with the ledger, and with the ledger lost) and prove counts and ids do not move; failure and retry;
-- notice fan-out; another organization's event and rules; disabled, archived and non-matching rules; overdue events
-- once per task per due time; no rule on task.* events other than task.overdue.
-- ===========================================================================
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(145);

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
grant execute on function pg_temp.val(text), pg_temp.try_msg(text) to public;

-- The simulated worker. One call = one worker process draining what is due. Flags:
--   p_crash_after_tasks: die right after the task handler of a booking.confirmed event (nothing completed or released)
--   p_fail_after_tasks:  report a failure (fail_outbox_event) right after the task handler instead of crashing
--   p_ignore_ledger:     behave as if the ledger row had not been written (a crash between effect and ledger row)
create function pg_temp.run_worker(p_worker text, p_crash_after_tasks boolean default false,
                                   p_fail_after_tasks boolean default false, p_ignore_ledger boolean default false) returns int
language plpgsql as $$
declare
  ev public.outbox_events;
  done text[];
  r record;
  p uuid;
  got int;
  rounds int := 0;
  handled int := 0;
begin
  loop
    rounds := rounds + 1;
    exit when rounds > 10;
    got := 0;
    for ev in select * from public.claim_outbox_events(p_worker, 50, 60) loop
      got := got + 1;
      handled := handled + 1;
      done := case when p_ignore_ledger then '{}'::text[] else coalesce(array(select h from public.outbox_handlers_done(ev.id) h), '{}'::text[]) end;
      if not ('tasks' = any (done)) then
        for r in select * from public.match_workflow_rules(ev.id) loop
          perform public.create_task_from_event(ev.id, r.rule_id);
        end loop;
        perform public.record_outbox_handler(ev.id, 'tasks');
      end if;
      if p_crash_after_tasks and ev.type = 'booking.confirmed' then
        return handled;                 -- the process dies here: no complete, no fail, the lock just sits there
      end if;
      if p_fail_after_tasks and ev.type = 'booking.confirmed' then
        perform public.fail_outbox_event(ev.id, p_worker, 'notify handler failed: mail provider down');
        continue;
      end if;
      if not ('notify' = any (done)) then
        if ev.type = 'task.created' then
          for p in select x from public.task_recipient_person_ids(ev.entity_id) x loop
            perform public.create_notification(ev.id, p, 'task.assigned', 'You have a new task', null, '/tasks');
          end loop;
        elsif ev.type = 'notice.published' then
          for p in select x from public.notice_audience_person_ids(ev.entity_id) x loop
            perform public.create_notification(ev.id, p, 'notice.published', 'New notice', null, '/notices');
          end loop;
        end if;
        perform public.record_outbox_handler(ev.id, 'notify');
      end if;
      perform public.complete_outbox_event(ev.id, p_worker);
    end loop;
    exit when got = 0;
  end loop;
  return handled;
end $$;
grant execute on function pg_temp.run_worker(text, boolean, boolean, boolean) to public;

-- State snapshot helpers (owner reads): counts and a fingerprint of the ids.
create temp table gs (k text primary key, v text);
grant all on gs to public;
create function pg_temp.fp(p_what text) returns text language plpgsql as $$
declare r text;
begin
  execute case p_what
    when 'tasks'         then 'select md5(coalesce(string_agg(id::text, '','' order by id), '''')) || '':'' || count(*) from public.tasks'
    when 'task_events'   then 'select md5(coalesce(string_agg(id::text, '','' order by id), '''')) || '':'' || count(*) from public.task_events'
    when 'task_created'  then 'select md5(coalesce(string_agg(id::text, '','' order by id), '''')) || '':'' || count(*) from public.outbox_events where type = ''task.created'''
    when 'notifications' then 'select md5(coalesce(string_agg(id::text, '','' order by id), '''')) || '':'' || count(*) from public.notifications'
    when 'deliveries'    then 'select md5(coalesce(string_agg(id::text, '','' order by id), '''')) || '':'' || count(*) from public.notification_deliveries'
    when 'events'        then 'select md5(coalesce(string_agg(id::text, '','' order by id), '''')) || '':'' || count(*) from public.outbox_events'
  end into r;
  return r;
end $$;
grant execute on function pg_temp.fp(text) to public;

-- ---------------------------------------------------------------------------
-- Setup (owner). Templates, rules, job titles.
-- ---------------------------------------------------------------------------
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id) values
  (pg_temp.id('pjt_mgr_a1'),  pg_temp.id('org_a'), pg_temp.id('p_manager_a1'), pg_temp.id('jt_a'), pg_temp.id('loc_a1')),
  (pg_temp.id('pjt_st2_a2'),  pg_temp.id('org_a'), pg_temp.id('p_staff_a2'),   pg_temp.id('jt_a'), pg_temp.id('loc_a2')),
  (pg_temp.id('pjt_dis_a1'),  pg_temp.id('org_a'), pg_temp.id('p_disabled_a'), pg_temp.id('jt_a'), pg_temp.id('loc_a1'));
insert into public.task_templates (id, organization_id, location_id, title, instructions, default_priority, due_offset_minutes, assign_to, assign_job_title_id, assign_person_id) values
  (pg_temp.id('tpl_title'),  pg_temp.id('org_a'), null,                  'Set up the party room', 'Tables and chairs', 'high', 60,   'job_title', pg_temp.id('jt_a'), null),
  (pg_temp.id('tpl_person'), pg_temp.id('org_a'), pg_temp.id('loc_a1'),  'Greet the party host',  null,                'normal', -30, 'person',    null, pg_temp.id('p_staff_a1')),
  (pg_temp.id('tpl_none'),   pg_temp.id('org_a'), null,                  'Look into it',          null,                'low',   null, 'none',      null, null),
  (pg_temp.id('tpl_a2'),     pg_temp.id('org_a'), pg_temp.id('loc_a2'),  'A2 only task',          null,                'normal', null, 'none',      null, null),
  (pg_temp.id('tpl_b'),      pg_temp.id('org_b'), null,                  'Org B task',            null,                'normal', null, 'none',      null, null);
insert into public.workflow_rules (id, organization_id, location_id, name, event_type, condition, task_template_id) values
  (pg_temp.id('rule1'),  pg_temp.id('org_a'), null,                 'R1 any booking',          'booking.confirmed', '{}',                                                      pg_temp.id('tpl_title')),
  (pg_temp.id('rule2'),  pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'R2 party at A1',          'booking.confirmed', '{"all":[{"field":"kind","op":"eq","value":"party"}]}',     pg_temp.id('tpl_person')),
  (pg_temp.id('rule3'),  pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'R3 A2 only',              'booking.confirmed', '{}',                                                      pg_temp.id('tpl_a2')),
  (pg_temp.id('rule4'),  pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'R4 disabled',             'booking.confirmed', '{}',                                                      pg_temp.id('tpl_none')),
  (pg_temp.id('rule5'),  pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'R5 swim only',            'booking.confirmed', '{"all":[{"field":"kind","op":"eq","value":"swim"}]}',      pg_temp.id('tpl_none')),
  (pg_temp.id('rule7'),  pg_temp.id('org_a'), null,                 'R7 cancelled bookings',   'booking.cancelled', '{}',                                                      pg_temp.id('tpl_none')),
  (pg_temp.id('rule_sh'),pg_temp.id('org_a'), null,                 'R-shift (org A)',         'shift.uncovered',   '{}',                                                      pg_temp.id('tpl_none')),
  (pg_temp.id('rule_i1'),pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'R-incident at A1',        'incident.submitted','{}',                                                      pg_temp.id('tpl_none')),
  (pg_temp.id('rule_i2'),pg_temp.id('org_a'), null,                 'R-incident org-wide',     'incident.submitted','{}',                                                      pg_temp.id('tpl_none')),
  (pg_temp.id('rule_od'),pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'R-overdue escalation',    'task.overdue',      '{}',                                                      pg_temp.id('tpl_none')),
  (pg_temp.id('rule_b'), pg_temp.id('org_b'), null,                 'B booking',               'booking.confirmed', '{}',                                                      pg_temp.id('tpl_b'));
select is((select count(*) from public.workflow_rules where enabled), 0::bigint, 'a rule is always created disabled (even from the owner)');
update public.workflow_rules set enabled = true where id <> pg_temp.id('rule4');

-- ---------------------------------------------------------------------------
-- Scenario 1: booking.confirmed at A1 (a party). Matching rules: rule1 (org-wide) and rule2 (A1, kind=party).
-- ---------------------------------------------------------------------------
insert into gs select 'e1', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'booking.confirmed', 'bookings', pg_temp.id('booking_1'),
  jsonb_build_object('kind', 'party', 'anchor_at', '2030-01-01T10:00:00Z', 'space_id', pg_temp.id('space_a1')::text));
select pg_temp.act_as('service_role');
select is((select array_agg(rule_id order by rule_id) from public.match_workflow_rules((select v::uuid from gs where k = 'e1'))),
          (select array_agg(x order by x) from unnest(array[pg_temp.id('rule1'), pg_temp.id('rule2')]) x),
  'match: exactly the two rules that apply (rule1 org-wide, rule2 A1 + condition); not A2''s, not the disabled, not the swim-only, not the cancelled-bookings rule');
select is(public.create_task_from_event((select v::uuid from gs where k = 'e1'), pg_temp.id('rule4')), null, 'a disabled rule creates nothing (null)');
select is(public.create_task_from_event((select v::uuid from gs where k = 'e1'), pg_temp.id('rule3')), null, 'a rule of another location creates nothing (null)');
select is(public.create_task_from_event((select v::uuid from gs where k = 'e1'), pg_temp.id('rule5')), null, 'a rule whose condition does not match creates nothing (null)');
select is(public.create_task_from_event((select v::uuid from gs where k = 'e1'), pg_temp.id('rule7')), null, 'a rule for another event type creates nothing (null)');
select is(public.create_task_from_event((select v::uuid from gs where k = 'e1'), pg_temp.id('rule_b')), null, 'another organization''s rule creates nothing (null)');
select is(pg_temp.try_msg(format('select public.create_task_from_event(%L, %L)', gen_random_uuid(), pg_temp.id('rule1'))), '22023 no such event', 'an unknown event is refused');
select pg_temp.act_as('postgres');
select is((select count(*) from public.tasks), 0::bigint, 'nothing was created by those refused calls');

-- Step 1: worker w1 claims the event, runs the task handler, writes its ledger row, and CRASHES.
select pg_temp.act_as('service_role');
select is(pg_temp.run_worker('w1', true), 1, 'worker w1 handled one event before it crashed');
select pg_temp.act_as('postgres');
select is((select count(*) from public.tasks), 2::bigint, 'after the crash: one task per matching rule (2), not 0 and not 3');
select is((select count(*) from public.tasks where source_event_id = (select v::uuid from gs where k = 'e1')), 2::bigint, 'both tasks carry the source event id');
select is((select array_agg(source_rule_id order by source_rule_id) from public.tasks), (select array_agg(x order by x) from unnest(array[pg_temp.id('rule1'), pg_temp.id('rule2')]) x), 'and the two rules that matched');
select is((select array_agg(handler) from public.outbox_event_handlers where event_id = (select v::uuid from gs where k = 'e1')), array['tasks'], 'the ledger has exactly one entry: tasks');
select results_eq($$select status, attempts, locked_by from public.outbox_events where id = (select v::uuid from gs where k = 'e1')$$, $$select 'processing'::text, 1, 'w1'::text$$,
  'the event is still locked by the dead worker (attempt 1)');
select is((select count(*) from public.task_events), 2::bigint, 'two task_events rows (kind created), one per task');
select is((select count(*) from public.outbox_events where type = 'task.created'), 2::bigint, 'two task.created events, one per task');
select is((select count(*) from public.notifications), 0::bigint, 'no notification yet (the task.created events have not been processed)');
-- the other worker cannot take it while the lock is live; after the lock expires it can
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('w2', 1, 60) where type = 'booking.confirmed'), 0::bigint, 'while w1''s lock is live no other worker gets the booking event');
select pg_temp.act_as('postgres');
update public.outbox_events set status = 'pending', locked_by = null, locked_at = null, lock_expires_at = null where false;
update public.outbox_events set lock_expires_at = now() - interval '1 second' where id = (select v::uuid from gs where k = 'e1');
-- the claim above (w2, limit 1) may have claimed a due task.created event instead; release it so the run below is a clean second worker
update public.outbox_events set status = 'pending', locked_by = null, locked_at = null, lock_expires_at = null, attempts = attempts - 1
  where status = 'processing' and locked_by = 'w2';

-- Step 2: worker w2 drains: reclaims the booking event (attempt 2), skips the finished handler, completes it, then
-- fans the two task.created events out to notifications.
select pg_temp.act_as('service_role');
select cmp_ok(pg_temp.run_worker('w2'), '>=', 3, 'worker w2 handled the reclaimed booking event and both task.created events');
select pg_temp.act_as('postgres');
select results_eq($$select status, attempts from public.outbox_events where id = (select v::uuid from gs where k = 'e1')$$, $$select 'done'::text, 2$$, 'the booking event is done after attempt 2');
select is((select count(*) from public.outbox_events where status <> 'done'), 0::bigint, 'every event is done');
select is((select count(*) from public.tasks), 2::bigint, 'still exactly 2 tasks after the reclaim and the finish');
select is((select count(*) from public.task_events), 2::bigint, 'still exactly 2 task_events');
select is((select count(*) from public.outbox_events where type = 'task.created'), 2::bigint, 'still exactly 2 task.created events');
select is((select count(*) from public.notifications), 3::bigint, 'exactly 3 notifications: task 1 goes to its 2 job-title holders at A1, task 2 to its assigned person');
select is((select count(*) from public.notification_deliveries), 9::bigint, 'exactly 9 deliveries: in_app, email, push for each notification');
select is((select array_agg(distinct person_id order by person_id) from public.notifications n join public.tasks t on t.id = n.source_id and t.task_template_id = pg_temp.id('tpl_title')),
          (select array_agg(x order by x) from unnest(array[pg_temp.id('p_staff_a1'), pg_temp.id('p_manager_a1')]) x),
  'the job-title task notified the title holders at A1 (staff A1, manager A1) and not the A2 holder or the disabled account');
select is((select array_agg(person_id) from public.notifications n join public.tasks t on t.id = n.source_id and t.task_template_id = pg_temp.id('tpl_person')), array[pg_temp.id('p_staff_a1')],
  'the person-assigned task notified only that person');
select is((select count(*) from (select source_event_id, person_id, kind from public.notifications group by 1, 2, 3 having count(*) > 1) d), 0::bigint, 'no (event, person, kind) has two notifications');
select is((select count(*) from (select notification_id, channel from public.notification_deliveries group by 1, 2 having count(*) > 1) d), 0::bigint, 'no notification has two deliveries on one channel');
select is((select string_agg(channel || '=' || status, ',' order by channel) from public.notification_deliveries where notification_id = (select id from public.notifications limit 1)),
  'email=pending,in_app=sent,push=skipped', 'a notification''s deliveries: in_app sent at once, email pending, push skipped (no device)');
-- the content of what was created
select results_eq($$select t.title, t.priority, t.status, t.due_at, t.assigned_person_id, t.assigned_job_title_id, t.space_id, t.created_by_person_id, t.source_event_id, t.task_template_id
    from public.tasks t where t.source_rule_id = pg_temp.id('rule1')$$,
  $$select 'Set up the party room'::text, 'high'::text, 'open'::text, '2030-01-01T11:00:00Z'::timestamptz, null::uuid, pg_temp.id('jt_a'), pg_temp.id('space_a1'), null::uuid,
           (select v::uuid from gs where k = 'e1'), pg_temp.id('tpl_title')$$,
  'task from rule1: template title and priority, due = anchor_at + 60 minutes, routed to the job title, space from the payload, created by the system');
select results_eq($$select t.title, t.priority, t.due_at, t.assigned_person_id, t.assigned_job_title_id from public.tasks t where t.source_rule_id = pg_temp.id('rule2')$$,
  $$select 'Greet the party host'::text, 'normal'::text, '2030-01-01T09:30:00Z'::timestamptz, pg_temp.id('p_staff_a1'), null::uuid$$,
  'task from rule2: due = anchor_at - 30 minutes, assigned to the template''s person');
select is((select count(*) from public.task_events where kind = 'created' and actor_person_id is null and source_event_id = (select v::uuid from gs where k = 'e1') and to_status = 'open' and from_status is null), 2::bigint,
  'each task has one created history row by the system, pointing at the source event');
select is((select count(*) from public.outbox_events where type = 'task.created' and correlation_id = (select v::uuid from gs where k = 'e1')), 2::bigint, 'the task.created events carry the source event''s correlation id');
select is((select count(*) from public.outbox_events e where e.type = 'task.created' and e.entity_id in (select id from public.tasks) and e.organization_id = pg_temp.id('org_a') and e.location_id = pg_temp.id('loc_a1')), 2::bigint,
  'each task.created event points at its task, in its organization and location');
-- remember everything
insert into gs values ('f_tasks', pg_temp.fp('tasks')), ('f_te', pg_temp.fp('task_events')), ('f_tc', pg_temp.fp('task_created')), ('f_n', pg_temp.fp('notifications')),
  ('f_d', pg_temp.fp('deliveries')), ('f_ev', pg_temp.fp('events'));

-- Step 3: replay the whole event with the ledger intact: every handler is skipped.
select pg_temp.act_as('postgres');
update public.outbox_events set status = 'pending', processed_at = null, attempts = 0, next_attempt_at = now() where type in ('booking.confirmed', 'task.created');
select pg_temp.act_as('service_role');
select cmp_ok(pg_temp.run_worker('w3'), '>=', 3, 'replay 1 (ledger intact): the worker handled all three events again');
select pg_temp.act_as('postgres');
select is(pg_temp.fp('tasks'), (select v from gs where k = 'f_tasks'), 'replay 1: tasks unchanged, same ids');
select is(pg_temp.fp('task_events'), (select v from gs where k = 'f_te'), 'replay 1: task_events unchanged, same ids');
select is(pg_temp.fp('task_created'), (select v from gs where k = 'f_tc'), 'replay 1: task.created events unchanged, same ids');
select is(pg_temp.fp('notifications'), (select v from gs where k = 'f_n'), 'replay 1: notifications unchanged, same ids');
select is(pg_temp.fp('deliveries'), (select v from gs where k = 'f_d'), 'replay 1: deliveries unchanged, same ids');
select is(pg_temp.fp('events'), (select v from gs where k = 'f_ev'), 'replay 1: no new outbox events of any kind');

-- Step 4: replay with the ledger LOST (a crash between a handler''s effect and its ledger row): handlers run again.
delete from public.outbox_event_handlers;
update public.outbox_events set status = 'pending', processed_at = null, attempts = 0, next_attempt_at = now() where type in ('booking.confirmed', 'task.created');
select pg_temp.act_as('service_role');
select cmp_ok(pg_temp.run_worker('w4', false, false, true), '>=', 3, 'replay 2 (ledger ignored): every handler ran again');
select pg_temp.act_as('postgres');
select is(pg_temp.fp('tasks'), (select v from gs where k = 'f_tasks'), 'replay 2: tasks unchanged, same ids (unique (source_event_id, task_template_id))');
select is(pg_temp.fp('task_events'), (select v from gs where k = 'f_te'), 'replay 2: task_events unchanged, same ids');
select is(pg_temp.fp('task_created'), (select v from gs where k = 'f_tc'), 'replay 2: task.created events unchanged, same ids');
select is(pg_temp.fp('notifications'), (select v from gs where k = 'f_n'), 'replay 2: notifications unchanged, same ids (unique (source_event_id, person_id, kind))');
select is(pg_temp.fp('deliveries'), (select v from gs where k = 'f_d'), 'replay 2: deliveries unchanged, same ids');
select is(pg_temp.fp('events'), (select v from gs where k = 'f_ev'), 'replay 2: no new outbox events of any kind');
-- and again, twice more, in the other order of events
update public.outbox_events set status = 'pending', processed_at = null, attempts = 0, next_attempt_at = now() where type in ('booking.confirmed', 'task.created');
select pg_temp.act_as('service_role');
select cmp_ok(pg_temp.run_worker('w5', false, false, true), '>=', 3, 'replay 3 (ledger ignored again)');
select pg_temp.act_as('postgres');
select is(pg_temp.fp('tasks') || pg_temp.fp('task_events') || pg_temp.fp('task_created') || pg_temp.fp('notifications') || pg_temp.fp('deliveries') || pg_temp.fp('events'),
  (select string_agg(v, '' order by k) from (select v, case k when 'f_tasks' then 1 when 'f_te' then 2 when 'f_tc' then 3 when 'f_n' then 4 when 'f_d' then 5 when 'f_ev' then 6 end as k from gs where k like 'f\_%') z),
  'replay 3: everything still identical');
-- the service functions are idempotent by themselves, called directly
select pg_temp.act_as('service_role');
select is(public.create_task_from_event((select v::uuid from gs where k = 'e1'), pg_temp.id('rule1')), (select id from public.tasks where source_rule_id = pg_temp.id('rule1')), 'create_task_from_event again returns the same task id');
select is(public.create_notification((select id from public.outbox_events where type = 'task.created' limit 1), (select person_id from public.notifications limit 1), 'task.assigned', 'You have a new task'), (select id from public.notifications where person_id = (select person_id from public.notifications limit 1) and source_event_id = (select id from public.outbox_events where type = 'task.created' limit 1)),
  'create_notification again returns the same notification id (null if the combination was not one of ours)') ;
select pg_temp.act_as('postgres');
select is(pg_temp.fp('tasks') || pg_temp.fp('notifications'), (select v from gs where k = 'f_tasks') || (select v from gs where k = 'f_n'), 'and nothing was added by the direct calls');
-- a rule disabled after the fact: replaying the event does not undo or duplicate anything
update public.workflow_rules set enabled = false where id = pg_temp.id('rule1');
select pg_temp.act_as('service_role');
select is(public.create_task_from_event((select v::uuid from gs where k = 'e1'), pg_temp.id('rule1')), null, 'a rule disabled afterwards: create_task_from_event returns null for the old event');
select pg_temp.act_as('postgres');
select is(pg_temp.fp('tasks'), (select v from gs where k = 'f_tasks'), 'and the task it made earlier is left alone');
update public.workflow_rules set enabled = true where id = pg_temp.id('rule1');

-- ---------------------------------------------------------------------------
-- Scenario 2: failure and retry (not a crash): the event fails after the task handler, backs off, and runs again.
-- ---------------------------------------------------------------------------
select pg_temp.act_as('postgres');
insert into gs select 'e2', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'booking.confirmed', 'bookings', pg_temp.id('booking_2'),
  jsonb_build_object('kind', 'party', 'anchor_at', '2030-02-01T10:00:00Z'));
select pg_temp.act_as('service_role');
select pg_temp.run_worker('w6', false, true);
select pg_temp.act_as('postgres');
select results_eq($$select status, attempts, last_error, (next_attempt_at = now() + interval '1 minute') from public.outbox_events where id = (select v::uuid from gs where k = 'e2')$$,
  $$select 'pending'::text, 1, 'notify handler failed: mail provider down'::text, true$$, 'the failed event is pending again with a 1 minute backoff and its error');
select is((select count(*) from public.tasks where source_event_id = (select v::uuid from gs where k = 'e2')), 2::bigint, 'its tasks exist after the failed attempt (2)');
update public.outbox_events set next_attempt_at = now() where id = (select v::uuid from gs where k = 'e2');   -- the backoff passes
select pg_temp.act_as('service_role');
select pg_temp.run_worker('w7');
select pg_temp.act_as('postgres');
select results_eq($$select status, attempts from public.outbox_events where id = (select v::uuid from gs where k = 'e2')$$, $$select 'done'::text, 2$$, 'the retry finishes the event on attempt 2');
select is((select count(*) from public.tasks where source_event_id = (select v::uuid from gs where k = 'e2')), 2::bigint, 'after the retry: still 2 tasks for that event');
select is((select count(*) from public.tasks), 4::bigint, 'and 4 tasks in all (2 per booking event)');
select is((select count(*) from public.notifications), 6::bigint, '6 notifications in all (3 per booking event)');
select is((select count(*) from public.notification_deliveries), 18::bigint, '18 deliveries in all');
select is((select count(*) from (select source_event_id, task_template_id from public.tasks group by 1, 2 having count(*) > 1) d), 0::bigint, 'no (event, template) pair has two tasks');
-- two rules that share a template: one task (the unique key is event + template)
insert into gs select 'e4', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'incident.submitted', 'incidents', pg_temp.id('incident_1'), '{"severity":"minor"}');
select pg_temp.act_as('service_role');
select is((select count(*) from public.match_workflow_rules((select v::uuid from gs where k = 'e4'))), 2::bigint, 'incident.submitted at A1 matches two rules that share one template');
select pg_temp.run_worker('w8');
select pg_temp.act_as('postgres');
select is((select count(*) from public.tasks where source_event_id = (select v::uuid from gs where k = 'e4')), 1::bigint, 'and creates one task, not two (a task per event and template)');

-- ---------------------------------------------------------------------------
-- Scenario 3: another organization. An org B event never picks up org A's rules; org B's own rule works for org B.
-- ---------------------------------------------------------------------------
select pg_temp.act_as('postgres');
insert into gs select 'eb1', private.emit_event(pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'shift.uncovered', 'shifts', pg_temp.id('shift_b'), '{"x":"1"}');
insert into gs select 'eb2', private.emit_event(pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'booking.confirmed', 'bookings', pg_temp.id('booking_b'), '{"kind":"party"}');
select pg_temp.fp('tasks') into temp table before_b;
select pg_temp.act_as('service_role');
select is((select count(*) from public.match_workflow_rules((select v::uuid from gs where k = 'eb1'))), 0::bigint, 'an org B shift event matches nothing: the only shift rule belongs to org A');
select is(public.create_task_from_event((select v::uuid from gs where k = 'eb1'), pg_temp.id('rule_sh')), null, 'create_task_from_event(org B event, org A rule) creates nothing');
select is(public.create_task_from_event((select v::uuid from gs where k = 'eb2'), pg_temp.id('rule1')), null, 'create_task_from_event(org B booking, org A rule1) creates nothing either');
select is((select array_agg(rule_id) from public.match_workflow_rules((select v::uuid from gs where k = 'eb2'))), array[pg_temp.id('rule_b')], 'an org B booking matches only org B''s own rule');
select pg_temp.run_worker('w9');
select pg_temp.act_as('postgres');
select is((select count(*) from public.tasks where organization_id = pg_temp.id('org_b')), 1::bigint, 'org B ends with exactly one task (from its own rule)');
select is((select count(*) from public.tasks where organization_id = pg_temp.id('org_a') and source_event_id in ((select v::uuid from gs where k = 'eb1'), (select v::uuid from gs where k = 'eb2'))), 0::bigint, 'and org A got none from org B''s events');
select is((select count(*) from public.tasks where organization_id = pg_temp.id('org_b') and source_rule_id in (select id from public.workflow_rules where organization_id = pg_temp.id('org_a'))), 0::bigint, 'no org B task came from an org A rule');
select is((select count(*) from public.tasks where organization_id <> (select organization_id from public.workflow_rules r where r.id = source_rule_id)), 0::bigint, 'no task anywhere belongs to a different organization than the rule that made it');
-- the database refuses a rule or task that crosses organizations at all
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), 'cross', 'booking.confirmed', pg_temp.id('tpl_b'))$$), '42501', 'a rule cannot use another organization''s template (refused, uniform 42501)');
select is(pg_temp.try($$insert into public.tasks (organization_id, location_id, title, source_event_id, source_rule_id, task_template_id)
  values (pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'x', gen_random_uuid(), pg_temp.id('rule1'), pg_temp.id('tpl_b'))$$), '23503', 'a task cannot point at another organization''s rule (composite key)');
select is(pg_temp.try($$insert into public.tasks (organization_id, location_id, title, source_event_id, source_rule_id, task_template_id)
  values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'dup', (select v::uuid from gs where k = 'e1'), pg_temp.id('rule1'), pg_temp.id('tpl_title'))$$), '23505', 'a second task for the same (event, template) is refused by the unique key');
select is(pg_temp.try($$insert into public.tasks (organization_id, location_id, title, source_event_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'x', gen_random_uuid())$$), '23514', 'a source event without a rule and template is refused');

-- ---------------------------------------------------------------------------
-- Scenario 4: rules and templates: archived, location pairing, and no rules on task.* events except task.overdue
-- ---------------------------------------------------------------------------
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), null, 'wide', 'booking.confirmed', pg_temp.id('tpl_person'))$$), '23514',
  'an organization-wide rule cannot use a template that belongs to one location');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'a1 on a2 tpl', 'booking.confirmed', pg_temp.id('tpl_a2'))$$), '23514',
  'a rule at A1 cannot use A2''s template');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'ok', 'booking.confirmed', pg_temp.id('tpl_person'))$$), 'ok',
  'twin: a rule at A1 can use A1''s template');
select is(pg_temp.try(format($q$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), null, 'bad', %L, pg_temp.id('tpl_none'))$q$, t)), '23514',
  'a rule cannot be created for event type ' || t) from unnest(array['task.created', 'task.completed', 'task.assigned', 'task.started', 'task.cancelled', 'task.reopened', 'task.commented', 'task.escalated', 'task.anything', 'bogus.type', 'notice.archived', 'message.sent']) t;
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), null, 'ok-overdue', 'task.overdue', pg_temp.id('tpl_none'))$$), 'ok',
  'twin: a rule on task.overdue is accepted');
select is(pg_temp.try($$update public.workflow_rules set event_type = 'task.created' where id = pg_temp.id('rule1')$$), '23514', 'an existing rule cannot be switched to task.created either');
select pg_temp.act_as('u_orgadmin_a');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), null, 'via api', 'task.created', pg_temp.id('tpl_none'))$$), '23514', 'an org admin cannot create a task.created rule through the API');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, location_id, name, event_type, task_template_id) values (pg_temp.id('org_a'), null, 'via api', 'task.overdue', pg_temp.id('tpl_none'))$$), 'ok', 'twin: an org admin can create a task.overdue rule through the API');
select pg_temp.act_as('postgres');
select is((select count(*) from public.workflow_rules where enabled and event_type like 'task.%' and event_type <> 'task.overdue'), 0::bigint, 'no enabled rule reacts to a task.* event other than task.overdue');
select pg_temp.act_as('service_role');
select is((select count(*) from public.outbox_events e where e.type = 'task.created' and exists (select 1 from public.match_workflow_rules(e.id))), 0::bigint, 'no task.created event matches any rule (so tasks cannot create tasks in a loop)');
select pg_temp.act_as('postgres');
select is((select count(*) from public.tasks where source_event_id in (select id from public.outbox_events where type like 'task.%' and type <> 'task.overdue')), 0::bigint, 'no task was created from a task.* event (other than overdue)');
-- an archived template stops its rules
update public.task_templates set archived_at = now() where id = pg_temp.id('tpl_a2');
insert into gs select 'e5', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a2'), 'booking.confirmed', 'bookings', pg_temp.id('booking_5'), '{}');
select pg_temp.act_as('service_role');
select is((select count(*) from public.match_workflow_rules((select v::uuid from gs where k = 'e5')) m where m.rule_id = pg_temp.id('rule3')), 0::bigint, 'a rule whose template is archived no longer matches');
select is((select count(*) from public.match_workflow_rules((select v::uuid from gs where k = 'e5')) m where m.rule_id = pg_temp.id('rule1')), 1::bigint, 'twin: the org-wide rule still matches the A2 event');
select pg_temp.act_as('postgres');
select is(pg_temp.try($$update public.workflow_rules set enabled = true where id = pg_temp.id('rule3')$$), '23514', 'an archived template cannot back an enabled rule (refused when enabling)');
-- an archived rule stops
update public.workflow_rules set enabled = false, archived_at = now() where id = pg_temp.id('rule7');
select is(pg_temp.try($$update public.workflow_rules set enabled = true where id = pg_temp.id('rule7')$$), '23514', 'an archived rule cannot be enabled');
-- a condition with a different JSON type does not match
select pg_temp.act_as('postgres');
insert into gs select 'e_nokind', private.emit_event(pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'booking.confirmed', 'bookings', pg_temp.id('booking_nokind'), '{}');
select is(private.workflow_condition_matches('{"all":[{"field":"n","op":"eq","value":5}]}', '{"n":"5"}'), false, 'condition: the string "5" does not equal the number 5');
select is(private.workflow_condition_matches('{"all":[{"field":"n","op":"eq","value":5}]}', '{"n":5}'), true, 'condition: twin, 5 equals 5');
select is(private.workflow_condition_matches('{"all":[{"field":"k","op":"in","value":["a","b"]},{"field":"n","op":"eq","value":true}]}', '{"k":"b","n":true}'), true, 'condition: "in" and "eq" clauses must all match');
select is(private.workflow_condition_matches('{"all":[{"field":"k","op":"in","value":["a","b"]},{"field":"n","op":"eq","value":true}]}', '{"k":"c","n":true}'), false, 'condition: one failing clause fails the rule');
select is(private.workflow_condition_matches('{"all":[{"field":"k","op":"eq","value":"x"}]}', '{"k":null}'), false, 'condition: a payload field that is JSON null does not match "x"');
select is(private.workflow_condition_matches('{"all":[{"field":"missing","op":"in","value":["x","y"]}]}', '{"other":"x"}'), false, 'condition: a missing payload field does not match (in)');
-- (000600 R16a) an eq or in clause on a field that is absent from the payload, or JSON null, never matches.
select is(private.workflow_condition_matches('{"all":[{"field":"missing","op":"eq","value":"x"}]}', '{}'), false, 'condition: a missing payload field does not match (eq)');
select pg_temp.act_as('service_role');
select is((select count(*) from public.match_workflow_rules((select v::uuid from gs where k = 'e_nokind')) m where m.rule_id = pg_temp.id('rule2')), 0::bigint,
  'a booking event with no "kind" in its payload does not match the "kind = party" rule');
select is((select count(*) from public.match_workflow_rules((select v::uuid from gs where k = 'e_nokind')) m where m.rule_id = pg_temp.id('rule1')), 1::bigint,
  'twin: the same event still matches the rule without a condition');
select pg_temp.act_as('postgres');
select pg_temp.act_as('postgres');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, name, event_type, condition, task_template_id) values (pg_temp.id('org_a'), 'c', 'booking.confirmed', '{"any":[]}', pg_temp.id('tpl_none'))$$), '23514', 'a condition other than {} or {"all": [...]} is refused');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, name, event_type, condition, task_template_id) values (pg_temp.id('org_a'), 'c', 'booking.confirmed', '{"all":[{"field":"k","op":"like","value":"x"}]}', pg_temp.id('tpl_none'))$$), '23514', 'an operator other than eq / in is refused');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, name, event_type, condition, task_template_id) values (pg_temp.id('org_a'), 'c', 'booking.confirmed', '{"all":[{"field":"k","op":"eq","value":{"a":1}}]}', pg_temp.id('tpl_none'))$$), '23514', 'a nested value in a clause is refused');
select is(pg_temp.try($$insert into public.workflow_rules (organization_id, name, event_type, condition, task_template_id) values (pg_temp.id('org_a'), 'c', 'booking.confirmed', '{"all":[]}', pg_temp.id('tpl_none'))$$), '23514', 'an empty clause list is refused');

-- ---------------------------------------------------------------------------
-- Scenario 5: task.overdue, once per task per due time
-- ---------------------------------------------------------------------------
select pg_temp.act_as('postgres');
delete from public.tasks where id in (select id from public.tasks);   -- start the overdue scenario from a clean task table (cascades task_events)
insert into public.tasks (id, organization_id, location_id, title, status, due_at, completed_at, cancelled_at) values
  (pg_temp.id('od_open'),   pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'overdue open',        'open',        now() - interval '1 day', null, null),
  (pg_temp.id('od_prog'),   pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'overdue in progress', 'in_progress', now() - interval '2 hours', null, null),
  (pg_temp.id('od_done'),   pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'late but done',       'done',        now() - interval '1 day', now(), null),
  (pg_temp.id('od_canc'),   pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'late but cancelled',  'cancelled',   now() - interval '1 day', null, now()),
  (pg_temp.id('od_future'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'not yet due',         'open',        now() + interval '1 day', null, null),
  (pg_temp.id('od_nodue'),  pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'no due time',         'open',        null, null, null),
  (pg_temp.id('od_b'),      pg_temp.id('org_b'), pg_temp.id('loc_b1'), 'org B overdue',       'open',        now() - interval '3 hours', null, null);
update public.outbox_events set next_attempt_at = now() + interval '1 day', status = 'pending' where status <> 'done';   -- park older events
delete from public.outbox_events where type = 'task.overdue';
select pg_temp.act_as('service_role');
select is(pg_temp.try_msg($$select public.emit_overdue_task_events(0)$$), '22023 invalid limit', 'overdue: limit 0 is refused');
select is(pg_temp.try_msg($$select public.emit_overdue_task_events(5001)$$), '22023 invalid limit', 'overdue: limit 5001 is refused');
select is(public.emit_overdue_task_events(), 3, 'overdue: first run emits one event for each of the 3 open / in-progress tasks past due (not done, cancelled, future or undated)');
select is(public.emit_overdue_task_events(), 0, 'overdue: second run emits nothing (once per task per due time)');
select is(public.emit_overdue_task_events(), 0, 'overdue: a third run neither');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'task.overdue'), 3::bigint, 'exactly 3 task.overdue events exist');
select is((select array_agg(entity_id order by entity_id) from public.outbox_events where type = 'task.overdue'),
          (select array_agg(x order by x) from unnest(array[pg_temp.id('od_open'), pg_temp.id('od_prog'), pg_temp.id('od_b')]) x), 'for the right tasks');
select is((select count(*) from public.outbox_events e join public.tasks t on t.id = e.entity_id where e.type = 'task.overdue' and e.organization_id = t.organization_id and e.location_id = t.location_id
             and e.payload ->> 'task_id' = t.id::text and (e.payload ->> 'due_at')::timestamptz = t.due_at), 3::bigint, 'each event carries its task''s organization, location, id and due time');
select is((select count(*) from public.tasks where overdue_emitted_for = due_at), 3::bigint, 'the tasks remember the due time they were announced for');
-- a new due time makes it eligible again, once
update public.tasks set due_at = now() - interval '30 minutes' where id = pg_temp.id('od_open');
select pg_temp.act_as('service_role');
select is(public.emit_overdue_task_events(), 1, 'overdue: after the due time changed, the task is announced once more');
select is(public.emit_overdue_task_events(), 0, 'overdue: and then not again');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'task.overdue' and entity_id = pg_temp.id('od_open')), 2::bigint, 'two overdue events for that task (one per due time)');
-- a task closed after it was announced is not announced again; a limit is honoured
update public.tasks set status = 'done', completed_at = now() where id = pg_temp.id('od_prog');
update public.tasks set due_at = now() - interval '10 minutes' where id in (pg_temp.id('od_prog'), pg_temp.id('od_b'));
select pg_temp.act_as('service_role');
select is(public.emit_overdue_task_events(1), 1, 'overdue: the limit is honoured (one of the two changed tasks; the closed one never counts)');
select is(public.emit_overdue_task_events(10), 0, 'overdue: nothing left (the other changed task was done)');
-- a rule on task.overdue turns each overdue event into one task, once
select pg_temp.act_as('postgres');
update public.outbox_events set next_attempt_at = now() where type = 'task.overdue';
update public.tasks set due_at = null where id in (pg_temp.id('od_open'), pg_temp.id('od_b'));   -- stop further overdue noise
select pg_temp.fp('tasks') as f into temp table before_od;
select pg_temp.act_as('service_role');
select cmp_ok(pg_temp.run_worker('w10'), '>=', 3, 'the worker drains the overdue events');
select pg_temp.act_as('postgres');
select is((select count(*) from public.tasks where source_rule_id = pg_temp.id('rule_od')), 3::bigint, 'the A1 overdue rule created one task per overdue event at A1 (3: two for od_open''s two due times, one for od_prog); org B''s event created none');
select is((select count(*) from public.tasks where organization_id = pg_temp.id('org_b') and source_event_id is not null), 0::bigint, 'org B''s overdue event created nothing (the rule is org A''s)');
update public.outbox_events set status = 'pending', processed_at = null, attempts = 0, next_attempt_at = now() where type = 'task.overdue';
select pg_temp.fp('tasks') as f into temp table after_od1;
select pg_temp.act_as('service_role');
select pg_temp.run_worker('w11', false, false, true);
select pg_temp.act_as('postgres');
select is(pg_temp.fp('tasks'), (select f from after_od1), 'replaying the overdue events (ledger ignored) creates no further tasks');

-- ---------------------------------------------------------------------------
-- Scenario 6: notice.published fans out to the audience, once per person, also on replay
-- ---------------------------------------------------------------------------
select pg_temp.act_as('u_manager_a1');
insert into public.notices (id, organization_id, location_id, title, body) values (pg_temp.id('gate_notice'), pg_temp.id('org_a'), pg_temp.id('loc_a1'), 'Pool closed Friday', 'The pool is closed on Friday.');
insert into public.notice_audiences (organization_id, notice_id, location_id) values (pg_temp.id('org_a'), pg_temp.id('gate_notice'), pg_temp.id('loc_a1'));
select pg_temp.act_as('postgres');
update public.outbox_events set next_attempt_at = now() + interval '1 day' where status = 'pending';
select pg_temp.act_as('u_manager_a1');
select public.publish_notice(pg_temp.id('gate_notice'), now() + interval '1 hour');
select pg_temp.act_as('postgres');
select is((select count(*) from public.outbox_events where type = 'notice.published'), 1::bigint, 'publishing emitted exactly one notice.published event');
select is((select next_attempt_at from public.outbox_events where type = 'notice.published'), now() + interval '1 hour', 'scheduled for the publish time, not before');
select pg_temp.act_as('service_role');
select is((select count(*) from public.claim_outbox_events('w12', 10, 60) where type = 'notice.published'), 0::bigint, 'a worker does not pick up a scheduled notice before its time');
select pg_temp.act_as('postgres');
select pg_temp.act_as('service_role');
select is((select count(*) from public.notice_audience_person_ids(pg_temp.id('gate_notice'))), 0::bigint, 'fan-out: a notice that is published but not live yet (publish time an hour away) has no audience to notify');
select pg_temp.act_as('postgres');
-- the hour passes: the event is due and the notice is live
update public.outbox_events set next_attempt_at = now() where type = 'notice.published';
update public.notices set publish_at = now() where id = pg_temp.id('gate_notice');
select pg_temp.act_as('service_role');
select is((select array_agg(x order by x) from public.notice_audience_person_ids(pg_temp.id('gate_notice')) x),
          (select array_agg(p order by p) from unnest(array[pg_temp.id('p_orgadmin_a'), pg_temp.id('p_locadmin_a1'), pg_temp.id('p_manager_a1'), pg_temp.id('p_staff_a1')]) p),
  'the audience of an A1 "everyone" notice: org admin, A1 admin, manager A1, staff A1 (not staff A2 at another location, not the disabled account)');
select pg_temp.run_worker('w13');
select pg_temp.act_as('postgres');
select is((select count(*) from public.notifications where kind = 'notice.published'), 4::bigint, 'one notice notification per audience member (4)');
select is((select count(*) from (select person_id from public.notifications where kind = 'notice.published' group by 1 having count(*) > 1) d), 0::bigint, 'nobody was notified twice');
select pg_temp.fp('notifications') as f, pg_temp.fp('deliveries') as d into temp table notice_fp;
delete from public.outbox_event_handlers;
update public.outbox_events set status = 'pending', processed_at = null, attempts = 0, next_attempt_at = now() where type = 'notice.published';
select pg_temp.act_as('service_role');
select pg_temp.run_worker('w14', false, false, true);
select pg_temp.run_worker('w15', false, false, true);
select pg_temp.act_as('postgres');
select is(pg_temp.fp('notifications') || pg_temp.fp('deliveries'), (select f || d from notice_fp), 'replaying the notice event (ledger lost, twice): the same notifications and deliveries, same ids');

select pg_temp.act_as('postgres');
select * from finish();
rollback;
