-- Phase 1 (roadmap 1.5): append-only audit log, written by a generic trigger
-- in the same transaction as the change.
--
-- To audit a new table (later phases), one line:
--   select private.enable_audit('public.my_table');
-- with redacted columns (values replaced by "[redacted]", the column name is
-- still listed in changed_columns):
--   select private.enable_audit('public.incident_sensitive_details', 'id', array['injury_description', 'treatment']);
-- For a table whose primary key column is not "id", pass it as the 2nd argument.

create table public.audit_log (
  id bigint generated always as identity primary key,
  occurred_at timestamptz not null default now(),          -- transaction start time
  transaction_id bigint not null default (pg_catalog.pg_current_xact_id()::text::bigint),
  organization_id uuid,      -- null only for platform-level rows (modules, system roles, platform_admins)
  location_id uuid,
  actor_user_id uuid,        -- auth.uid() at the time, null for service_role/migrations without a JWT
  actor_person_id uuid,      -- caller's person in organization_id, if any
  actor_role text not null,  -- database role: authenticated / service_role / postgres / ...
  action text not null check (action in ('insert', 'update', 'delete')),
  table_schema text not null,
  table_name text not null,
  row_id text,               -- the row's primary key as text
  old_row jsonb,
  new_row jsonb,
  changed_columns text[]     -- update: columns whose value changed (updated_at excluded); null otherwise
);
-- No foreign keys on purpose: audit rows outlive the rows (and organizations) they describe.

create index audit_log_org_occurred_idx on public.audit_log (organization_id, occurred_at desc);
create index audit_log_location_occurred_idx on public.audit_log (location_id, occurred_at desc)
  where location_id is not null;
create index audit_log_table_row_idx on public.audit_log (table_name, row_id);
create index audit_log_actor_user_idx on public.audit_log (actor_user_id) where actor_user_id is not null;

-- ---------------------------------------------------------------------------
-- Append-only: UPDATE, DELETE and TRUNCATE raise for every role, including
-- service_role and the table owner. (Only dropping/disabling the trigger,
-- which needs table ownership, gets around this; see SECURITY.md.)
-- ---------------------------------------------------------------------------
create function private.tg_audit_log_append_only()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'audit_log is append-only (% blocked)', tg_op using errcode = 'insufficient_privilege';
end;
$$;
revoke all on function private.tg_audit_log_append_only() from public, anon, authenticated;

create trigger audit_log_no_update_delete before update or delete on public.audit_log
  for each row execute function private.tg_audit_log_append_only();
create trigger audit_log_no_truncate before truncate on public.audit_log
  for each statement execute function private.tg_audit_log_append_only();

-- ---------------------------------------------------------------------------
-- Generic row audit trigger.
-- tg_argv[0] = primary key column (default 'id'); tg_argv[1..] = columns to redact.
-- organization_id / location_id are read from the row's columns of those
-- names; for organizations the row's id is the organization, for locations
-- the row's id is the location.
-- ---------------------------------------------------------------------------
create function private.tg_audit_row()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_old jsonb := case when tg_op in ('UPDATE', 'DELETE') then to_jsonb(old) end;
  v_new jsonb := case when tg_op in ('INSERT', 'UPDATE') then to_jsonb(new) end;
  v_row jsonb := coalesce(v_new, v_old);
  v_pk text := coalesce(tg_argv[0], 'id');
  v_changed text[];
  v_org uuid;
  v_loc uuid;
  v_uid uuid := auth.uid();
  v_role text := current_setting('role', true);
  v_col text;
  i integer;
begin
  if tg_op = 'UPDATE' then
    select array_agg(n.key order by n.key) into v_changed
    from jsonb_each(v_new) n
    where n.key <> 'updated_at' and n.value is distinct from (v_old -> n.key);
    if v_changed is null then
      return null; -- no-op update: nothing to record
    end if;
  end if;

  -- Redact listed columns (keep nulls as null so "was it set" stays visible).
  if tg_nargs > 1 then
    for i in 1 .. tg_nargs - 1 loop
      v_col := tg_argv[i];
      if v_old ? v_col and v_old -> v_col <> 'null'::jsonb then
        v_old := jsonb_set(v_old, array[v_col], '"[redacted]"'::jsonb);
      end if;
      if v_new ? v_col and v_new -> v_col <> 'null'::jsonb then
        v_new := jsonb_set(v_new, array[v_col], '"[redacted]"'::jsonb);
      end if;
    end loop;
  end if;

  if tg_table_schema = 'public' and tg_table_name = 'organizations' then
    v_org := (v_row ->> 'id')::uuid;
  else
    v_org := (v_row ->> 'organization_id')::uuid;
  end if;
  if tg_table_schema = 'public' and tg_table_name = 'locations' then
    v_loc := (v_row ->> 'id')::uuid;
  else
    v_loc := (v_row ->> 'location_id')::uuid;
  end if;

  if v_role is null or v_role = 'none' then
    v_role := session_user;
  end if;

  insert into public.audit_log (
    organization_id, location_id, actor_user_id, actor_person_id, actor_role,
    action, table_schema, table_name, row_id, old_row, new_row, changed_columns)
  values (
    v_org, v_loc, v_uid,
    case when v_uid is not null and v_org is not null then
      (select a.person_id from public.accounts a where a.user_id = v_uid and a.organization_id = v_org)
    end,
    v_role,
    lower(tg_op), tg_table_schema, tg_table_name, v_row ->> v_pk,
    v_old, v_new, v_changed);
  return null;
end;
$$;
revoke all on function private.tg_audit_row() from public, anon, authenticated;

-- One-line attach for any table. Idempotent (replaces the trigger).
create function private.enable_audit(
  p_table regclass, p_pk_column text default 'id', p_redact text[] default '{}')
returns void
language plpgsql
set search_path = ''
as $$
declare
  v_args text := pg_catalog.quote_literal(p_pk_column);
  v_col text;
begin
  foreach v_col in array p_redact loop
    v_args := v_args || ', ' || pg_catalog.quote_literal(v_col);
  end loop;
  if exists (select 1 from pg_catalog.pg_trigger t where t.tgrelid = p_table and t.tgname = 'zz_audit') then
    execute format('drop trigger zz_audit on %s', p_table);
  end if;
  execute format(
    'create trigger zz_audit after insert or update or delete on %s '
    'for each row execute function private.tg_audit_row(%s)', p_table, v_args);
end;
$$;
revoke all on function private.enable_audit(regclass, text, text[]) from public, anon, authenticated;

-- Attach to every Phase 1 table.
do $$
begin
  perform private.enable_audit('public.organizations');
  perform private.enable_audit('public.organization_settings');
  perform private.enable_audit('public.locations');
  perform private.enable_audit('public.space_kinds');
  perform private.enable_audit('public.spaces');
  perform private.enable_audit('public.space_hours');
  perform private.enable_audit('public.space_closures');
  perform private.enable_audit('public.platform_admins', 'user_id');
  perform private.enable_audit('public.modules', 'key');
  perform private.enable_audit('public.roles');
  perform private.enable_audit('public.role_default_permissions');
  perform private.enable_audit('public.people');
  perform private.enable_audit('public.accounts');
  perform private.enable_audit('public.role_assignments');
  perform private.enable_audit('public.user_permissions');
  perform private.enable_audit('public.job_titles');
  perform private.enable_audit('public.person_job_titles');
end;
$$;

-- ---------------------------------------------------------------------------
-- Access: platform admins; audit_log >= view at org scope sees every row of
-- that org; at a location sees rows whose location_id is that location.
-- No insert/update/delete for authenticated (no grant, no policy).
-- ---------------------------------------------------------------------------
alter table public.audit_log enable row level security;

create policy audit_log_select on public.audit_log for select to authenticated
  using ((select public.is_platform_admin())
         or organization_id in (select private.permitted_org_ids('audit_log', 'view'))
         or location_id in (select private.permitted_location_ids('audit_log', 'view')));

revoke all on table public.audit_log from public, anon, authenticated, service_role;
grant select on table public.audit_log to authenticated;
-- service_role may append (e.g. future "sensitive record viewed" events) and read.
grant select, insert on table public.audit_log to service_role;
