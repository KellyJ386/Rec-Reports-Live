-- Phase 2: communications.
--
--   notices            announcements to an audience (draft -> published -> archived)
--   notice_audiences   who a notice is for: (location or whole org) x (job title or everyone)
--   acknowledgments    one per person per notice, written once, never changed
--   messages           direct / group messages between people
--   message_recipients one row per recipient, with read_at
--
-- Permission levels on the `communications` module (seeded defaults: staff =
-- edit, manager = admin, admin = admin):
--   view   read notices you are in the audience of; read your own messages
--   edit   also send messages (to people you can already see)
--   admin  manage notices in scope: write drafts, choose the audience,
--          publish, archive, see who acknowledged
-- A notice has a home scope (location_id null = organization). Managing it
-- needs communications = admin in that scope; a location notice can only
-- target its own location.
--
-- Messages are private to sender and recipients. Nobody else can read them:
-- not managers, not organization admins, not platform admins (no exception;
-- the Phase 1 platform-admin shortcut is deliberately not applied here). The
-- audit log redacts message bodies, and message events carry ids only.
--
-- Job titles only select an audience among people who are already members
-- covering the audience's location with communications >= view. They grant
-- nothing else.

-- ---------------------------------------------------------------------------
-- notices
-- ---------------------------------------------------------------------------
create table public.notices (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid,    -- home scope: null = organization-wide notice
  title text not null check (char_length(btrim(title)) between 1 and 200),
  body text not null check (char_length(btrim(body)) between 1 and 5000),
  urgency text not null default 'normal' check (urgency in ('normal', 'high', 'critical')),
  requires_acknowledgment boolean not null default false,
  publish_at timestamptz,          -- when it becomes visible (set at publish if empty)
  expires_at timestamptz,          -- hidden from the audience after this
  status text not null default 'draft' check (status in ('draft', 'published', 'archived')),
  author_person_id uuid,           -- set by trigger to the caller's person
  published_at timestamptz,
  published_by_person_id uuid,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  check (expires_at is null or publish_at is null or expires_at > publish_at),
  check (status <> 'published' or (publish_at is not null and published_at is not null)),
  check ((status = 'archived') = (archived_at is not null)),
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (author_person_id, organization_id) references public.people (id, organization_id),
  foreign key (published_by_person_id, organization_id) references public.people (id, organization_id)
);

create index notices_org_status_idx on public.notices (organization_id, status, publish_at desc);
create index notices_location_idx on public.notices (location_id, organization_id) where location_id is not null;
create index notices_author_idx on public.notices (author_person_id, organization_id) where author_person_id is not null;
create index notices_published_by_idx on public.notices (published_by_person_id, organization_id)
  where published_by_person_id is not null;

-- New notices are drafts written by the caller. (Column grants already keep
-- status and author out of tenant hands; this also covers service code.)
create function private.tg_notices_new()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.assert_member_of(new.organization_id);
  new.status := 'draft';
  new.published_at := null;
  new.published_by_person_id := null;
  new.archived_at := null;
  if (select auth.uid()) is not null then
    new.author_person_id := public.current_person_id(new.organization_id);
  end if;
  return new;
end;
$$;
revoke all on function private.tg_notices_new() from public, anon, authenticated;

create trigger notices_new before insert on public.notices
  for each row execute function private.tg_notices_new();
create trigger notices_timestamps before insert or update on public.notices
  for each row execute function private.tg_set_timestamps();
create trigger notices_immutable before update on public.notices
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id', 'author_person_id');

-- ---------------------------------------------------------------------------
-- notice_audiences
-- ---------------------------------------------------------------------------
create table public.notice_audiences (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  notice_id uuid not null,
  location_id uuid,      -- null = every location of the organization
  job_title_id uuid,     -- null = everyone (in that location / the organization)
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique nulls not distinct (notice_id, location_id, job_title_id),
  foreign key (notice_id, organization_id) references public.notices (id, organization_id) on delete cascade,
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (job_title_id, organization_id) references public.job_titles (id, organization_id)
);

create index notice_audiences_notice_idx on public.notice_audiences (organization_id, notice_id);
create index notice_audiences_location_idx on public.notice_audiences (location_id, organization_id) where location_id is not null;
create index notice_audiences_job_title_idx on public.notice_audiences (job_title_id, organization_id) where job_title_id is not null;

create trigger notice_audiences_timestamps before insert or update on public.notice_audiences
  for each row execute function private.tg_set_timestamps();
create trigger notice_audiences_immutable before update on public.notice_audiences
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'notice_id', 'location_id', 'job_title_id');

-- ---------------------------------------------------------------------------
-- acknowledgments (written once by acknowledge_notice, never changed)
-- ---------------------------------------------------------------------------
create table public.acknowledgments (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  notice_id uuid not null,
  person_id uuid not null,
  acknowledged_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (notice_id, person_id),
  foreign key (notice_id, organization_id) references public.notices (id, organization_id) on delete cascade,
  foreign key (person_id, organization_id) references public.people (id, organization_id)
);

create index acknowledgments_notice_idx on public.acknowledgments (organization_id, notice_id);
create index acknowledgments_person_idx on public.acknowledgments (person_id, organization_id);

create trigger acknowledgments_timestamps before insert on public.acknowledgments
  for each row execute function private.tg_set_timestamps();
create trigger acknowledgments_append_only before update on public.acknowledgments
  for each row execute function private.tg_append_only();
create trigger acknowledgments_immutable before update on public.acknowledgments
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'notice_id', 'person_id');

-- ---------------------------------------------------------------------------
-- messages / message_recipients (written only by send_message)
-- ---------------------------------------------------------------------------
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  sender_person_id uuid not null,
  body text not null check (char_length(btrim(body)) between 1 and 4000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  foreign key (sender_person_id, organization_id) references public.people (id, organization_id)
);

create index messages_sender_idx on public.messages (organization_id, sender_person_id, created_at desc);

create table public.message_recipients (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  message_id uuid not null,
  person_id uuid not null,
  read_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (message_id, person_id),
  foreign key (message_id, organization_id) references public.messages (id, organization_id) on delete cascade,
  foreign key (person_id, organization_id) references public.people (id, organization_id)
);

create index message_recipients_message_idx on public.message_recipients (organization_id, message_id);
create index message_recipients_person_idx on public.message_recipients (person_id, organization_id, read_at);

create trigger messages_timestamps before insert or update on public.messages
  for each row execute function private.tg_set_timestamps();
create trigger messages_immutable before update on public.messages
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'sender_person_id', 'body', 'created_at');
create trigger message_recipients_timestamps before insert or update on public.message_recipients
  for each row execute function private.tg_set_timestamps();
create trigger message_recipients_immutable before update on public.message_recipients
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'message_id', 'person_id');

-- Audit (bodies redacted: the audit log must not become a way to read
-- messages, and notice text stays in the notice).
do $$
begin
  perform private.enable_audit('public.notices', 'id', array['body']);
  perform private.enable_audit('public.notice_audiences');
  perform private.enable_audit('public.acknowledgments');
  perform private.enable_audit('public.messages', 'id', array['body']);
  perform private.enable_audit('public.message_recipients');
end;
$$;

-- ---------------------------------------------------------------------------
-- Access helpers
-- ---------------------------------------------------------------------------
create function private.can_manage_notice(p_organization_id uuid, p_location_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.has_permission(p_organization_id, p_location_id, 'communications', 'admin')
$$;

create function private.can_manage_notice_id(p_notice_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.notices n
                 where n.id = p_notice_id and private.can_manage_notice(n.organization_id, n.location_id))
$$;

-- May the caller add or remove this audience row? The notice must be a draft
-- the caller manages, in the same organization, and a location notice can
-- only target its own location.
create function private.can_edit_notice_audience(p_notice_id uuid, p_organization_id uuid, p_location_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.notices n
    where n.id = p_notice_id and n.organization_id = p_organization_id and n.status = 'draft'
      and private.can_manage_notice(n.organization_id, n.location_id)
      and (n.location_id is null or n.location_id = p_location_id))
$$;

-- THE audience rule, for any person (one implementation, used by the read
-- policy for the caller and by the worker's fan-out for everyone):
-- an audience row matches a person when
--   * scope: the person has communications >= view at the row's location
--     (row location null: at organization scope or at any location where they
--     hold an assignment). This uses private.person_effective_level, so it
--     needs an active account, a non-archived person and a covering
--     assignment, and for the caller applies the admin-tier MFA rule; and
--   * job title (if the row has one): the person holds that non-archived
--     title everywhere, or at the row's location (row location null: anywhere).
create function private.person_in_notice_audience(p_notice_id uuid, p_person_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select p_person_id is not null and exists (
    select 1
    from public.notice_audiences a
    join public.people p on p.id = p_person_id and p.organization_id = a.organization_id
    where a.notice_id = p_notice_id
      and (case
             when a.location_id is not null then
               coalesce(private.person_effective_level(a.organization_id, p_person_id, a.location_id, 'communications')
                        >= 'view', false)
             else
               coalesce(private.person_effective_level(a.organization_id, p_person_id, null, 'communications')
                        >= 'view', false)
               or exists (
                 select 1 from public.role_assignments ra
                 where ra.person_id = p_person_id and ra.organization_id = a.organization_id
                   and ra.location_id is not null
                   and coalesce(private.person_effective_level(a.organization_id, p_person_id, ra.location_id,
                                                               'communications') >= 'view', false))
           end)
      and (a.job_title_id is null or exists (
             select 1 from public.person_job_titles pjt
             join public.job_titles jt on jt.id = pjt.job_title_id and jt.archived_at is null
             where pjt.person_id = p_person_id
               and pjt.job_title_id = a.job_title_id
               and (pjt.location_id is null or a.location_id is null or pjt.location_id = a.location_id))))
$$;
revoke all on function private.person_in_notice_audience(uuid, uuid) from public, anon, authenticated;

-- Is the caller in the notice's audience?
create function private.in_notice_audience(p_notice_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.notices n
    where n.id = p_notice_id
      and private.person_in_notice_audience(n.id, public.current_person_id(n.organization_id)))
$$;

-- Audience members may read a notice while it is published and live.
create function private.can_read_notice_as_audience(
  p_notice_id uuid, p_status text, p_publish_at timestamptz, p_expires_at timestamptz)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(p_status = 'published' and p_publish_at <= now()
     and (p_expires_at is null or p_expires_at > now())
     and private.in_notice_audience(p_notice_id), false)
$$;

create function private.is_message_party(p_message_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.messages m
                 where m.id = p_message_id and m.sender_person_id in (select private.my_person_ids()))
      or exists (select 1 from public.message_recipients r
                 where r.message_id = p_message_id and r.person_id in (select private.my_person_ids()))
$$;

create function private.is_message_sender(p_message_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.messages m
                 where m.id = p_message_id and m.sender_person_id in (select private.my_person_ids()))
$$;

revoke all on function
  private.can_manage_notice(uuid, uuid), private.can_manage_notice_id(uuid),
  private.can_edit_notice_audience(uuid, uuid, uuid), private.in_notice_audience(uuid),
  private.can_read_notice_as_audience(uuid, text, timestamptz, timestamptz),
  private.is_message_party(uuid), private.is_message_sender(uuid)
from public, anon, authenticated;
grant execute on function
  private.can_manage_notice(uuid, uuid), private.can_manage_notice_id(uuid),
  private.can_edit_notice_audience(uuid, uuid, uuid), private.in_notice_audience(uuid),
  private.can_read_notice_as_audience(uuid, text, timestamptz, timestamptz),
  private.is_message_party(uuid), private.is_message_sender(uuid)
to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- RPCs (authenticated). 42501 'not allowed' never says whether a row exists.
-- ---------------------------------------------------------------------------

-- Publish a draft. p_publish_at null = the draft's publish_at, else now; a time
-- in the past means now. Needs at least one audience row. Emits
-- notice.published, which workers pick up at publish_at (not before).
create function public.publish_notice(p_notice_id uuid, p_publish_at timestamptz default null)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_n public.notices%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_n from public.notices n where n.id = p_notice_id for update;
  if not found or not private.can_manage_notice(v_n.organization_id, v_n.location_id) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if v_n.status <> 'draft' then
    raise exception 'only a draft can be published' using errcode = 'invalid_parameter_value';
  end if;
  if not exists (select 1 from public.notice_audiences a where a.notice_id = v_n.id) then
    raise exception 'choose who the notice is for first' using errcode = 'invalid_parameter_value';
  end if;
  update public.notices n
  set status = 'published',
      publish_at = greatest(coalesce(p_publish_at, n.publish_at, now()), now()),
      published_at = now(),
      published_by_person_id = public.current_person_id(n.organization_id)
  where n.id = v_n.id
  returning * into v_n;
  if v_n.expires_at is not null and v_n.expires_at <= v_n.publish_at then
    raise exception 'the notice would expire before it is shown' using errcode = 'invalid_parameter_value';
  end if;
  perform private.emit_event(
    v_n.organization_id, v_n.location_id, 'notice.published', 'notices', v_n.id,
    jsonb_build_object('notice_id', v_n.id, 'location_id', v_n.location_id, 'urgency', v_n.urgency,
                       'requires_acknowledgment', v_n.requires_acknowledgment,
                       'publish_at', v_n.publish_at, 'expires_at', v_n.expires_at),
    1, null, v_n.publish_at);
end;
$$;

-- draft | published -> archived. Emits notice.archived.
create function public.archive_notice(p_notice_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_n public.notices%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_n from public.notices n where n.id = p_notice_id for update;
  if not found or not private.can_manage_notice(v_n.organization_id, v_n.location_id) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if v_n.status = 'archived' then
    raise exception 'this notice is already archived' using errcode = 'invalid_parameter_value';
  end if;
  update public.notices n
  set status = 'archived', archived_at = now()
  where n.id = v_n.id;
  perform private.emit_event(
    v_n.organization_id, v_n.location_id, 'notice.archived', 'notices', v_n.id,
    jsonb_build_object('notice_id', v_n.id, 'location_id', v_n.location_id));
end;
$$;

-- The caller acknowledges a live notice they are in the audience of.
-- Idempotent: a second call writes nothing and returns the first time.
-- Emits notice.acknowledged once, on the first call.
create function public.acknowledge_notice(p_notice_id uuid)
returns timestamptz
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_n public.notices%rowtype;
  v_me uuid;
  v_at timestamptz;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_n from public.notices n where n.id = p_notice_id;
  if not found
     or private.can_read_notice_as_audience(v_n.id, v_n.status, v_n.publish_at, v_n.expires_at) is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  v_me := public.current_person_id(v_n.organization_id);
  if v_me is null then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  insert into public.acknowledgments (organization_id, notice_id, person_id)
  values (v_n.organization_id, v_n.id, v_me)
  on conflict (notice_id, person_id) do nothing
  returning acknowledged_at into v_at;
  if v_at is not null then
    perform private.emit_event(
      v_n.organization_id, v_n.location_id, 'notice.acknowledged', 'notices', v_n.id,
      jsonb_build_object('notice_id', v_n.id, 'person_id', v_me));
    return v_at;
  end if;
  select a.acknowledged_at into v_at from public.acknowledgments a
  where a.notice_id = v_n.id and a.person_id = v_me;
  return v_at;
end;
$$;

-- Send a message to 1-50 people the caller can already see in that
-- organization (not archived, not themselves). Needs communications >= edit in
-- some scope of the organization. Any recipient that fails the check refuses
-- the whole message with the same error (it does not say which). Emits
-- message.sent with ids only. Returns the message id.
create function public.send_message(p_organization_id uuid, p_recipient_person_ids uuid[], p_body text)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_recipients uuid[];
  v_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  v_me := public.current_person_id(p_organization_id);
  if v_me is null or not private.has_permission_anywhere(p_organization_id, 'communications', 'edit') then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  select coalesce(array_agg(distinct r), '{}') into v_recipients
  from unnest(coalesce(p_recipient_person_ids, '{}')) r where r is not null;
  if cardinality(v_recipients) not between 1 and 50 then
    raise exception 'choose 1 to 50 people' using errcode = 'invalid_parameter_value';
  end if;
  if p_body is null or char_length(btrim(p_body)) not between 1 and 4000 then
    raise exception 'a message needs 1 to 4000 characters' using errcode = 'invalid_parameter_value';
  end if;
  if v_me = any (v_recipients)
     or exists (
       select 1 from unnest(v_recipients) r
       where not exists (select 1 from public.people p
                         where p.id = r and p.organization_id = p_organization_id and p.archived_at is null)
          or r not in (select private.visible_person_ids())) then
    raise exception 'you cannot message one or more of these people' using errcode = 'insufficient_privilege';
  end if;

  insert into public.messages (organization_id, sender_person_id, body)
  values (p_organization_id, v_me, btrim(p_body))
  returning id into v_id;
  insert into public.message_recipients (organization_id, message_id, person_id)
  select p_organization_id, v_id, r from unnest(v_recipients) r;

  perform private.emit_event(
    p_organization_id, null, 'message.sent', 'messages', v_id,
    jsonb_build_object('message_id', v_id, 'sender_person_id', v_me,
                       'recipient_person_ids', to_jsonb(v_recipients)));
  return v_id;
end;
$$;

-- Mark a message read for the caller (a recipient). Idempotent; keeps the
-- first read time.
create function public.mark_message_read(p_message_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if not exists (select 1 from public.message_recipients r
                 where r.message_id = p_message_id and r.person_id in (select private.my_person_ids())) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  update public.message_recipients r set read_at = now()
  where r.message_id = p_message_id and r.person_id in (select private.my_person_ids()) and r.read_at is null;
end;
$$;

revoke all on function
  public.publish_notice(uuid, timestamptz), public.archive_notice(uuid), public.acknowledge_notice(uuid),
  public.send_message(uuid, uuid[], text), public.mark_message_read(uuid)
from public, anon, authenticated;
grant execute on function
  public.publish_notice(uuid, timestamptz), public.archive_notice(uuid), public.acknowledge_notice(uuid),
  public.send_message(uuid, uuid[], text), public.mark_message_read(uuid)
to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- RLS, policies, grants
-- ---------------------------------------------------------------------------
alter table public.notices enable row level security;
alter table public.notice_audiences enable row level security;
alter table public.acknowledgments enable row level security;
alter table public.messages enable row level security;
alter table public.message_recipients enable row level security;

create policy notices_select on public.notices for select to authenticated
  using (private.can_manage_notice(organization_id, location_id)
         or private.can_read_notice_as_audience(id, status, publish_at, expires_at));
create policy notices_insert on public.notices for insert to authenticated
  with check (private.can_manage_notice(organization_id, location_id));
create policy notices_update on public.notices for update to authenticated
  using (status = 'draft' and private.can_manage_notice(organization_id, location_id))
  with check (status = 'draft' and private.can_manage_notice(organization_id, location_id));
create policy notices_delete on public.notices for delete to authenticated
  using (status = 'draft' and private.can_manage_notice(organization_id, location_id));

create policy notice_audiences_select on public.notice_audiences for select to authenticated
  using (private.can_manage_notice_id(notice_id));
create policy notice_audiences_insert on public.notice_audiences for insert to authenticated
  with check (private.can_edit_notice_audience(notice_id, organization_id, location_id));
create policy notice_audiences_delete on public.notice_audiences for delete to authenticated
  using (private.can_edit_notice_audience(notice_id, organization_id, location_id));

create policy acknowledgments_select on public.acknowledgments for select to authenticated
  using (person_id in (select private.my_person_ids()) or private.can_manage_notice_id(notice_id));

create policy messages_select on public.messages for select to authenticated
  using (private.is_message_party(id));

create policy message_recipients_select on public.message_recipients for select to authenticated
  using (person_id in (select private.my_person_ids()) or private.is_message_sender(message_id));

revoke all on table public.notices, public.notice_audiences, public.acknowledgments,
  public.messages, public.message_recipients
from public, anon, authenticated, service_role;

grant select on table public.notices, public.notice_audiences, public.acknowledgments,
  public.messages, public.message_recipients
to authenticated, service_role;
grant insert (id, organization_id, location_id, title, body, urgency, requires_acknowledgment, publish_at, expires_at)
  on public.notices to authenticated;
grant update (title, body, urgency, requires_acknowledgment, publish_at, expires_at) on public.notices to authenticated;
grant delete on public.notices to authenticated;
grant insert (id, organization_id, notice_id, location_id, job_title_id) on public.notice_audiences to authenticated;
grant delete on public.notice_audiences to authenticated;
