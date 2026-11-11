# Security

Baseline: OWASP ASVS Level 2, with stricter controls on incident injury details.

## Roles (pilot)

Same model as RinkReports Pro (see `docs/REUSE_INVENTORY.md`):

| Role | Scope | Rank | Default use |
| --- | --- | --- | --- |
| `super_admin` | Platform | 100 | Max Facility staff only. A row in `platform_admins`, never a tenant role assignment. |
| `admin` | Organization or location | 80 (90 at org scope) | Users, roles, settings, everything in scope |
| `manager` | Location | 50 | Configure spaces, templates, forms, schedules; review incidents |
| `staff` | Location | 10 | Own shift, own tasks, checklists, file incidents, read notices |
| custom roles | Location (defined per organization) | 1-79 | Defined per organization by org-scope admins |

- Roles only seed defaults (`role_default_permissions`). What a person can do is their effective permission (module x level), see below.
- Job titles (`job_titles`) route tasks and notices ("Lifeguard", "Front Desk"). They grant no permissions. A policy may use them only to **narrow** what a member already permitted in that scope sees (which tasks at a location are theirs, which notices they are the audience of); never to give reach to a location, an organization or a module. Adding a job title to someone therefore exposes at most the tasks and notices routed to that title in a scope where they already have the module.
- Do not use `org_admin`, `facility_manager`, `gm` or `supervisor` as role keys (a check constraint rejects them). "Supervisor" is a job title.

## Access model (built in Phase 1)

**Membership.** A user is a member of an organization when they have an `accounts` row there with `disabled_at` null, their `people` row is not archived, and they hold at least one `role_assignments` row on a non-archived role (at a non-archived location, if location scoped). A `user_permissions` row alone grants nothing. A non-member sees nothing at all, including modules and system roles.

**Admin tier needs MFA (`aal2`)** (migration `20261112000100_auth_hardening`). Platform-admin status, and every assignment whose effective rank is >= 80 (admin at a location = 80, admin at organization scope = 90), count only when the session JWT has `aal` = `aal2` (`auth.jwt() ->> 'aal'`; Supabase Auth issues `aal1` after the first factor and `aal2` after a verified MFA challenge; a token without the claim is `aal1`). At `aal1` those grants are treated as if they did not exist: an admin-only user is a non-member (sees nothing, can do nothing), and someone who is admin at one location and staff at another keeps exactly the staff access. It is applied once, in the two cores everything else is built on: `private.my_assignments()` (the caller's assignments) and `private.person_effective_level()` when the person is the caller's own; plus `public.is_platform_admin()`. Every helper, policy, trigger and RPC inherits it. The threshold lives in `private.admin_tier_min_rank()` (80). A **target's** rank for the tier rule (`private.person_max_rank`) and `person_effective_permission` about **another** person are not affected, so an admin always counts at full rank as a target. `public.session_needs_mfa()` returns true when the caller holds admin-tier access that is suppressed right now, so the app can send them to the second-step screen. **Voluntary MFA** (since `20261112000600`): a user who has a verified factor (`auth.mfa_factors`, `status = 'verified'`) needs `aal2` for **any** grant to count, whatever their rank; at `aal1` they are a non-member everywhere and `session_needs_mfa()` is true for them. Same two cores (`private.user_has_verified_mfa(uid)` inside `my_assignments` and the caller's own `person_effective_level`). If `auth.mfa_factors` does not exist (the plain-Postgres stand-in), nobody has a verified factor, which equals the old rule. Consequences to know: an `aal1` admin-only user also cannot read their own messages and notifications or edit their own profile until they pass MFA (they are a non-member until then).

**Effective rank.** `roles.rank`, plus 10 when the assignment is organization scoped. So: org admin 90, location admin 80, manager 50, staff 10, custom 1-79, platform admin 100. A person's rank in scope is the highest of their assignments at org scope or at that location.

**Effective permission** (`effective_permission(org, location, module)`), levels `none < view < edit < admin`:
0. The scope must exist: `location` null means the organization exists; otherwise the location must belong to that organization. A scope that doesn't exist gives `none` / false / rank 0, even for platform admins.
1. No assignment covering the scope (org scope for `location` null; org scope or that location otherwise) → `none`, and `has_permission` is **false at every level, `none` included** (it answers "is a member in this scope and has at least this level").
2. Else a `user_permissions` row for that person, module and location → its level.
3. Else a `user_permissions` row for that person and module with `location_id` null → its level.
4. Else the highest `role_default_permissions` level among the roles covering the scope; else `none`.
Overrides can raise or lower. Platform admins always get `admin`. One implementation, `private.person_effective_level(org, person, location, module)`, backs both `effective_permission` (the caller) and `person_effective_permission` (another person), so the two can't drift.

`people_roles` levels: `admin` = manage people, accounts, role assignments and user permissions; `edit` = assign job titles only; `view` = nothing extra in Phase 1. Seeded defaults: admin = `admin` on every module; manager = no `people_roles` admin (`edit`), `audit_log` none, `accidents` none, mostly `admin` on operational modules; staff = `none` on `people_roles`, `audit_log`, `accidents`, `reports`, otherwise `view`/`edit`. Filing an accident by staff must come from the Phase 4 "filer" rule, not from the `accidents` level.

**Tier rule** (enforced by RLS, so it holds for any client using the user's JWT). A user can create or remove a role assignment, create/change/remove a `user_permissions` row, change or remove an account, or change a person only when:
- they hold `people_roles` = `admin` in that scope (a location-scoped admin has no org scope, so can never touch org-scope assignments or org-wide overrides, and acts only on people assigned at their location);
- the target's highest rank anywhere in the organization is strictly below the actor's rank in scope;
- any role being granted ranks (with its scope) strictly below the actor's rank;
- **permission cap:** for `user_permissions`, the level granted is at most the actor's own effective level for that module in that scope. For a role assignment (grant or removal), every `role_default_permissions` row of that role must be at or below the actor's own effective level for its module in that scope. For custom role defaults, an org admin can set a level only up to their own organization-scope level for that module;
- **visibility:** the target must be visible to the actor (see Reads). The old "or has no assignments yet" exception is gone, so a location admin can't claim unassigned or offboarded people;
- **archived targets:** an archived person can be changed (assignments, overrides, account, person row, un-archiving) only by an organization-scope `people_roles` admin;
- **last assignment:** only an organization-scope `people_roles` admin (or a platform admin, or service code without a user JWT) can remove a person's last role assignment. It is checked at end of statement by the `role_assignments_keep_last` trigger. Location admins offboard someone by archiving them. This keeps every person visible to the location that manages them;
- the target is not themselves. Nobody changes their own roles, permissions, account or person row through the tables. The one exception is `update_own_profile` (below), which edits only `preferred_name` and `phone`.

Consequences: an org admin (90) can create and remove location admins (80) but not other org admins; creating or removing an org admin needs a platform admin or the service role. A location admin (80) can't create another admin.

**Reads.**

| Data | Who reads |
| --- | --- |
| `organizations`, `organization_settings`, `locations`, `space_kinds`, `spaces`, `space_hours`, `space_closures`, `job_titles`, custom `roles` and their defaults | Every member of the organization (data class Public) |
| `modules`, system `roles` and their defaults | Any member of any organization |
| `people`, `role_assignments`, `person_job_titles` | Org-scope assignment holders: everyone in the org. Location-scoped users: people holding an assignment at one of their own locations, plus themselves. People with no assignments are visible only to org-scope users. |
| `accounts`, `user_permissions` | Own rows, plus people with `people_roles` = `admin` in scope (org scope: all; location: people assigned there) |
| `audit_log` | `audit_log` >= `view`: at org scope every row of the org; at a location only rows whose `location_id` is that location |
| `platform_admins` | Nobody but service_role |
| `outbox_events`, `outbox_event_handlers` | Same rule as `audit_log` (`audit_log` >= `view`; org scope all events of the org, a location only events with that `location_id`; org-wide events need org scope). This is the "failed jobs" screen. |
| `task_templates`, `workflow_rules` | `tasks` = `admin` at the row's location; an org-wide row (`location_id` null) by anyone with `tasks` = `admin` at org scope or at any location of the org |
| `tasks`, `task_events` | `tasks` = `admin` at the location: every task there. `tasks` >= `view` at the location: tasks assigned to them; tasks with no person assigned and either no job title or a job title they hold there (title at that location or everywhere); unassigned tasks. History rows follow their task. |
| `notices` | `communications` = `admin` in the notice's home scope (`location_id`, null = org); otherwise only while published, `publish_at` <= now, not expired, and the caller is in its audience (see Communications) |
| `notice_audiences` | `communications` = `admin` in the notice's home scope |
| `acknowledgments` | Own rows, plus `communications` = `admin` in the notice's home scope |
| `messages`, `message_recipients` | Sender and recipients only. **No admin or platform-admin exception.** A sender sees the recipient rows (and `read_at`) of their own messages. |
| `notifications`, `notification_deliveries`, `push_subscriptions`, `notification_preferences` | The person themselves only, no platform-admin exception. Deliveries: status columns only (no provider id, no error). Push subscriptions: never `endpoint`, `p256dh` or `auth_secret` (not even the owner; only service_role). |
| `positions`, `qualifications`, `position_qualifications` | Members with `staff_schedule` >= `view` at org scope or at any location of the org (Phase 3) |
| `person_qualifications` | The person, plus `staff_schedule` >= `edit` over that person (org scope, or a location where they hold an assignment) |
| `schedules` | `staff_schedule` >= `edit` at the location: drafts too. `staff_schedule` >= `view`: published only |
| `shifts` | `staff_schedule` >= `edit` at the location: all. Otherwise only shifts of a **published** schedule: every non-cancelled one at a location where the caller has `staff_schedule` >= `view`, plus the caller's own in any status (own = a person id of `private.my_person_ids()`, so the MFA rules and membership apply; 20261113000200). **Columns** (20261113000200): `authenticated` may read every column except `override_kinds`, `override_by_person_id`, `override_at` and `uncovered_emitted_for`; `select *` is refused. Schedulers read overrides with `shift_overrides(schedule_id)` |
| `shift_templates`, `shift_template_items` | `staff_schedule` >= `edit` at the location |
| `availability`, `time_off_requests` (reason included) | The person, plus `availability_time_off` = `admin` over that person. Nobody else |
| `shift_swaps` | The two parties, plus `shift_swaps` = `admin` at the location |
| `shift_claims` | The claimant, plus `shift_swaps` = `admin` at the location |

**Writes.**

| Table | Insert | Update | Delete |
| --- | --- | --- | --- |
| `organizations` | service_role | org-scope admin, `name` only | service_role |
| `organization_settings` | trigger | org-scope admin | no |
| `locations` | org-scope admin | admin of that location or org-scope admin; changing `archived_at` (archive or restore) needs an org-scope admin (trigger) | no (archive) |
| `space_kinds` | `locations_spaces` >= edit at org scope | same | no (archive) |
| `spaces` | `locations_spaces` >= edit at that location | same | no (archive) |
| `space_hours`, `space_closures` | `locations_spaces` >= edit at that location | same | same |
| `roles` (custom), `role_default_permissions` (custom roles only) | org-scope admin; a default's level is capped at the admin's own org-scope level | same | defaults only |
| `job_titles` | org-scope admin | same | no (archive) |
| `person_job_titles` | `people_roles` >= edit in scope, person visible | no | same as insert |
| `people` | `people_roles` = admin at org scope (an unassigned person); everyone else onboards with `create_person_with_assignment` | tier rule | no (archive) |
| `accounts` | service_role (invite flow) | tier rule, `disabled_at` only | tier rule |
| `role_assignments` | tier rule | no; use `replace_role_assignment` | tier rule; last assignment only by org scope |
| `user_permissions` | tier rule | tier rule, `level` only | tier rule |
| `audit_log`, `platform_admins`, `modules` | no | no | no |
| `outbox_events` | `private.emit_event` only (no role, service_role included, has INSERT) | worker functions; `retry_dead_outbox_event` | no |
| `outbox_event_handlers` | `record_outbox_handler` (service_role) | no | no |
| `task_templates` | `tasks` = `admin` in the row's scope (org-wide row: org scope); an assigned person must be visible | same, columns `title, instructions, default_priority, due_offset_minutes, assign_to, assign_job_title_id, assign_person_id, archived_at` | no (archive) |
| `workflow_rules` | `tasks` = `admin` in the row's scope; always created **disabled** (trigger); a location template only serves rules of that location | same, columns `name, event_type, condition, task_template_id, enabled, archived_at` | no (archive) |
| `tasks`, `task_events` | RPCs only (`create_task`, `create_task_from_event`) | RPCs only | no |
| `notices` | `communications` = `admin` in its home scope; always a draft, author = caller (trigger) | drafts only, columns `title, body, urgency, requires_acknowledgment, publish_at, expires_at`; status only via `publish_notice` / `archive_notice` | drafts only |
| `notice_audiences` | draft notice the caller manages; a location notice may only target its own location | no | same as insert |
| `acknowledgments` | `acknowledge_notice` only | never (trigger blocks every role, owner included) | no |
| `messages`, `message_recipients` | `send_message` only | `mark_message_read` only | no |
| `notifications`, `notification_deliveries` | worker functions only | `mark_notifications_read` / `mark_all_notifications_read`; worker functions | no |
| `push_subscriptions` | `save_push_subscription` (own) | same; `disable_push_subscription` (service_role) | own rows (`delete_push_subscription` or by id) |
| `notification_preferences` | own rows | own rows, `enabled` only | own rows |
| All Phase 3 (`staffing`) tables | RPCs only (see "Staff scheduling") | RPCs only | RPCs only (a draft shift, a template item, an availability window, a person qualification) |

Platform admins pass every policy through the helpers (support needs no service-role key). A location-scoped admin can't insert into `people` directly. Onboarding goes through `create_person_with_assignment`, which is the only way to attach a first assignment to a person the caller can't already see, and only to the person that same call creates.

**Error messages.** BEFORE triggers run before RLS, so they must not describe rows the caller can't see. The role-assignment and space-hierarchy triggers first refuse a signed-in caller who is not a member of the row's organization with `42501 not allowed`. A role that doesn't exist and a role from another organization both give `42501 not allowed`. Own-org messages name no keys. The `space_hours` exclusion constraint includes `organization_id` and `location_id`, so its DETAIL (which prints the conflicting row) can only show a row of the caller's own tenant. Any new BEFORE trigger, or any constraint whose error echoes another row, must follow the same rule.

**Grants.** `anon` and `PUBLIC` have no privileges on any table or function. `authenticated` has only the table operations listed above, with column-level UPDATE grants (never `id`, `organization_id`, `location_id`, `slug`, `key`). `service_role` has select/insert/update/delete on Phase 1 tables but **no TRUNCATE, TRIGGER or REFERENCES** (also revoked in default privileges), and only SELECT on `audit_log`. Every audited table also has a `zz_audit_no_truncate` statement trigger that blocks TRUNCATE for every role, the owner included. Phase 2 tables are stricter for service_role: it has SELECT only on `outbox_events`, `outbox_event_handlers`, `tasks`, `task_events`, the communications tables and the notification tables, and writes them only through the worker functions, so no API key can skip a history row or an event, or forge an outbox row; it has select/insert/update/delete on `task_templates` and `workflow_rules` (configuration). Default privileges are revoked, so a new table or function is granted to nobody until a migration says so. Every new migration must: create the table, `enable row level security`, `revoke all ... from public, anon, authenticated`, grant exactly what its policies need, and attach the audit trigger. Phase 3 tables: `authenticated` and `service_role` have SELECT only; nobody has INSERT, UPDATE or DELETE. On `shifts`, `authenticated` has a column-level SELECT grant without the override and sweep columns (20261113000200); `service_role` keeps table-level SELECT.

### Helper functions

All are `security definer`, `stable`, `set search_path = ''`, take identity only from `auth.uid()`, and return false / 0 / `none` / empty for organizations the caller is not in. `public` ones are granted to `authenticated` and `service_role` (and so are callable via `/rpc`); `private` ones are usable in policies but not exposed by the API.

```sql
public.is_platform_admin() returns boolean
public.auth_org_ids() returns setof uuid                 -- member orgs (all for platform admin)
public.auth_location_ids() returns setof uuid            -- all locations of org-scope orgs + assigned locations
public.current_person_id(p_organization_id uuid) returns uuid   -- active account's person, or null
public.has_role(p_organization_id uuid, p_location_id uuid, p_role_key text) returns boolean
    -- location null: org-scope assignment only; else org scope or that location. True for platform admin.
    -- All four below return false / 0 / 'none' when the location is not in that organization.
public.actor_rank(p_organization_id uuid, p_location_id uuid) returns integer   -- 0 if none, 100 platform
public.effective_permission(p_organization_id uuid, p_location_id uuid, p_module_key text) returns permission_level
public.has_permission(p_organization_id uuid, p_location_id uuid, p_module_key text, p_min_level permission_level) returns boolean

private.permitted_org_ids(p_module_key text, p_min_level permission_level) returns setof uuid
private.permitted_location_ids(p_module_key text, p_min_level permission_level) returns setof uuid
private.visible_person_ids() returns setof uuid
private.my_person_ids() returns setof uuid
private.people_admin_person_ids() returns setof uuid
private.can_create_person(p_organization_id uuid) returns boolean
private.can_manage_person(p_organization_id uuid, p_person_id uuid) returns boolean
private.can_manage_role_assignment(p_organization_id uuid, p_person_id uuid, p_role_id uuid, p_location_id uuid) returns boolean
private.can_manage_user_permission(p_organization_id uuid, p_person_id uuid, p_location_id uuid, p_module_key text, p_level permission_level) returns boolean
-- internal, not granted to anyone: private.my_assignments(), private.person_max_rank(uuid),
--   private.scope_exists(uuid, uuid), private.person_effective_level(uuid, uuid, uuid, text),
--   private.can_grant_role(uuid, uuid, uuid, uuid)   -- the tier/cap rule without the visibility check

-- Phase 2 (migrations 20261112000100-000500)
public.session_needs_mfa() returns boolean                                   -- authenticated, service_role
public.can_manage_person_account(p_organization_id uuid, p_person_id uuid) returns boolean   -- authenticated, service_role
private.has_permission_anywhere(p_organization_id uuid, p_module_key text, p_min_level permission_level) returns boolean
private.my_job_title_scopes() returns table (job_title_id uuid, location_id uuid)   -- "everywhere" titles expanded per location
private.can_read_task_config(p_organization_id uuid, p_location_id uuid) returns boolean
private.can_see_task(p_organization_id uuid, p_location_id uuid, p_assigned_person_id uuid, p_assigned_job_title_id uuid) returns boolean
private.can_manage_notice(uuid, uuid), private.can_manage_notice_id(uuid), private.can_edit_notice_audience(uuid, uuid, uuid),
private.in_notice_audience(uuid), private.can_read_notice_as_audience(uuid, text, timestamptz, timestamptz),
private.is_message_party(uuid), private.is_message_sender(uuid)             -- all boolean, used by policies
-- internal, not granted: private.admin_tier_min_rank(), private.session_is_aal2(), private.emit_event(...),
--   private.person_in_notice_audience(uuid, uuid), private.valid_task_assignee(uuid, uuid, uuid),
--   private.lock_task_for_caller(uuid, permission_level), private.record_task_change(...),
--   private.person_is_active_member(uuid, uuid), private.assert_service_caller()
```

Every boolean helper used as a gate in a PL/pgSQL `IF` must never return NULL (`coalesce(..., false)`), and RPCs test gates with `is not true`: `IF NOT NULL` does not raise. (Found and fixed while building `can_see_task`.)

`public.can_manage_person_account(org, person)`: true only when the caller is signed in, the person is in that organization, not archived, visible to the caller, has no account yet, and `private.can_manage_person` holds (people_roles = admin in a covering scope, caller's rank strictly above the person's highest rank, not themselves). False, never an error, for anything else. The invite flow checks it with the user's JWT before using the service key to create the login.

### Rate limits (migration `20261112000100_auth_hardening`)

```sql
public.consume_rate_limit(p_bucket text, p_key text, p_max integer, p_window_seconds integer) returns boolean  -- service_role ONLY
```
Fixed window: counts one hit for (bucket, key) in the current window and returns true while the count is <= `p_max`. Keys (an email or an IP) are normalized (since `000600`: every Unicode whitespace or invisible separator character removed anywhere, then lowercased; `private.normalize_rate_limit_key`) and stored only as HMAC-SHA256 with a random per-database secret (`private.rate_limit_secret`), so a copy of the table cannot be reversed with a list of emails. Tables live in schema `private` (not exposed by the API), have RLS on with no policies and no grants for any API role, and are not audited. Each call drops that key's expired windows; `private.purge_rate_limit_counters()` (service_role, direct connection or pg_cron only) deletes all expired windows. Not callable by `anon` or `authenticated`.

### Outbox and jobs (migration `20261112000200_outbox_and_jobs`)

`private.emit_event(org, location, type, entity_table, entity_id, payload, schema_version, correlation_id, available_at, causation_event_id)` (10th parameter since `000600`) is the only writer of `outbox_events`; nobody (service_role included) has INSERT. It is called inside the same transaction as the business change. **Payload rule** (`private.validate_event_payload`, also a CHECK): a flat object of at most 32 snake_case keys whose values are null, boolean, number, a string <= 200 chars, or an array of <= 100 strings <= 64 chars (ids); at most 8 kB. No nested objects, so free text and record copies cannot ride along; handlers re-read rows. `last_error` must not contain personal data (it is redacted in the audit log anyway).

Worker API, **service_role only** (each also refuses a caller with a user JWT):
```sql
public.claim_outbox_events(p_worker text, p_limit integer, p_lock_seconds integer) returns setof outbox_events
public.complete_outbox_event(p_id uuid, p_worker text) returns boolean          -- false = claim lost
public.fail_outbox_event(p_id uuid, p_worker text, p_error text) returns text   -- 'pending' | 'dead' | null (claim lost)
public.record_outbox_handler(p_event_id uuid, p_handler text) returns boolean   -- true = newly recorded
public.outbox_handlers_done(p_event_id uuid) returns setof text
```
Claims use `FOR UPDATE SKIP LOCKED`, count as an attempt, and set `lock_expires_at`; an expired lock is reclaimable (a crashed worker), or goes to `dead` if it was the last attempt. Attempts: `private.outbox_max_attempts()` = 8; backoff `private.outbox_backoff(n)` = 2^(n-1) minutes, capped at 6 hours. Admin API: `public.retry_dead_outbox_event(p_id uuid) returns void` (authenticated, service_role): `audit_log` = `admin` at org scope or at the event's location; 42501 `not allowed` for missing / other org / no permission; resets attempts, keeps the handler ledger, records `retried_at` / `retried_by_person_id`.

### Tasks RPCs (migration `20261112000300_tasks_and_workflows`)

Module `tasks` levels: `view` = see own / own-title / unassigned tasks at the location; `edit` = also start, complete, reopen-from-done, comment, and create a task for yourself or nobody; `admin` = all tasks at the location, create for anyone, assign, cancel, reopen cancelled, templates and rules. (Seeded: staff `edit`, manager `admin`.) All are security definer, identity from `auth.uid()`, 42501 `not allowed` without saying whether the task exists, 22023 for state errors on tasks the caller can see. Each writes the `task_events` row and emits `task.<kind>` in the same transaction. Granted to authenticated and service_role.
```sql
public.create_task(p_organization_id uuid, p_location_id uuid, p_title text, p_instructions text default null,
  p_due_at timestamptz default null, p_priority text default 'normal', p_space_id uuid default null,
  p_assigned_person_id uuid default null, p_assigned_job_title_id uuid default null) returns uuid
public.start_task(p_task_id uuid) returns void                 -- open -> in_progress; claims an unassigned task
public.complete_task(p_task_id uuid, p_note text default null) returns void
public.reopen_task(p_task_id uuid, p_reason text default null) returns void
public.assign_task(p_task_id uuid, p_person_id uuid, p_job_title_id uuid) returns void   -- admin; both null = unassign
public.cancel_task(p_task_id uuid, p_reason text default null) returns void               -- admin
public.add_task_comment(p_task_id uuid, p_body text) returns uuid                          -- task_events id
```
An assignee must be an active member covering the location (active account, not archived, an assignment at org scope or that location) and visible to the caller. There is no `source_event_id` parameter anywhere a tenant can reach. Worker functions, **service_role only**:
```sql
public.match_workflow_rules(p_event_id uuid) returns table (rule_id uuid, task_template_id uuid)
public.create_task_from_event(p_event_id uuid, p_rule_id uuid) returns uuid   -- existing task on retry; null if the rule no longer applies
public.emit_overdue_task_events(p_limit integer default 500) returns integer   -- task.overdue once per task per due_at
```

### Communications RPCs (migration `20261112000400_communications`)

Module `communications` levels: `view` = read notices you are the audience of and your own messages; `edit` = also send messages; `admin` = manage notices in scope. **Audience rule** (`private.person_in_notice_audience`, one implementation for the read policy and the worker fan-out): an audience row (location or whole org) x (job title or everyone) matches a person who has `communications` >= `view` at that location (org-wide row: at org scope or at any location they are assigned to), computed with `person_effective_level` (so: active account, not archived, covering assignment, MFA rule for the caller), and, for a job-title row, holds that non-archived title everywhere or at that location. **Messages are private**: only sender and recipients read them; no manager, admin or platform admin can (a deliberate choice; Phase 1 does not require a platform-admin exception). The audit log redacts message and notice bodies. Since `000600` this is literally true for metadata too: `message.sent` carries only `message_id`; no tenant (platform admins included) can read `message.*` outbox rows or the audit rows of `messages`, `message_recipients`, `notifications`, `notification_deliveries`, `push_subscriptions`, `notification_preferences`, `outbox_event_handlers`; so an org admin or platform admin cannot learn who messaged whom, or when.
```sql
public.publish_notice(p_notice_id uuid, p_publish_at timestamptz default null) returns void  -- needs >= 1 audience row; emits notice.published available at publish_at
public.archive_notice(p_notice_id uuid) returns void
public.acknowledge_notice(p_notice_id uuid) returns timestamptz   -- caller only, live notice in their audience; idempotent (returns the first time)
public.send_message(p_organization_id uuid, p_recipient_person_ids uuid[], p_body text) returns uuid
    -- 1-50 recipients, each visible to the sender, in the org, not archived, not the sender; communications >= edit somewhere in the org
public.mark_message_read(p_message_id uuid) returns void          -- recipient only; keeps the first read time
```
All granted to authenticated and service_role; all need a user JWT.

### Notifications (migration `20261112000500_notifications`)

Person RPCs (authenticated, service_role; own rows only):
```sql
public.mark_notifications_read(p_notification_ids uuid[]) returns integer   -- ids that are not yours are ignored
public.mark_all_notifications_read(p_organization_id uuid) returns integer
public.save_push_subscription(p_organization_id uuid, p_endpoint text, p_p256dh text, p_auth_secret text, p_user_agent text default null) returns uuid
public.delete_push_subscription(p_organization_id uuid, p_endpoint text) returns boolean
```
Worker functions, **service_role only**:
```sql
public.create_notification(p_event_id uuid, p_person_id uuid, p_kind text, p_title text, p_body text default null,
  p_link_path text default null, p_urgency text default null) returns uuid   -- idempotent on (event, person, kind); null if not an active member of the event's org
public.notice_audience_person_ids(p_notice_id uuid) returns setof uuid
public.task_recipient_person_ids(p_task_id uuid) returns setof uuid
public.claim_notification_deliveries(p_worker text, p_limit integer, p_lock_seconds integer, p_channel text default null) returns setof notification_deliveries
public.complete_notification_delivery(p_id uuid, p_worker text, p_provider_message_id text default null) returns boolean
public.fail_notification_delivery(p_id uuid, p_worker text, p_error text, p_permanent boolean default false) returns text
public.skip_notification_delivery(p_id uuid, p_worker text, p_reason text) returns boolean
public.disable_push_subscription(p_id uuid) returns boolean
```
`create_notification` writes three deliveries: `in_app` sent at once; `email` and `push` pending, or skipped when the person turned the channel off (**ignored for `critical`**) or, for push, has no active device. Deliveries retry up to `private.delivery_max_attempts()` = 5 with the outbox backoff. Titles, bodies and link paths of notifications, delivery errors and push endpoints/keys are redacted in the audit log.

Policy style: wrap argument-free helpers in a subselect (`organization_id in (select public.auth_org_ids())`, `(select public.is_platform_admin())`) so Postgres evaluates them once per statement. Policies on identity tables only call these definer helpers, so they never recurse. RLS is enabled (not `force`d) on every table: the definer helpers rely on the table owner bypassing RLS.

### Phase 2 review fixes (migration `20261112000600_phase2_review_fixes`)

**Limits (all of them, one list).** Per person (keyed by the caller's auth user id, `private.write_limits()`, counted with `consume_rate_limit` under bucket `write.<action>`); a refused call raises **SQLSTATE `PT429`, message `slow down`** (PostgREST answers HTTP 429) and does not count:

| Action | Limit | Where |
| --- | --- | --- |
| `task_create` | 60 / 10 min | `create_task` |
| `task_comment` | 60 / 10 min | `add_task_comment` |
| `task_transition` | 120 / 10 min | `start_task`, `complete_task`, `reopen_task`, `assign_task`, `cancel_task` |
| `message_send` | 30 / 10 min | `send_message` |
| `notice_publish` | 20 / hour | `publish_notice` |
| `notice_critical` | 5 / day | `publish_notice` of a `critical` notice (on top of the above) |
| `push_save` | 10 / hour | `save_push_subscription` |
| `staffing_config` | 120 / 10 min | `save_position`, `archive_position`, `save_qualification`, `archive_qualification`, `set_person_qualification`, `remove_person_qualification`, `save_shift_template`, `archive_shift_template`, `add_shift_template_item`, `remove_shift_template_item` (Phase 3), `set_staffing_switches` (20261113000200) |
| `shift_edit` | 300 / 10 min | `create_schedule`, `create_shift`, `update_shift`, `assign_shift`, `cancel_shift`; `apply_shift_template` is charged **once per shift it makes** (at least once per call; 20261113000200), so one call can make at most what is left of the 300 |
| `schedule_publish` | 20 / hour | `publish_schedule` |
| `shift_exchange` | 30 / 10 min | `request_shift_swap`, `respond_shift_swap`, `cancel_shift_swap`, `request_shift_drop`, `request_shift_claim`, `cancel_shift_claim` |
| `shift_decide` | 120 / 10 min | `decide_shift_swap`, `decide_shift_claim` |
| `availability_edit` | 60 / 10 min | `add_availability`, `remove_availability` |
| `time_off_request` | 20 / hour | `request_time_off`, `cancel_time_off` |
| `time_off_decide` | 120 / 10 min | `decide_time_off` |

Other limits: event causation depth 3 (`private.outbox_max_causation_depth()`); 20 enabled workflow rules per organization per event type (`private.max_enabled_rules_per_event_type()`); 10 push subscriptions per person, oldest replaced (`private.max_push_subscriptions_per_person()`); 3 manual retries per dead event (`private.outbox_max_manual_retries()`); unchanged: outbox 8 attempts, deliveries 5, batches 1-500, overdue sweep 1-5000, `create_notifications` 1-10000 people.

**Workflow loops.** No rule reacts to an event about a rule-made task; no rule matches an event at causation depth 3; `task.overdue` rules need a template due >= 1 minute later (null offset allowed); 20 enabled rules per org per type (checked under an advisory lock). The `workflow_rules` trigger checks, in order: member of the org, `tasks` = `admin` in the rule's scope, the template exists in the org **and** is readable by the caller (all three: 42501 `not allowed`, so it never tells a template at another location from a missing one).

**Fairness.** `claim_outbox_events`, `claim_notification_deliveries` and `emit_overdue_task_events` take each organization's oldest due row first, then each one's second, and so on. Claim names are per-claim tokens in practice (the app passes `<job>:<random uuid>` per invocation; a reclaim overwrites `locked_by`), so signatures are unchanged.

**Push.** One allowlist, `private.push_endpoint_allowed(text)`: https, no userinfo, port 443 or none, host `fcm.googleapis.com`, `updates.push.services.mozilla.com`, `*.push.apple.com`, `*.notify.windows.com`. Enforced by a CHECK on `push_subscriptions` and by `save_push_subscription` (22023 `this push service is not supported`). Saving an endpoint removes every other person's row for that endpoint (any org; shared phone or kiosk) without saying whether there was one.

**Other.** Locks are taken only after the permission check (`lock_task_for_caller`, `retry_dead_outbox_event`, `publish_notice`, `archive_notice`), so a caller without access cannot detect a row by waiting on its lock. Archived job titles route nothing. A template whose `assign_person_id` the reader cannot see is not readable. Notice fan-out returns nobody unless the notice is published and live. The platform-admin branch of `person_effective_level` honours a disabled account or archived person. Append-only tables (`task_events`, `acknowledgments`) refuse UPDATE, DELETE and TRUNCATE for every role; DELETE passes only as the FK cascade of deleting the task / notice / organization. No timestamp column accepts +/-infinity. Free-text titles (`tasks.title`, `notices.title`, `task_templates.title`, `workflow_rules.name`) are redacted in the audit log.

New and changed functions (all security definer, `search_path = ''`; service_role-only ones also refuse any JWT with a `sub`):
```sql
-- authenticated + service_role
public.notice_acknowledgment_status(p_notice_id uuid) returns table (person_id uuid, acknowledged_at timestamptz)
    -- communications = admin over the notice's home scope, else 42501; audience + acknowledgers, limited to people the caller can see
public.my_notices(p_organization_id uuid default null, p_limit integer default 50) returns table (notice_id uuid,
    organization_id uuid, location_id uuid, title text, body text, urgency text, requires_acknowledgment boolean,
    publish_at timestamptz, expires_at timestamptz, acknowledged_at timestamptz)   -- live notices addressed to the caller; <= 200
public.can_resend_person_invite(p_organization_id uuid, p_person_id uuid) returns boolean
    -- tier rule of can_manage_person_account; true only for an active account whose auth user never confirmed and never signed in
-- service_role only
public.create_notifications(p_event_id uuid, p_person_ids uuid[], p_kind text, p_title text, p_summary text default null,
    p_link text default null, p_urgency text default null) returns integer   -- people who now have it (new or existing)
public.worker_task_for_event(p_event_id uuid) returns table (task_id, organization_id, location_id, location_name, title,
    status, priority, due_at, assigned_person_id, assigned_job_title_id)
public.worker_notice_for_event(p_event_id uuid) returns table (notice_id, organization_id, location_id, title, status, urgency,
    requires_acknowledgment, publish_at, expires_at)
public.worker_notification_for_delivery(p_delivery_id uuid) returns table (delivery_id, notification_id, organization_id,
    person_id, channel, status, attempts, kind, title, body, link_path, urgency)
public.worker_email_for_delivery(p_delivery_id uuid) returns text   -- confirmed auth.users.email of the person's active account; never people.email;
    -- since 000700 also null when auth.users.banned_until is in the future or deleted_at is set
public.worker_message_recipients_for_event(p_event_id uuid) returns table (organization_id uuid, message_id uuid, person_id uuid, link_path text)
    -- (000700) message.sent event only, message in the event's organization; recipients except the sender who are active
    -- members; no body, sender or read state. Handlers notify with generic text ("You have a new message").
public.worker_push_subscriptions_for_delivery(p_delivery_id uuid) returns table (subscription_id, endpoint, p256dh, auth_secret)
public.release_outbox_event(p_id uuid, p_worker text) returns boolean            -- give back a claim, attempt not counted
public.release_notification_delivery(p_id uuid, p_worker text) returns boolean
public.extend_outbox_lock(p_id uuid, p_worker text, p_seconds integer) returns boolean   -- holder only, lock not yet expired; 5-3600
public.escalate_overdue_task(p_event_id uuid) returns setof uuid
    -- task.overdue event; once per task per due_at; records an 'escalated' task_events row; returns tasks = admin people at the
    -- location when the task is unassigned or the assignee has not started/completed/reopened/commented; idempotent per event
```
Changed behaviour of existing functions: `retry_dead_outbox_event` refuses `message.*` events (42501) and a 4th manual retry (22023); `publish_notice` validates everything before writing (an expiry before the publish time is 22023, not 23514); `fail_notification_delivery` keeps `next_attempt_at` on a final failure; `create_task` / `publish_notice` refuse non-finite times with 22023.

### Message notifications (migration `20261112000700_worker_message_recipients`)

The worker learns who to tell about a message only through `public.worker_message_recipients_for_event` (service_role only; refuses any JWT with a `sub`). It returns ids and an app link (`/app/messages/<id>`), never content, so message text never reaches `notifications`, the outbox or the audit log: the notification title is generic ("You have a new message") and its body is empty. `escalate_overdue_task` does not exclude the assignee (it returns everyone with `tasks` = `admin` at the location, which can include an assignee who is a manager); notifying the assignee separately with the same `kind` and event is safe because `create_notification` is idempotent on (event, person, kind).

### Staff scheduling (migration `20261113000100_staff_scheduling`)

**Modules** (existing keys; seeded defaults staff / manager / admin):

| Module | `view` | `edit` | `admin` |
| --- | --- | --- | --- |
| `staff_schedule` (view / admin / admin) | Published schedules and shifts at the location; your own shifts | Also drafts; create schedules, add / change / assign / cancel shifts, stamp templates, publish; templates at the location | Also override the time off and qualification rules when assigning (any path); positions (org-wide ones need org scope), qualifications (admin anywhere in the org), and who holds them (admin over the person) |
| `shift_swaps` (edit / admin / admin) | nothing extra | Offer, accept, cancel swaps; request drops; claim open shifts (own only) | See every swap, drop and claim at the location; approve or deny them (not your own) |
| `availability_time_off` (edit / admin / admin) | Your own availability and time off | Also change your availability; request and cancel your own time off | Read and decide availability and time off of people in scope (org scope: all; a location: people assigned there); not your own |

**Assignment rules** (`private.shift_assignment_problems`, the one implementation, used by every path that puts a person on a shift: `create_shift`, `assign_shift`, `update_shift` (new time or position), `apply_shift_template`, `respond_shift_swap`, `decide_shift_swap`, the auto-approval, `request_shift_claim`, `decide_shift_claim`, plus `my_claimable_shifts` and the `shift.opened` fan-out):
1. `not_member`: the person is not archived, an active member (`person_is_active_member`), has `staff_schedule` >= `view` at the shift's location (`person_effective_level`: active account, covering assignment, MFA rule when it is the caller), and, on manager paths, is visible to the caller (`visible_person_ids`; platform admins skip this).
2. `overlap`: no other scheduled shift of that person anywhere in the organization overlaps (`[starts_at, ends_at)`). Also the `shifts_no_overlap` exclusion constraint; a race-time violation is turned into the same 23514.
3. `time_off`: no approved time off whose local days (in the shift location's time zone) overlap the shift.
4. `qualification`: every qualification the position requires is held with `valid_from <= d <= expires_on` (nulls open), `d` = the local date of the shift start.

`p_override` (on `create_shift`, `update_shift`, `assign_shift`, `decide_shift_swap`, `decide_shift_claim`) lets 3 and 4 through only for `staff_schedule` = `admin` at the location (otherwise 42501 `only a schedule admin can override`), and never when the person on the shift is the caller (42501 `you cannot override the rules for yourself`, 20261113000200; an override flag that is not needed is ignored); the kinds overridden are written to `shifts.override_kinds` / `_by` / `_at` (audited) and `shift.assigned` carries `override: true`. 1 and 2 are never overridable. Staff-initiated paths check only the acting person's own rules (a swap request checks only that B can work at the location and has `shift_swaps` >= `edit`; B's own rules are checked when B accepts), so nobody learns a co-worker's time off. `apply_shift_template` never overrides: an item whose default assignee fails a rule becomes an open shift and the result row names the rule.

**Atomicity.** Every path reads the row, checks permission, then locks: shift rows (`FOR UPDATE`, in id order when two), then the swap or claim row, then a transaction advisory lock per person (`staffing:person:<id>`, in id order), then re-checks state and rules and moves the assignment in the same transaction. `decide_time_off`, `cancel_time_off`, `set_person_qualification` and `remove_person_qualification` take the same person lock, so an approval of time off and an assignment of that person serialize (approval is refused while the person holds an overlapping scheduled shift). Changes to a shift's assignee close what no longer applies: open swaps / drops of it (as X or Y) become `cancelled`, open claims become `denied` (decided by the system, with events). Assignment RPCs also take a share lock on the schedule, so a change is either before or after `publish_schedule`, never half.

**Shift exchange design.** Swap: A offers X (optionally for B's Y at the same location) -> B accepts -> a manager approves, unless `settings.staffing.auto_approve_swaps` is true, the swap has **no counter shift** (20261113000200: with a counter shift the outcome would tell B whether A can work Y, so those always wait for a manager) and every rule passes at accept time (then it is approved at once; if any rule fails it silently waits for a manager). Drop: A requests; X stays A's until a manager approves, then it is open (`shift.opened`) and the claim path covers it. Claim: a person asks for an open shift; a manager approves, or with `settings.staffing.first_come_open_shifts` the first valid claim is approved at once under the shift lock. Exchanges only for scheduled shifts of a published schedule that have not started. One open swap or drop per shift.

RPCs (all `security definer`, `search_path = ''`, need a user JWT (`not signed in` otherwise), granted to `authenticated` and `service_role`; 42501 `not allowed` for missing, other organization or not permitted, without saying which; permission is checked before any row lock):
```sql
-- configuration (staffing_config limit)
public.position_shifts_missing_qualification(p_position_id uuid) returns integer   -- 000200; staff_schedule >= edit in the position's scope
public.save_position(p_organization_id uuid, p_location_id uuid, p_name text, p_qualification_ids uuid[] default null,
  p_position_id uuid default null) returns uuid            -- staff_schedule = admin in the position's scope; ids null = keep, '{}' = none
public.archive_position(p_position_id uuid, p_archived boolean default true) returns void
public.save_qualification(p_organization_id uuid, p_name text, p_qualification_id uuid default null) returns uuid  -- admin anywhere in the org
public.archive_qualification(p_qualification_id uuid, p_archived boolean default true) returns void   -- refused while a position requires it
public.set_person_qualification(p_organization_id uuid, p_person_id uuid, p_qualification_id uuid,
  p_valid_from date default null, p_expires_on date default null) returns uuid    -- admin over the person, person visible, not yourself; upsert
public.remove_person_qualification(p_person_qualification_id uuid) returns void
public.save_shift_template(p_organization_id uuid, p_location_id uuid, p_name text, p_span_days integer default 7,
  p_template_id uuid default null) returns uuid             -- staff_schedule >= edit at the location
public.archive_shift_template(p_template_id uuid, p_archived boolean default true) returns void
public.add_shift_template_item(p_template_id uuid, p_position_id uuid, p_day_offset integer, p_start_time time,
  p_duration_minutes integer, p_assigned_person_id uuid default null, p_notes text default null) returns uuid
public.remove_shift_template_item(p_item_id uuid) returns void
-- schedules and shifts (shift_edit; publish: schedule_publish); staff_schedule >= edit at the location
public.create_schedule(p_organization_id uuid, p_location_id uuid, p_week_start date) returns uuid   -- existing id if present
public.publish_schedule(p_schedule_id uuid) returns void
public.create_shift(p_schedule_id uuid, p_position_id uuid, p_starts_at timestamptz, p_ends_at timestamptz,
  p_assigned_person_id uuid default null, p_notes text default null, p_override boolean default false) returns uuid
public.update_shift(p_shift_id uuid, p_position_id uuid default null, p_starts_at timestamptz default null,
  p_ends_at timestamptz default null, p_notes text default null, p_override boolean default false) returns void  -- null = keep
public.assign_shift(p_shift_id uuid, p_person_id uuid, p_override boolean default false) returns void   -- null person = open it
public.cancel_shift(p_shift_id uuid) returns void            -- draft: deleted; published: cancelled + shift.cancelled
public.apply_shift_template(p_schedule_id uuid, p_template_id uuid, p_first_day integer default 0)
  returns table (shift_id uuid, assigned_person_id uuid, refused text, item_id uuid)   -- draft only; one row per item (000200)
public.shift_overrides(p_schedule_id uuid) returns table (shift_id uuid, override_kinds text[],
  override_by_person_id uuid, override_at timestamptz)        -- 000200; staff_schedule >= edit at the location
-- exchange (shift_exchange; decisions: shift_decide)
public.request_shift_swap(p_shift_id uuid, p_to_person_id uuid, p_counter_shift_id uuid default null, p_note text default null) returns uuid
public.respond_shift_swap(p_swap_id uuid, p_accept boolean) returns text   -- B only; 'accepted' | 'approved' (auto) | 'denied'
public.decide_shift_swap(p_swap_id uuid, p_approve boolean, p_override boolean default false) returns void  -- shift_swaps = admin, not a party
public.cancel_shift_swap(p_swap_id uuid) returns void        -- either party while requested / accepted
public.request_shift_drop(p_shift_id uuid, p_note text default null) returns uuid
public.request_shift_claim(p_shift_id uuid) returns uuid     -- shift_swaps >= edit; caller must pass every rule now
public.decide_shift_claim(p_claim_id uuid, p_approve boolean, p_override boolean default false) returns void
public.cancel_shift_claim(p_claim_id uuid) returns void      -- the claimant
public.swap_candidates(p_shift_id uuid) returns table (person_id uuid, display_name text)  -- 000200; the shift's assignee only
public.my_claimable_shifts(p_organization_id uuid, p_limit integer default 50) returns table (shift_id uuid,
  location_id uuid, schedule_id uuid, position_id uuid, starts_at timestamptz, ends_at timestamptz)   -- <= 200
-- availability and time off (availability_edit, time_off_request, time_off_decide)
public.add_availability(p_organization_id uuid, p_day_of_week integer, p_start_time time, p_end_time time, p_kind text,
  p_effective_from date default null, p_effective_to date default null) returns uuid   -- own; availability_time_off >= edit somewhere
public.remove_availability(p_availability_id uuid) returns void
public.request_time_off(p_organization_id uuid, p_starts_on date, p_ends_on date, p_reason text default null) returns uuid
public.cancel_time_off(p_time_off_id uuid) returns void      -- own; pending, or approved and not ended
public.decide_time_off(p_time_off_id uuid, p_approve boolean) returns void   -- availability_time_off = admin over the person, not own
-- organization settings (000200; staffing_config limit)
public.set_staffing_switches(p_organization_id uuid, p_auto_approve_swaps boolean default null,
  p_first_come_open_shifts boolean default null) returns void   -- admin role at organization scope; null = keep
```

Errors the app maps (stable messages; DETAIL carries the rule code on 23514 rule errors):

| SQLSTATE | Message | When |
| --- | --- | --- |
| 42501 | `not signed in` / `not allowed` | no JWT / missing, other org, or not permitted |
| 42501 | `only a schedule admin can override`, `you cannot override the rules for yourself` (000200), `you cannot decide your own swap`, `you cannot decide your own request`, `you cannot change your own qualifications` | visible row, wrong actor |
| 23514 | `that person cannot work at this location` (DETAIL `not_member`), `that person already has a shift at that time` (`overlap`), `that person has approved time off then` (`time_off`), `that person is missing a required qualification` (`qualification`) | assignment rules |
| 23514 | `you cannot take this shift` (DETAIL `unavailable`; 000200: on a staff path, the caller's overlap is with a draft shift), `a schedule holds at most 2000 shifts` (DETAIL `too_many_shifts`; 000200), `you cannot swap with that person` (`not_member`), `the shift changed since the swap was offered` / `... drop was requested` (`stale`), `this shift is no longer open` (`stale`), `that person has shifts on those days; reassign them first` (`has_shifts`), `another schedule already covers part of that week` | exchange and time off rules |
| 22023 | `invalid week`, `a week must start on the organization's first day of the week`, `a shift needs a start and an end`, `a shift ends after it starts and lasts at most 24 hours`, `the shift must start during the schedule week`, `unknown position at this location`, `notes are too long`, `the note is too long`, `the reason is too long`, `a name needs 1 to 100 characters`, `a position with that name already exists`, `a qualification with that name already exists`, `unknown qualification`, `at most 20 qualifications`, `a position still requires this qualification`, `the location of a position cannot change`, `a template covers 1 day or 7 days`, `the length of a template cannot change`, `that day is outside the template`, `that day is outside the week`, `a shift needs a start time and 15 minutes to 24 hours`, `a template holds at most 200 shifts`, `that template belongs to another location`, `that template is archived`, `a template can only be added to a draft schedule`, `this schedule is already published`, `a cancelled shift cannot be changed` / `... assigned`, `this shift is already cancelled`, `nothing to change`, `this shift cannot be swapped now` / `... dropped now`, `that shift cannot be part of this swap`, `this shift already has an open swap or drop`, `this swap is no longer open`, `this request is not waiting for a decision`, `this request is already closed`, `you already asked for this shift`, `accept or decline`, `approve or deny`, `invalid day`, `invalid kind`, `invalid dates`, `the end must be after the start`, `at most 100 availability windows`, `choose a first and last day, at most a year apart`, `those days are too far in the past or future`, `this request can no longer be cancelled` | bad input / state |
| PT429 | `slow down` | write limits above |

Worker functions, **service_role only** (each refuses a JWT with a `sub`; each joins only rows of the event's organization):
```sql
public.emit_uncovered_shift_events(p_within interval, p_limit integer default 500) returns integer
    -- shift.uncovered once per shift per starts_at: open, scheduled, published, starting in (now, now + p_within];
    -- p_within 1 minute .. 14 days, p_limit 1-5000; round-robin by organization, SKIP LOCKED
public.worker_shift_for_event(p_event_id uuid) returns table (shift_id, organization_id, location_id, location_name,
    location_timezone, schedule_id, schedule_status, week_start, position_id, position_name, starts_at, ends_at,
    assigned_person_id, status)        -- shift.* events, and the shift of a shift_swap.* / shift_claim.* event; no notes
public.worker_shift_event_recipients(p_event_id uuid) returns table (person_id uuid, reason text)
    -- every staffing event; one row per person; only active, non-archived members of the event's organization
```

| Event | Recipients (`reason`) |
| --- | --- |
| `schedule.published` | Current holders of scheduled shifts in that schedule (`schedule_published`). The payload carries `open_shift_count` (000200) so the notice can say "N open shifts" |
| `shift.assigned` / `.unassigned` / `.changed` / `.cancelled` | The payload `person_id` (`assigned` / `unassigned` / `changed` / `cancelled`) |
| `shift.opened` | Not emitted by `publish_schedule` (000200); at most 20 per location per clock hour. While still open, published and not started: people with `shift_swaps` >= `edit` at the location who pass every rule for it now (`can_claim`) |
| `shift.uncovered` | While still open: `staff_schedule` >= `edit` or `shift_swaps` = `admin` at the location (`uncovered`) |
| `shift_swap.requested` | Swap: B while still requested (`swap_offered`). Drop: `shift_swaps` admins at the location while requested, parties excluded (`needs_approval`) |
| `shift_swap.accepted` | A (`swap_accepted`); plus approvers while still accepted (`needs_approval`) |
| `shift_swap.approved` / `.denied` / `.cancelled` | Both parties except the payload's actor (`swap_approved` / `swap_denied` / `swap_cancelled`) |
| `shift_claim.requested` | Approvers at the location while still requested, claimant excluded (`needs_approval`) |
| `shift_claim.approved` / `.denied` | The claimant (`claim_approved` / `claim_denied`); `.cancelled`: nobody |
| `time_off.requested` | `availability_time_off` admins over the person while still pending (`needs_approval`) |
| `time_off.decided` | The person (`time_off_decided`) |
| `time_off.cancelled` | Approvers, only when it had been approved (`time_off_cancelled`) |

New private helpers: `private.has_permission_over_person(org, person, module, level)`, `private.can_see_schedule(org, location, status)`, `private.can_see_shift(org, location, schedule_id, assigned_person_id, status)` (policies; granted to authenticated and service_role); internal, not granted: `private.staffing_setting`, `private.shift_assignment_problems`, `private.require_assignable`, `private.lock_staffing_people`, `private.write_shift_assignee`, `private.after_assignee_change`, `private.close_shift_exchanges`, `private.lock_shift_for_scheduler`, `private.lock_swap_and_shifts`, `private.execute_swap`, `private.execute_claim`, `private.shift_is_exchangeable`, `private.staffing_location_people`, `private.time_off_approvers`, `private.validate_shift_times`, `private.validate_shift_position`, `private.emit_shift_event` / `emit_swap_event` / `emit_claim_event`, trigger `private.tg_shifts_validate`.

#### Review fixes (migration `20261113000200_staff_scheduling_review_fixes`)

| Item | Behaviour now |
| --- | --- |
| M1 | An override that is actually needed is refused when the person on the shift is the caller: 42501 `you cannot override the rules for yourself` (`create_shift`, `assign_shift`, `update_shift`). Another admin must do it. |
| M2 | `shifts.override_kinds`, `override_by_person_id`, `override_at`, `uncovered_emitted_for`: no SELECT for `authenticated` (column grants; `select *` on `shifts` is refused, name the columns). `shift_overrides(p_schedule_id)` returns them for `staff_schedule` >= `edit` at the schedule's location (42501 otherwise). Audit rows of `shifts` redact `override_kinds`, `override_by_person_id`, `override_at` (and `notes`) as `"[redacted]"`; that an override exists stays visible (non-null), its kind does not. Audit rows written before this migration are not rewritten (no real data exists yet). |
| M4 | (a) `apply_shift_template` charges `shift_edit` once per shift made (at least once). (b) At most **2,000 scheduled shifts per schedule**: `create_shift` and `apply_shift_template` refuse with 23514 `a schedule holds at most 2000 shifts` (DETAIL `too_many_shifts`); `apply_shift_template` is all or nothing. Serialized by a per-schedule advisory lock. (c) `publish_schedule` emits only `schedule.published`; the payload gains `open_shift_count`; recipients unchanged (current holders). (d) `shift.opened` (create on a published schedule, unassign, approved drop) is emitted at most **20 times per location per clock hour** (a fixed window from `consume_rate_limit`, bucket `staffing.shift_opened`, key `organization_id:location_id`; so up to 40 inside any sliding hour that spans two windows). Beyond that the action succeeds without the event; `emit_uncovered_shift_events` still covers those shifts. |
| M5 | `can_see_shift` own-shift branch, `cancel_time_off`, `cancel_shift_swap`, `cancel_shift_claim` require the caller's person to be in `private.my_person_ids()` (membership and the MFA rules). A person with no role, or an MFA user at aal1, gets 42501 / sees no own shifts. |
| L1 | `create_shift` and `assign_shift` run the `not_member` rule (organization, membership, location, visibility) before taking the person lock (`private.precheck_assignee`), so a person of another organization is refused at once. |
| L2 | `archive_qualification` locks the qualification `FOR UPDATE` before checking positions; `save_position` locks the qualifications it names `FOR SHARE` before checking them. The later call sees the earlier one: `unknown qualification` or `a position still requires this qualification`. |
| L3 | Auto-approval applies only to swaps without a counter shift. |
| L4 | Staff paths (`request_shift_claim`, first-come claim, `respond_shift_swap` accept): if the caller's overlap is only with shifts of draft schedules, the refusal is 23514 `you cannot take this shift` (DETAIL `unavailable`); an overlap with one of their published shifts still says `that person already has a shift at that time`. `my_claimable_shifts` still leaves such a shift out (absence only). `decide_time_off` keeps counting every scheduled shift of the person (drafts and other locations included) and keeps its message, which names no location or schedule: an approval must never leave approved time off under an assigned shift, and the decider (an `availability_time_off` admin over the person) learns only that some shift exists on those days. |
| L5 | `position_shifts_missing_qualification(p_position_id) returns integer`: future scheduled shifts of the position whose assignee lacks a requirement on the shift's local date and has no qualification override. `staff_schedule` >= `edit` in the position's scope. Call it after `save_position`. Nothing is refused or unassigned. `save_position` keeps its signature (returns the id). |
| L6 | `update_shift` that changes the time or position closes the shift's open swaps / drops (cancelled) and claims (denied), with events, like an assignee change. A notes-only change closes nothing. |
| L7 | `set_staffing_switches(p_organization_id, p_auto_approve_swaps, p_first_come_open_shifts)`: one UPDATE that merges into `settings.staffing` only (null = keep), so no other key is lost. Same guard as a direct settings update (admin role at organization scope, admin-tier MFA rule), plus the `staffing_config` limit. The app must stop writing the whole `settings` object for this. |
| DST | `apply_shift_template` returns one row per item (new last column `item_id`). `shift_id` null with `refused` = `time_change` (would last over 24 hours across a clock change) or `position_unavailable` (position archived or not at the location): no shift made. |
| G1 | `swap_candidates(p_shift_id) returns table (person_id, display_name)`: only for the shift's current assignee (a member) with `shift_swaps` >= `edit` at the location, on a shift they can see (42501 otherwise). Returns exactly the people `request_shift_swap` accepts as the other person (active members who can work at the location, have `shift_swaps` >= `edit` there and are visible to the caller), the caller excluded, at most 500, by name. It never looks at time off, qualifications or other shifts. `display_name` = preferred name (else first name) + last name, from people rows the caller can already read. |
| G2 | `update_shift`: `p_notes` null keeps the notes; `''` (or only spaces) clears them. Unchanged behaviour, now documented. |
| G3 | `apply_shift_template`: item `day_offset` d lands on local date `schedules.week_start + p_first_day + d` (the schedule's own `week_start`, the organization's first day of the week). `p_first_day` defaults to 0; a week template takes only 0, a day template 0-6. Unchanged behaviour, now documented. |

New private helpers (not granted): `private.assignee_not_member`, `private.precheck_assignee`, `private.lock_schedule_shift_count`, `private.emit_shift_opened`, `private.max_shifts_per_schedule()` (2000), `private.max_shift_opened_per_hour()` (20).

Known limits of Phase 3: losing an assignment or a qualification, or archiving a person, does not unassign their future shifts (the rules apply when someone is put on a shift); availability is not enforced; audit rows of `availability` and `time_off_requests` (dates and status, reason redacted) are readable by `audit_log` viewers, who are not necessarily `availability_time_off` admins (add both tables to `private.audit_hidden_tables()` if that is not acceptable).

### People RPCs (migration `20261111000500_people_rpcs`)

Both are `security definer`, `set search_path = ''`, take identity from `auth.uid()` only, raise `42501` (insufficient_privilege) when refused, and are granted to `authenticated` and `service_role` (not anon). Their writes go through the normal triggers, so the audit log records the real caller (`actor_role = authenticated`, the caller's user and person ids).

```sql
public.create_person_with_assignment(
  p_organization_id uuid, p_first_name text, p_last_name text,
  p_role_id uuid, p_location_id uuid,            -- p_location_id null = organization scope (admin role only)
  p_preferred_name text default null, p_email text default null,
  p_phone text default null, p_employee_number text default null
) returns uuid                                   -- the new person id
```
Creates the person and their first role assignment in one transaction. It checks `private.can_create_person(org)`, then `private.can_grant_role(org, new_person, role, location)`: the policy rule (tier rule, scope, rank, permission cap) minus the visibility check, which a person created moments ago can't pass. Then the `role_assignments` validation trigger runs. Any failure rolls back both rows. The caller can read both rows back afterwards. There is no service-role shortcut: without a user JWT it raises "not signed in". Server code holding the service key inserts the two rows directly. The session `role` setting is never trusted for authorization, because the API login role (`authenticator`) is a member of `service_role`.

```sql
public.update_own_profile(p_organization_id uuid, p_preferred_name text, p_phone text) returns uuid  -- caller's person id
```
For a member of the organization (active account, person not archived, at least one active assignment): sets exactly `preferred_name` and `phone` on the caller's own person row. A null or blank value clears the field. It can't change names of record, `email` (the contact/invite address), `employee_number`, `archived_at`, `organization_id`, or anything that affects access. Platform admins with no person in the org, disabled accounts, non-members and service_role without a JWT are refused.

### Admin RPCs (migration `20261111000600_security_review_fixes`)

Same standards as the people RPCs. Both refuse with `42501 not allowed`, without saying whether the row exists.

```sql
public.person_effective_permission(p_organization_id uuid, p_person_id uuid, p_location_id uuid, p_module_key text)
  returns permission_level
```
Another person's effective permission, computed exactly as `effective_permission` would for them: a disabled account, an archived person, an archived role or location, or a person with no account all give `none`. Callable by a platform admin, an org-scope `people_roles` admin, or a `people_roles` admin at a location where that person holds an assignment. It is read-only, so it writes no audit row.

```sql
public.replace_role_assignment(p_assignment_id uuid, p_role_id uuid, p_location_id uuid) returns uuid  -- new assignment id
```
Swaps one assignment for another for the same person in one transaction. Both the removal and the grant must pass `private.can_manage_role_assignment` (tier rule, scope, visibility, archived target, permission cap). It inserts the new row before deleting the old one, so the person never has zero assignments. If the person already holds the replacement, the old row is removed and the existing id is returned. The same role and scope raise `22023 nothing to change`. The insert and delete are audited normally.

### Audit log

Append-only, written by a trigger in the same transaction as every change to a Phase 1 table and most Phase 2 changes (exactly what is and is not audited for Phase 2 is listed in `docs/DATA_MODEL.md`; worker bookkeeping on `outbox_events`, `outbox_event_handlers` and `notification_deliveries` is not) (details in `docs/DATA_MODEL.md`). UPDATE, DELETE and TRUNCATE raise for every role, including service_role and the owner. Only the trigger function inserts rows: neither `authenticated` nor `service_role` has INSERT, so no API key can forge an actor or timestamp. The Phase 4 "sensitive record viewed" rows will need a dedicated security-definer writer. Only someone who owns the table (the migration role) could drop or disable that trigger, so a migration that touches `audit_log` triggers needs security review. Reads of Sensitive data are not captured by triggers; Phase 4 must write those audit rows explicitly.

## Data classes

| Class | Examples | Who can read |
| --- | --- | --- |
| Public | Facility name, space names | Anyone in the org |
| Internal | Schedules, tasks, notices, checklists | Org members in scope |
| Restricted | Incident narrative, witness names | `manager` and above in scope, plus the filer |
| Sensitive | Injury and medical details, accident photos, contact info of injured parties | `admin`, plus managers with the accident-reports grant; every read is audited |

## Required controls

- RLS enabled on every table, with no permissive default. Helper functions (see "Helper functions") are `security definer` with a fixed `search_path`.
- MFA for `admin` tier and above (enforced in the database since `20261112000100`; the app still has to run the MFA enrollment and challenge screens); admin idle sign-out after 30 minutes (not built).
- Rate limits on auth endpoints (database primitive `consume_rate_limit` built; the app calls it on sign-in and password reset). Per-person write limits on the event-emitting RPCs (`000600`, table above).
- Server-side zod validation on every mutation.
- No sensitive fields in logs or error reports.
- Secrets live only in Vercel and Supabase settings, and gitleaks runs in CI.
- Signed URLs for incident attachments, using private buckets only.

## Required tests (CI-blocking)

- pgTAP: for every table, a user in org A can't read or write org B's rows.
- pgTAP: `staff` can't read `incident_sensitive_details`.
- pgTAP: a user can't reach a location they aren't assigned to.
- Integration: a retried outbox event creates no duplicate tasks or messages.
- Integration: two overlapping bookings on one space fail.
