# Data model

## Conventions

- UUID primary keys (`gen_random_uuid()`), `created_at` / `updated_at` as `timestamptz`. Both timestamps are set by the `private.tg_set_timestamps()` trigger on every insert/update; client values are ignored.
- `snake_case`, plural table names, prefixed by domain only where a name would clash.
- Every business table has `organization_id uuid not null`. Location-scoped tables also have `location_id uuid not null`.
- Foreign keys within a tenant are **composite**, `(id, organization_id)`, so a row can never point into another organization. A child that must stay in its parent's location uses `(id, organization_id, location_id)`.
- `id`, `organization_id` (and `location_id` where it pins a row to its parent) are immutable: `private.tg_immutable_columns(...)` raises for every role, service_role included.
- Every FK has an index whose leading columns cover it.
- Times are stored in UTC. Each location has an IANA `timezone`, and the UI shows local time.
- Soft-delete (`archived_at`) only for configuration rows: templates, spaces, positions. History rows are never deleted.
- Incident history and the audit log are append-only. Corrections go in as new rows.

## Hierarchy

Organization → Location → Space (a resource) → optional sub-space (a lane, a court half).

## Core tables (pilot)

| Domain | Tables |
| --- | --- |
| organizations | `organizations`, `locations`, `organization_settings` |
| identity | `people` (business person), `accounts` (maps `auth.users` to a person), `roles`, `role_default_permissions`, `modules`, `role_assignments` (person, role, scope: org / location), `user_permissions` (module x level override), `job_titles`, `person_job_titles`, `platform_admins` |
| resources | `space_kinds`, `spaces`, `space_hours`, `space_closures` |
| scheduling | `bookings`, `booking_series`, `booking_task_templates` |
| staffing | `positions`, `qualifications`, `person_qualifications`, `shifts`, `availability`, `shift_swaps`, `coverage_rules` |
| workflows | `outbox_events`, `outbox_event_handlers`, `task_templates`, `workflow_rules`, `tasks`, `task_events` |
| checklists | `checklist_templates`, `checklist_template_items`, `checklist_runs`, `checklist_responses` |
| incidents | `incident_forms`, `incidents`, `incident_parties`, `incident_sensitive_details`, `incident_history`, `incident_reviews` |
| communications | `messages`, `message_recipients`, `notices`, `notice_audiences`, `acknowledgments`, `shift_handoffs` (not built yet), `notifications`, `notification_deliveries`, `push_subscriptions`, `notification_preferences` |
| audit | `audit_log` |

Key constraints:

- `bookings`: an exclusion constraint on `(space_id, tstzrange(start_at - setup_buffer, end_at + cleanup_buffer))` for active bookings, so a space can never be double-booked.
- `tasks`: `unique (source_event_id, task_template_id)` so a retried event can't create a duplicate task.
- `incident_sensitive_details` is a separate table with its own stricter RLS. It holds injury and medical details.

## Room left for deferred modules

- `people` is separate from `accounts`, so a future customer or guardian is just another person.
- `bookings.program_session_id uuid null`, with no FK yet. Programs come later.
- The outbox `type` is free text with a schema version, so payment events need no change to the outbox.
- `spaces.kind` is a configurable lookup (pool, gym, court, studio, rink, room), not an enum, so aquatics and rinks need no migration.

## Phase 1 schema (built)

Migrations: `20261111000100_organizations_and_resources`, `..000200_identity_and_access`, `..000300_rls_helpers_and_policies`, `..000400_audit_log`, `..000500_people_rpcs` (RPCs `create_person_with_assignment` and `update_own_profile`), `..000600_security_review_fixes` (review fixes; RPCs `person_effective_permission` and `replace_role_assignment`). Access rules and RPC contracts are in `docs/SECURITY.md`.

Schemas: `public` (tables, the public helpers); `private` (trigger functions and policy helpers, not exposed by the Data API).

| Table | Scope | Notes that differ from the obvious |
| --- | --- | --- |
| `organizations` | tenant root (no `organization_id`) | `slug` unique, lowercase `a-z0-9-`. Insert/delete by service_role only. Insert trigger creates the `organization_settings` row and default `space_kinds` (pool, gym, court, studio, rink, field, room, other). |
| `organization_settings` | org | Exactly one row per org (`organization_id` unique). `default_timezone` (IANA), `week_starts_on` 0-6 (0 = Sunday), `settings jsonb` object, at most 64 kB as text. |
| `locations` | org | Archiving or restoring needs an org-scope admin (trigger). `timezone` required, validated: `UTC` or an `Area/Location` name in `pg_timezone_names` (rejects `EST`, `UTC+5`). Optional `code` unique per org. Unique active name per org. `archived_at`. |
| `space_kinds` | org | Per-org lookup, `unique (organization_id, key)`; `key` immutable. `archived_at`. |
| `spaces` | location | FKs: `(location_id, organization_id)`, `(space_kind_id, organization_id)`, `(parent_space_id, organization_id, location_id)`. One level of nesting only (trigger): a parent is top level, a space with children can't get a parent. `location_id` immutable. Unique active name per (location, parent). `archived_at`; no hard delete by tenants. |
| `space_hours` | location | `day_of_week` ISO 1 = Monday .. 7 = Sunday; `opens_at < closes_at` (`24:00` allowed, overnight = two rows); optional `effective_from/to` dates for seasons. Exclusion constraint `space_hours_no_overlap` (btree_gist): no two rows for the same space and weekday may overlap in time (`[opens_at, closes_at)`, compared as a timestamp range on a fixed date) when their date ranges overlap. A null date is open-ended. Adjacent rows such as 06:00-12:00 and 12:00-18:00 are fine. FK `(space_id, organization_id, location_id)`. |
| `space_closures` | location | `space_id` null = whole location closed. `starts_at < ends_at` (timestamptz). |
| `platform_admins` | platform | `user_id` PK → `auth.users`. The `super_admin` tier. Service-role only. |
| `modules` | global lookup | PK is `key` (text). 22 keys: locations_spaces, people_roles, audit_log, communications, tasks, staff_schedule, availability_time_off, shift_swaps, time_clock, timesheets, certifications, forms, checklists, incidents, accidents, daily_log, headcounts, facility_schedule, equipment, maintenance, documents, reports. |
| `roles` | global (system) or org (custom) | `organization_id` null = system role. `unique nulls not distinct (organization_id, key)`; `key` immutable. `rank`: super_admin 100, admin 80, manager 50, staff 10; custom 1-79. Custom keys can't reuse system keys; `org_admin`, `facility_manager`, `gm`, `supervisor` are rejected by constraint. |
| `role_default_permissions` | global or org | `(role_id, module_key)` unique, `level permission_level`. `organization_id` is copied from the role by trigger (null for system roles). |
| `people` | org | Business person; may have no account. `first_name`, `last_name`, `preferred_name`, `email`, `phone`, `employee_number` (unique per org). `archived_at`; never hard-deleted by tenants. Onboard with `create_person_with_assignment` (person + first assignment, atomic). A member edits only their own `preferred_name` and `phone`, through `update_own_profile`. |
| `accounts` | org | `user_id` → `auth.users`. `unique (user_id, organization_id)`, `unique (person_id)`. `disabled_at` set = not a member. Created by service_role only. |
| `role_assignments` | org or location | `location_id` null = organization scope, allowed only for the system `admin` role (trigger). A person's last assignment can be removed only by org scope (trigger `role_assignments_keep_last`). Swap roles with `replace_role_assignment`. `role_id` is a plain FK (system roles have no org); a trigger requires a system role or a custom role of the same org, never `super_admin`, never an archived role. `unique nulls not distinct (person_id, role_id, location_id)`. No updates by tenants: delete + insert. |
| `user_permissions` | org or location | Override of the role default for one module. `unique nulls not distinct (person_id, module_key, location_id)`. Only `level` is updatable. |
| `job_titles` | org | Routing only. Unique active name per org. `archived_at`. |
| `person_job_titles` | org or location | `location_id` null = everywhere the person works. `unique nulls not distinct (person_id, job_title_id, location_id)`. |
| `audit_log` | org / location / platform | See below. |

Type: `permission_level` enum, ordered `none < view < edit < admin`. Comparisons use enum order, so new levels must be inserted in the right place.

### Audit log

`audit_log` (`id bigint identity`, not uuid): `occurred_at` (transaction time), `transaction_id`, `organization_id` (null only for platform rows: `modules`, system `roles`, `platform_admins`), `location_id`, `actor_user_id` (`auth.uid()`), `actor_person_id` (caller's person in that org), `actor_role` (database role: `authenticated`, `service_role`, `postgres`), `action` (`insert`/`update`/`delete`), `table_schema`, `table_name`, `row_id` (**text**, the row's PK), `old_row`, `new_row` (jsonb), `changed_columns` (updates only, `updated_at` excluded). No FKs, so rows outlive what they describe. No-op updates are not logged.

Written by `private.tg_audit_row()` (security definer, AFTER row trigger named `zz_audit`) in the same transaction as the change. `organization_id`/`location_id` come from the row's columns of those names (for `organizations` / `locations`, the row's own `id`). Attach to a new table with one line, listing columns to redact (value becomes `"[redacted]"`, the name still appears in `changed_columns`):

```sql
select private.enable_audit('public.my_table');                                   -- PK column "id"
select private.enable_audit('public.incident_sensitive_details', 'id', array['injury_description']);
```

Every table that may hold injury or medical details must list those columns in `p_redact`. UPDATE, DELETE and TRUNCATE on `audit_log` raise for every role, owner included. Only the trigger function inserts (`service_role` has SELECT only). `enable_audit` also installs a `zz_audit_no_truncate` statement trigger, so TRUNCATE on any audited table raises (it would bypass row triggers).

## Phase 2 schema (built)

Migrations: `20261112000100_auth_hardening` (admin tier needs `aal2`, `consume_rate_limit`, `can_manage_person_account`), `..000200_outbox_and_jobs`, `..000300_tasks_and_workflows`, `..000400_communications`, `..000500_notifications`, `..000600_phase2_review_fixes` (review fixes; changes noted in the rows below), `..000700_worker_message_recipients` (worker read function for message recipients; no schema change). Access rules and RPC contracts are in `docs/SECURITY.md`. Every table below follows the conventions above (composite FKs, immutable `id`/`organization_id`/`location_id`, server timestamps, RLS, explicit grants, `zz_audit`).

| Table | Scope | Notes that differ from the obvious |
| --- | --- | --- |
| `outbox_events` | org, optional location | Written only by `private.emit_event`. `type` like `task.completed` (dotted snake case), `schema_version`, `entity_table` + `entity_id`, `payload` (flat object of ids/scalars, <= 32 keys, <= 8 kB; CHECK), `correlation_id` (defaults to the event's own id; follow-on events carry the source's). `status` pending / processing / done / dead; `attempts`, `next_attempt_at`, `locked_at`, `locked_by`, `lock_expires_at` (processing iff locked), `last_error` (<= 2000), `processed_at` (iff done), `retried_at`, `retried_by_person_id`, `manual_retries` (at most 3). `causation_id` (the event being handled when this one was emitted; no FK) and `causation_depth` (0 = caused by a person or a sweep; cause's depth + 1 otherwise; `private.emit_event` refuses a depth over 3 with 54000). The descriptive columns, including the causation columns, are immutable for every role. |
| `outbox_event_handlers` | org | PK `(event_id, handler)`, `completed_at`. The per-handler ledger: a retried event skips handlers listed here. FK to the event with cascade. |
| `rate_limit_counters`, `rate_limit_secret` | schema `private` | Not tenant data: `(bucket, key_hash bytea, window_start)` PK, `window_end`, `hits`. Keys are HMAC'd, never stored. No API role has any privilege. |
| `task_templates` | org or location (`location_id` null = every location) | `due_offset_minutes` (-525600..525600, from the event's `anchor_at` payload field or the event time; negative = before), `assign_to` none / job_title / person / on_shift (Phase 3 placeholder: unassigned for now), with `assign_job_title_id` / `assign_person_id` required exactly when chosen. `archived_at`. |
| `workflow_rules` | org or location | `event_type` must be in `private.workflow_trigger_types()` (pilot event list; of the `task.*` events only `task.overdue`). That list alone did **not** stop loops: a rule on `task.overdue` whose template is already overdue fed itself (reviewed in Phase 2: 14 -> 374 tasks in five sweeps). Since `000600` loops are stopped by: `match_workflow_rules` never matching an event about a task that a rule created (`source_rule_id` set); event causation depth (no rule matches an event at depth 3); a rule on `task.overdue` needs a template with `due_offset_minutes` null or >= 1 (rule trigger, and a `task_templates` trigger refuses lowering the offset to <= 0 while such a rule exists); and at most 20 enabled rules per organization per `event_type`. `condition` jsonb: `{}` or `{"all":[{"field","op":"eq"|"in","value"}]}`, 1-10 clauses, scalars only (CHECK `private.validate_workflow_condition`). Always inserted with `enabled = false` (trigger). An archived rule cannot be enabled; a location template only serves rules of the same location. A condition clause on a field the payload does not have never matches (`eq` and `in`). |
| `tasks` | location | `space_id` (FK pinned to the location), `status` open / in_progress / done / cancelled (`completed_at` iff done, `cancelled_at` iff cancelled), `priority` low / normal / high / urgent, `due_at`, `assigned_person_id` and/or `assigned_job_title_id`, `created_by_person_id` (null = system), `completed_by_person_id`. `source_event_id` + `source_rule_id` + `task_template_id`: **`unique (source_event_id, task_template_id)`**, so one event makes at most one task per template. `source_event_id` is an idempotency key without an FK (outbox rows are purged after retention, tasks are kept). `overdue_emitted_for` = the `due_at` for which `task.overdue` was emitted; `escalated_for` = the `due_at` for which the task was escalated. No tenant writes. |
| `task_events` | location | Append-only history (`created`, `assigned`, `started`, `completed`, `reopened`, `cancelled`, `commented`, `escalated`): `actor_person_id` (null = system), `from_status` / `to_status`, new assignee for `created`/`assigned`, `body` (<= 2000: comment, note, reason), `source_event_id`. UPDATE, DELETE and TRUNCATE raise for every role (owner included); a DELETE passes only as the cascade of deleting its task (or the organization). FK `(task_id, organization_id, location_id)`. |
| `notices` | org (`location_id` = home scope, null = organization) | `title`, `body` (<= 5000), `urgency` normal / high / critical, `requires_acknowledgment`, `publish_at`, `expires_at` (> `publish_at`), `status` draft / published / archived, `author_person_id` (trigger), `published_at`, `published_by_person_id`, `archived_at`. Inserted as a draft only; edited only while draft. |
| `notice_audiences` | org | `(location_id or null = whole org) x (job_title_id or null = everyone)`, `unique nulls not distinct (notice_id, location_id, job_title_id)`. A location notice targets only its own location. |
| `acknowledgments` | org | `unique (notice_id, person_id)`, `acknowledged_at` server time. Written once by `acknowledge_notice`; UPDATE, DELETE and TRUNCATE raise for every role; a DELETE passes only as the cascade of deleting its notice (or the organization). |
| `messages` | org | `sender_person_id`, `body` (<= 4000, immutable). Written only by `send_message`. |
| `message_recipients` | org | `unique (message_id, person_id)`, `read_at`. |
| `notifications` | org, per person | `kind`, `title`, `body` (<= 500 summary), `link_path` (app-relative, `/...`), `source_table`, `source_id`, `source_event_id` (not null, no FK), `urgency`, `read_at`. **`unique (source_event_id, person_id, kind)`**. Everything except `read_at` is immutable. |
| `notification_deliveries` | org, per person | `channel` in_app / email / push, `status` pending / sent / failed / skipped, `attempts`, `next_attempt_at`, lock columns (a claim keeps status pending with `locked_by` set), `provider_message_id`, `last_error`, `sent_at` (iff sent). **`unique (notification_id, channel)`**. |
| `push_subscriptions` | org, per person | `endpoint` (CHECK `private.push_endpoint_allowed`: https, no userinfo, port 443 or none, host `fcm.googleapis.com`, `updates.push.services.mozilla.com`, `*.push.apple.com` or `*.notify.windows.com`), at most 10 per person (saving an 11th removes the least recently saved), one person per endpoint (saving removes other people's rows for it), `p256dh`, `auth_secret`, `user_agent`, `last_used_at`, `disabled_at`. `unique (person_id, endpoint)`. Endpoint and keys are never granted to `authenticated`. |
| `notification_preferences` | org, per person | `channel` email / push, `enabled`. `unique (person_id, channel)`. In-app cannot be turned off; critical ignores the setting. |

FKs into org-or-location parents (`tasks` -> `task_templates`, `tasks` -> `workflow_rules`, `workflow_rules` -> `task_templates`, `notice_audiences` -> `notices`) are `(id, organization_id)` only: the parent's null `location_id` means "every location", so pairing `location_id` would be wrong. Location compatibility is enforced by the `workflow_rules` trigger, `match_workflow_rules`, and the `notice_audiences` policy.

No timestamp or date column in `public` (except `audit_log`) accepts `infinity` / `-infinity`: each has a CHECK named `finite_<column>` (`000600`). New tables must add the same check (suggested catalog guard: every timestamptz/date column of a public table has a `finite_<column>` check).

Audit redactions (value becomes `"[redacted]"`): `outbox_events.last_error`, `task_templates.instructions/title`, `workflow_rules.name`, `tasks.instructions/title`, `task_events.body`, `notices.body/title`, `messages.body`, `notifications.title/body/link_path`, `notification_deliveries.last_error/provider_message_id`, `push_subscriptions.endpoint/p256dh/auth_secret/user_agent`. What is audited (since `000600`): every insert, update and delete of every Phase 2 table except: `outbox_events` (only a person's manual retry: `manual_retries` / `retried_at` change; not inserts, not any worker change), `outbox_event_handlers` (nothing: the trigger fires only on UPDATE, which no code does), `notification_deliveries` (only a change of `status`; not inserts, attempts, locks or retry times). Audit rows of `messages`, `message_recipients`, `notifications`, `notification_deliveries`, `push_subscriptions`, `notification_preferences` and `outbox_event_handlers`, and of `message.*` outbox events, are readable by no tenant (platform admins included; `private.audit_hidden_tables()`); service_role still reads them. Nothing here is Restricted or Sensitive yet; the redactions keep free text out of the audit log and keep it from becoming a way to read private messages.

### Outbox event types emitted (schema_version 1)

| Type | Emitted by | location_id | Payload |
| --- | --- | --- | --- |
| `task.created`, `task.started`, `task.completed`, `task.reopened`, `task.assigned`, `task.cancelled`, `task.commented` | the task RPCs and `create_task_from_event` | the task's | `task_id, task_event_id, location_id, status, priority, assigned_person_id, assigned_job_title_id, actor_person_id (null = system), due_at` |
| `task.overdue` | `emit_overdue_task_events` | the task's | `task_id, location_id, due_at, priority, space_id, assigned_person_id, assigned_job_title_id` |
| `notice.published` | `publish_notice` (available to workers at `publish_at`) | the notice's home | `notice_id, location_id, urgency, requires_acknowledgment, publish_at, expires_at` |
| `notice.archived` | `archive_notice` | the notice's home | `notice_id, location_id` |
| `notice.acknowledged` | `acknowledge_notice` (first time only) | the notice's home | `notice_id, person_id` |
| `message.sent` | `send_message` | null | `message_id` (sender and recipients were removed in `000600`, also from rows written before; no tenant can read `message.*` rows). The worker gets the recipients from `worker_message_recipients_for_event` (`000700`). |

Every event also carries `correlation_id`, `causation_id` and `causation_depth` (columns, not payload). Events emitted while handling another event (`task.created` from a rule, `task.overdue` of a rule-made task) pass it as the cause.

Producers of `booking.*`, `shift.*`, `checklist.*` and `incident.*` come with their domains. A producer that wants a task anchored to a time puts `anchor_at` (ISO timestamp) and, optionally, `space_id` in its payload.
