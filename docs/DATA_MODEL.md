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
| workflows | `outbox_events`, `workflow_rules`, `tasks`, `task_events` |
| checklists | `checklist_templates`, `checklist_template_items`, `checklist_runs`, `checklist_responses` |
| incidents | `incident_forms`, `incidents`, `incident_parties`, `incident_sensitive_details`, `incident_history`, `incident_reviews` |
| communications | `messages`, `message_recipients`, `notices`, `acknowledgments`, `shift_handoffs` |
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

Migrations: `20261111000100_organizations_and_resources`, `..000200_identity_and_access`, `..000300_rls_helpers_and_policies`, `..000400_audit_log`. Access rules are in `docs/SECURITY.md`.

Schemas: `public` (tables, the public helpers); `private` (trigger functions and policy helpers, not exposed by the Data API).

| Table | Scope | Notes that differ from the obvious |
| --- | --- | --- |
| `organizations` | tenant root (no `organization_id`) | `slug` unique, lowercase `a-z0-9-`. Insert/delete by service_role only. Insert trigger creates the `organization_settings` row and default `space_kinds` (pool, gym, court, studio, rink, field, room, other). |
| `organization_settings` | org | Exactly one row per org (`organization_id` unique). `default_timezone` (IANA), `week_starts_on` 0-6 (0 = Sunday), `settings jsonb` object. |
| `locations` | org | `timezone` required, validated: `UTC` or an `Area/Location` name in `pg_timezone_names` (rejects `EST`, `UTC+5`). Optional `code` unique per org. Unique active name per org. `archived_at`. |
| `space_kinds` | org | Per-org lookup, `unique (organization_id, key)`; `key` immutable. `archived_at`. |
| `spaces` | location | FKs: `(location_id, organization_id)`, `(space_kind_id, organization_id)`, `(parent_space_id, organization_id, location_id)`. One level of nesting only (trigger): a parent is top level, a space with children can't get a parent. `location_id` immutable. Unique active name per (location, parent). `archived_at`; no hard delete by tenants. |
| `space_hours` | location | `day_of_week` ISO 1 = Monday .. 7 = Sunday; `opens_at < closes_at` (`24:00` allowed, overnight = two rows); optional `effective_from/to` dates for seasons. No overlap constraint yet. FK `(space_id, organization_id, location_id)`. |
| `space_closures` | location | `space_id` null = whole location closed. `starts_at < ends_at` (timestamptz). |
| `platform_admins` | platform | `user_id` PK → `auth.users`. The `super_admin` tier. Service-role only. |
| `modules` | global lookup | PK is `key` (text). 22 keys: locations_spaces, people_roles, audit_log, communications, tasks, staff_schedule, availability_time_off, shift_swaps, time_clock, timesheets, certifications, forms, checklists, incidents, accidents, daily_log, headcounts, facility_schedule, equipment, maintenance, documents, reports. |
| `roles` | global (system) or org (custom) | `organization_id` null = system role. `unique nulls not distinct (organization_id, key)`; `key` immutable. `rank`: super_admin 100, admin 80, manager 50, staff 10; custom 1-79. Custom keys can't reuse system keys; `org_admin`, `facility_manager`, `gm`, `supervisor` are rejected by constraint. |
| `role_default_permissions` | global or org | `(role_id, module_key)` unique, `level permission_level`. `organization_id` is copied from the role by trigger (null for system roles). |
| `people` | org | Business person; may have no account. `first_name`, `last_name`, `preferred_name`, `email`, `phone`, `employee_number` (unique per org). `archived_at`; never hard-deleted by tenants. |
| `accounts` | org | `user_id` → `auth.users`. `unique (user_id, organization_id)`, `unique (person_id)`. `disabled_at` set = not a member. Created by service_role only. |
| `role_assignments` | org or location | `location_id` null = organization scope, allowed only for the system `admin` role (trigger). `role_id` is a plain FK (system roles have no org); a trigger requires a system role or a custom role of the same org, never `super_admin`, never an archived role. `unique nulls not distinct (person_id, role_id, location_id)`. No updates by tenants: delete + insert. |
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

Every table that may hold injury or medical details must list those columns in `p_redact`. UPDATE, DELETE and TRUNCATE on `audit_log` raise for every role, owner included.
