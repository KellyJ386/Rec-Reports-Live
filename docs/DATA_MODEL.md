# Data model

## Conventions

- UUID primary keys (`gen_random_uuid()`), `created_at` / `updated_at` as `timestamptz`.
- `snake_case`, plural table names, prefixed by domain only where a name would clash.
- Every business table has `organization_id uuid not null`. Location-scoped tables also have `location_id uuid not null`.
- Foreign keys within a tenant are **composite**, `(id, organization_id)`, so a row can never point into another organization.
- Times are stored in UTC. Each location has an IANA `timezone`, and the UI shows local time.
- Soft-delete (`archived_at`) only for configuration rows: templates, spaces, positions. History rows are never deleted.
- Incident history and the audit log are append-only. Corrections go in as new rows.

## Hierarchy

Organization → Location → Space (a resource) → optional sub-space (a lane, a court half).

## Core tables (pilot)

| Domain | Tables |
| --- | --- |
| organizations | `organizations`, `locations`, `organization_settings` |
| identity | `people` (business person), `accounts` (maps `auth.users` to a person), `role_assignments` (person, role, scope: org / location), `user_permissions` (module x level), `job_titles`, `person_job_titles` |
| resources | `spaces`, `space_hours`, `space_closures` |
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
