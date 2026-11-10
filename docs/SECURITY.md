# Security

Baseline: OWASP ASVS Level 2, with stricter controls on incident injury details.

## Roles (pilot)

Same model as RinkReports Pro (see `docs/REUSE_INVENTORY.md`):

| Role | Scope | Default use |
| --- | --- | --- |
| `super_admin` | Platform | Max Facility staff only |
| `admin` | Organization or location | Users, roles, settings, everything in scope |
| `manager` | Location | Configure spaces, templates, forms, schedules; review incidents |
| `staff` | Location | Own shift, own tasks, checklists, file incidents, read notices |
| custom roles | Organization | Defined per organization |

- Roles only seed defaults. What a person can do is `user_permissions` (module x level).
- Job titles (`job_titles`) route tasks and messages ("Lifeguard", "Front Desk"). They grant no permissions.
- Tier rule: a person can change a role or user only when it ranks strictly below their own.
- Do not use `org_admin`, `facility_manager`, `gm` or `supervisor` as role keys. "Supervisor" is a job title.

## Data classes

| Class | Examples | Who can read |
| --- | --- | --- |
| Public | Facility name, space names | Anyone in the org |
| Internal | Schedules, tasks, notices, checklists | Org members in scope |
| Restricted | Incident narrative, witness names | `manager` and above in scope, plus the filer |
| Sensitive | Injury and medical details, accident photos, contact info of injured parties | `admin`, plus managers with the accident-reports grant; every read is audited |

## Required controls

- RLS enabled on every table, with no permissive default. Helper functions `auth_org_ids()` and `has_role(org, location, role)` are `security definer` with a fixed `search_path`.
- MFA for `admin` tier and above; admin idle sign-out after 30 minutes.
- Rate limits on auth endpoints.
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
