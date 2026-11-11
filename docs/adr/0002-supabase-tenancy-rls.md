# ADR-0002: Supabase with organization tenancy enforced by RLS

Status: Accepted (Nov 10, 2026)

## Context
Multiple organizations share one database. A single missed `WHERE` clause must not leak another organization's data.

## Decision
- Every business table carries `organization_id`. Location-scoped tables also carry `location_id`.
- RLS is enabled on every table and denies by default. Policies call `security definer` helpers built on `role_assignments`.
- Foreign keys within a tenant are composite `(id, organization_id)`.
- Rec Reports uses its own Supabase projects (staging and production), separate from RinkReports Pro.

## Consequences
- Isolation holds even if application code has a bug.
- Every new table needs policies plus pgTAP allow/deny tests before merge.
- The service-role key is restricted to workers and provisioning.
